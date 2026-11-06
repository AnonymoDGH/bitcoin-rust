//! Address manager. Simplified port of src/addrman.h and src/addrman.cpp.
//!
//! Differences from Core, kept on purpose so this file stays self-contained:
//! - Bucket hashing is SipHash-2-4 keyed by a 64-bit secret. Core uses a cheap
//!   SHA-256 hash keyed by a random 256-bit nKey.
//! - No asmap: netgroups are IPv4 /16 and IPv6 /32, which is Core's default.
//! - No test-before-evict: a tried-table collision in `mark_good` leaves the
//!   address in the new table instead of queuing a feeler connection.
//! - No time penalty and no network filtering. The file format is our own
//!   (see `save`), not Core's peers.dat.
//! - Not thread-safe; the owner wraps it in a Mutex.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Total number of buckets for tried addresses.
pub const ADDRMAN_TRIED_BUCKET_COUNT: usize = 1 << 8;
/// Total number of buckets for new addresses.
pub const ADDRMAN_NEW_BUCKET_COUNT: usize = 1 << 10;
/// Entries per bucket, for both tables.
pub const ADDRMAN_BUCKET_SIZE: usize = 1 << 6;
/// Tried addresses from one netgroup spread over this many buckets.
pub const ADDRMAN_TRIED_BUCKETS_PER_GROUP: u64 = 8;
/// New addresses from one source netgroup spread over this many buckets.
pub const ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 64;
/// Maximum number of new-table slots one address may occupy.
pub const ADDRMAN_NEW_BUCKETS_PER_ADDRESS: u32 = 8;

const ADDRMAN_HORIZON_SECS: i64 = 30 * 24 * 60 * 60;
const ADDRMAN_RETRIES: u32 = 3;
const ADDRMAN_MAX_FAILURES: u32 = 10;
const ADDRMAN_MIN_FAIL_SECS: i64 = 7 * 24 * 60 * 60;

const PEERS_MAGIC: &[u8; 8] = b"BTCPEERS";
const PEERS_VERSION: u32 = 1;
/// Upper bound on entries in a file, so a corrupt count cannot allocate without limit.
const PEERS_MAX_ENTRIES: u32 = 1 << 20;

/// Network address record. `time` is the last-seen unix time in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetAddr {
    pub ip: IpAddr,
    pub port: u16,
    pub services: u64,
    pub time: u32,
}

impl NetAddr {
    pub fn new(ip: IpAddr, port: u16, services: u64, time: u32) -> Self {
        Self { ip, port, services, time }
    }
}

#[derive(Debug)]
struct Entry {
    addr: NetAddr,
    attempts: u32,
    last_try: u32,
    last_success: u32,
    in_tried: bool,
    /// Indices into `new_table` holding this entry. Its length is the multiplicity.
    new_slots: Vec<usize>,
}

/// Stochastic address manager with "new" and "tried" bucket tables.
#[derive(Debug)]
pub struct AddrMan {
    secret: u64,
    rng: XorShift64,
    next_id: u64,
    entries: HashMap<u64, Entry>,
    /// Lookup by (normalized ip, port).
    ids: HashMap<(IpAddr, u16), u64>,
    new_table: Vec<Option<u64>>,
    tried_table: Vec<Option<u64>>,
    /// Unique addresses currently in the new table.
    n_new: usize,
    /// Unique addresses currently in the tried table.
    n_tried: usize,
    /// Accept loopback and private addresses (regtest and tests only).
    accept_local: bool,
}

impl Default for AddrMan {
    fn default() -> Self {
        Self::new()
    }
}

impl AddrMan {
    /// Random bucket key and RNG seed, taken from std's OS-seeded RandomState.
    pub fn new() -> Self {
        Self::new_seeded(random_u64(), random_u64())
    }

    /// Fixed key and RNG seed, for reproducible behavior in tests.
    pub fn new_seeded(secret: u64, rng_seed: u64) -> Self {
        Self {
            secret,
            rng: XorShift64::new(rng_seed),
            next_id: 0,
            entries: HashMap::new(),
            ids: HashMap::new(),
            new_table: vec![None; ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE],
            tried_table: vec![None; ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE],
            n_new: 0,
            n_tried: 0,
            accept_local: false,
        }
    }

    /// Lets `add` keep loopback and private addresses. Off by default, since
    /// Core never stores them. Used on regtest and in tests, where every peer is local.
    pub fn set_accept_local(&mut self, accept: bool) {
        self.accept_local = accept;
    }

    /// Whether an address with this IP may be stored: Core's IsRoutable, or only
    /// unspecified and multicast rejected when local addresses are accepted.
    pub fn accepts_ip(&self, ip: IpAddr) -> bool {
        if self.accept_local {
            !ip.is_unspecified() && !ip.is_multicast()
        } else {
            is_routable(ip)
        }
    }

    /// Whether `addr` (ip and port) is known, in either table.
    pub fn contains(&self, addr: &NetAddr) -> bool {
        self.ids.contains_key(&addr_key(addr))
    }

    /// Whether `addr` is in the tried table.
    pub fn is_tried(&self, addr: &NetAddr) -> bool {
        self.ids
            .get(&addr_key(addr))
            .is_some_and(|id| self.entries[id].in_tried)
    }

    /// Number of unique addresses in either table.
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// Random sample for a `getaddr` reply: at most `max` addresses, and at most
    /// `max_pct` percent of the table. Terrible entries are skipped.
    pub fn get_addresses(&mut self, max: usize, max_pct: usize) -> Vec<NetAddr> {
        let now = now_secs() as i64;
        let mut all: Vec<NetAddr> = self
            .entries
            .values()
            .filter(|entry| !is_terrible(entry, now))
            .map(|entry| entry.addr)
            .collect();
        let n = (all.len() * max_pct / 100).min(max);
        for i in 0..n {
            let j = i + self.rng.below((all.len() - i) as u64) as usize;
            all.swap(i, j);
        }
        all.truncate(n);
        all
    }

    /// Writes the table to `path` through a temporary file, so a crash leaves
    /// either the old file or the new one.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let bytes = self.encode();
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".new");
        let tmp = PathBuf::from(tmp);
        {
            let mut file = File::create(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Reads a table written by `save`. The result has `accept_local` off.
    pub fn load(path: &Path) -> io::Result<AddrMan> {
        Self::decode(&std::fs::read(path)?)
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PEERS_MAGIC);
        out.extend_from_slice(&PEERS_VERSION.to_le_bytes());
        out.extend_from_slice(&self.secret.to_le_bytes());
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort_by_key(|entry| addr_key(&entry.addr));
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for entry in entries {
            match entry.addr.ip {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&entry.addr.port.to_le_bytes());
            out.extend_from_slice(&entry.addr.services.to_le_bytes());
            out.extend_from_slice(&entry.addr.time.to_le_bytes());
            out.extend_from_slice(&entry.attempts.to_le_bytes());
            out.extend_from_slice(&entry.last_try.to_le_bytes());
            out.extend_from_slice(&entry.last_success.to_le_bytes());
            out.push(u8::from(entry.in_tried));
            out.extend_from_slice(&(entry.new_slots.len() as u32).to_le_bytes());
            for slot in &entry.new_slots {
                out.extend_from_slice(&(*slot as u32).to_le_bytes());
            }
        }
        let checksum = keyed_hash(self.secret, &[out.as_slice()]);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> io::Result<AddrMan> {
        let bad = |why: &str| io::Error::new(io::ErrorKind::InvalidData, format!("peers file: {why}"));
        let (body, trailer) = bytes
            .len()
            .checked_sub(8)
            .map(|split| bytes.split_at(split))
            .ok_or_else(|| bad("truncated"))?;
        let mut reader = Reader { buf: body, pos: 0 };
        if reader.take(PEERS_MAGIC.len())? != PEERS_MAGIC {
            return Err(bad("bad magic"));
        }
        if reader.u32()? != PEERS_VERSION {
            return Err(bad("unsupported version"));
        }
        let secret = reader.u64()?;
        if keyed_hash(secret, &[body]).to_le_bytes().as_slice() != trailer {
            return Err(bad("checksum mismatch"));
        }

        let count = reader.u32()?;
        if count > PEERS_MAX_ENTRIES {
            return Err(bad("too many entries"));
        }
        let mut am = AddrMan::new_seeded(secret, random_u64());
        for _ in 0..count {
            let ip = match reader.u8()? {
                4 => IpAddr::V4(Ipv4Addr::from(reader.array::<4>()?)),
                6 => IpAddr::V6(Ipv6Addr::from(reader.array::<16>()?)),
                _ => return Err(bad("bad address family")),
            };
            let port = reader.u16()?;
            let services = reader.u64()?;
            let time = reader.u32()?;
            let attempts = reader.u32()?;
            let last_try = reader.u32()?;
            let last_success = reader.u32()?;
            let in_tried = match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(bad("bad table flag")),
            };
            let n_slots = reader.u32()?;
            if n_slots > ADDRMAN_NEW_BUCKETS_PER_ADDRESS {
                return Err(bad("too many new-table slots"));
            }
            let slots: Vec<usize> = (0..n_slots)
                .map(|_| reader.u32().map(|slot| slot as usize))
                .collect::<io::Result<_>>()?;
            if in_tried == !slots.is_empty() {
                return Err(bad("entry is in both tables or in neither"));
            }

            let addr = NetAddr::new(ip, port, services, time);
            let key = addr_key(&addr);
            if am.ids.contains_key(&key) {
                return Err(bad("duplicate address"));
            }
            let id = am.next_id;
            am.next_id += 1;
            if in_tried {
                let bucket = tried_bucket(secret, &addr);
                let idx = bucket * ADDRMAN_BUCKET_SIZE + bucket_position(secret, false, bucket, &addr);
                if am.tried_table[idx].is_some() {
                    return Err(bad("tried-table slot collision"));
                }
                am.tried_table[idx] = Some(id);
                am.n_tried += 1;
            } else {
                for &slot in &slots {
                    if slot >= am.new_table.len() || am.new_table[slot].is_some() {
                        return Err(bad("bad new-table slot"));
                    }
                    am.new_table[slot] = Some(id);
                }
                am.n_new += 1;
            }
            am.ids.insert(key, id);
            am.entries.insert(
                id,
                Entry {
                    addr,
                    attempts,
                    last_try,
                    last_success,
                    in_tried,
                    new_slots: slots,
                },
            );
        }
        if reader.pos != body.len() {
            return Err(bad("trailing bytes"));
        }
        Ok(am)
    }

    /// Number of unique addresses in the new table.
    pub fn new_size(&self) -> usize {
        self.n_new
    }

    /// Number of addresses in the tried table.
    pub fn tried_size(&self) -> usize {
        self.n_tried
    }

    /// Adds an address learned from `source` to the new table.
    /// Returns true if it was placed in a new bucket, including an extra bucket for a known address.
    pub fn add(&mut self, addr: NetAddr, source: NetAddr) -> bool {
        if !self.accepts_ip(addr.ip) {
            return false;
        }
        let now = now_secs() as i64;
        let key = addr_key(&addr);

        let id = match self.ids.get(&key).copied() {
            Some(id) => {
                let entry = self.entries.get_mut(&id).expect("ids and entries are in sync");
                entry.addr.services |= addr.services;
                // Core refreshes the stored time at most hourly for online peers, daily otherwise.
                // A refresh alone does not count as a new placement, so it returns false below.
                let online = now - (addr.time as i64) < 86_400;
                let interval: i64 = if online { 3_600 } else { 86_400 };
                if (entry.addr.time as i64) < addr.time as i64 - interval {
                    entry.addr.time = addr.time;
                }
                if addr.time <= entry.addr.time || entry.in_tried {
                    return false;
                }
                let refs = entry.new_slots.len() as u32;
                if refs >= ADDRMAN_NEW_BUCKETS_PER_ADDRESS {
                    return false;
                }
                // Each extra placement is 2^refs times less likely than the one before.
                if refs > 0 && self.rng.below(1u64 << refs) != 0 {
                    return false;
                }
                id
            }
            None => {
                let id = self.next_id;
                self.next_id += 1;
                self.entries.insert(
                    id,
                    Entry {
                        addr,
                        attempts: 0,
                        last_try: 0,
                        last_success: 0,
                        in_tried: false,
                        new_slots: Vec::new(),
                    },
                );
                self.ids.insert(key, id);
                id
            }
        };
        self.place_in_new(id, source.ip)
    }

    /// Records a successful connection and moves the address from new to tried.
    /// Returns false if the address is unknown, already tried, or its tried slot is taken.
    pub fn mark_good(&mut self, addr: &NetAddr) -> bool {
        let now = now_secs();
        let Some(&id) = self.ids.get(&addr_key(addr)) else {
            return false;
        };
        let secret = self.secret;
        let entry = self.entries.get_mut(&id).expect("ids and entries are in sync");
        entry.last_success = now;
        entry.last_try = now;
        entry.attempts = 0;
        if entry.in_tried {
            return false;
        }
        let bucket = tried_bucket(secret, &entry.addr);
        let idx = bucket * ADDRMAN_BUCKET_SIZE + bucket_position(secret, false, bucket, &entry.addr);
        if self.tried_table[idx].is_some() {
            return false;
        }

        let had_new = !entry.new_slots.is_empty();
        for slot in std::mem::take(&mut entry.new_slots) {
            self.new_table[slot] = None;
        }
        if had_new {
            self.n_new -= 1;
        }
        entry.in_tried = true;
        self.tried_table[idx] = Some(id);
        self.n_tried += 1;
        true
    }

    /// Records a connection attempt. `count_failure` feeds the failure counter used by
    /// `is_terrible` and `get_chance`.
    pub fn attempt(&mut self, addr: &NetAddr, count_failure: bool) {
        let now = now_secs();
        if let Some(&id) = self.ids.get(&addr_key(addr)) {
            let entry = self.entries.get_mut(&id).expect("ids and entries are in sync");
            entry.last_try = now;
            if count_failure {
                entry.attempts = entry.attempts.saturating_add(1);
            }
        }
    }

    /// Picks a random address to connect to. With `new_only`, only the new table is used.
    /// Mirrors Core's Select_: choose a table, then a random bucket and entry, and accept
    /// the entry with probability GetChance(). Each rejection raises the acceptance factor,
    /// so the loop terminates once any entry exists.
    pub fn select(&mut self, new_only: bool) -> Option<NetAddr> {
        if self.entries.is_empty() || (new_only && self.n_new == 0) {
            return None;
        }
        let search_tried = if new_only || self.n_tried == 0 {
            false
        } else if self.n_new == 0 {
            true
        } else {
            self.rng.next_u64() & 1 == 1
        };
        let (table, bucket_count) = if search_tried {
            (&self.tried_table, ADDRMAN_TRIED_BUCKET_COUNT)
        } else {
            (&self.new_table, ADDRMAN_NEW_BUCKET_COUNT)
        };

        let now = now_secs() as i64;
        let mut chance_factor = 1.0f64;
        loop {
            let bucket = self.rng.below(bucket_count as u64) as usize;
            let start = bucket * ADDRMAN_BUCKET_SIZE;
            let mut candidates = [0u64; ADDRMAN_BUCKET_SIZE];
            let mut n = 0;
            for id in table[start..start + ADDRMAN_BUCKET_SIZE].iter().flatten() {
                candidates[n] = *id;
                n += 1;
            }
            if n == 0 {
                continue;
            }
            let id = candidates[self.rng.below(n as u64) as usize];
            let entry = &self.entries[&id];
            if self.rng.chance(chance_factor * get_chance(entry, now)) {
                return Some(entry.addr);
            }
            chance_factor *= 1.2;
        }
    }

    /// Puts entry `id` into its new-table bucket for `source`. An occupied slot is only
    /// overwritten if its occupant is terrible, or is held in several buckets while this
    /// candidate has no placement yet.
    fn place_in_new(&mut self, id: u64, source: IpAddr) -> bool {
        let addr = self.entries[&id].addr;
        let bucket = new_bucket(self.secret, &addr, source);
        let idx = bucket * ADDRMAN_BUCKET_SIZE + bucket_position(self.secret, true, bucket, &addr);
        match self.new_table[idx] {
            None => {
                self.occupy_new(id, idx);
                true
            }
            Some(other) if other == id => false,
            Some(other) => {
                let now = now_secs() as i64;
                let my_refs = self.entries[&id].new_slots.len();
                let other_entry = &self.entries[&other];
                let overwrite = is_terrible(other_entry, now)
                    || (other_entry.new_slots.len() > 1 && my_refs == 0);
                if overwrite {
                    self.clear_new_slot(idx);
                    self.occupy_new(id, idx);
                    true
                } else {
                    if my_refs == 0 {
                        self.remove_entry(id);
                    }
                    false
                }
            }
        }
    }

    fn occupy_new(&mut self, id: u64, idx: usize) {
        self.new_table[idx] = Some(id);
        let entry = self.entries.get_mut(&id).expect("ids and entries are in sync");
        if entry.new_slots.is_empty() {
            self.n_new += 1;
        }
        entry.new_slots.push(idx);
    }

    /// Frees a new-table slot. The occupying entry is deleted if this was its last slot.
    fn clear_new_slot(&mut self, idx: usize) {
        let Some(id) = self.new_table[idx].take() else {
            return;
        };
        let entry = self.entries.get_mut(&id).expect("ids and entries are in sync");
        entry.new_slots.retain(|&s| s != idx);
        if entry.new_slots.is_empty() {
            self.n_new -= 1;
            if !entry.in_tried {
                self.remove_entry(id);
            }
        }
    }

    /// Drops an entry with no table slots from the maps.
    fn remove_entry(&mut self, id: u64) {
        if let Some(entry) = self.entries.remove(&id) {
            debug_assert!(entry.new_slots.is_empty() && !entry.in_tried);
            self.ids.remove(&addr_key(&entry.addr));
        }
    }
}

/// Maps IPv4-mapped IPv6 addresses to IPv4 so both spellings share one identity.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Identity of an address: normalized IP and port.
fn addr_key(addr: &NetAddr) -> (IpAddr, u16) {
    (normalize_ip(addr.ip), addr.port)
}

/// Hashed form of an address: 16-byte IPv6 (IPv4 mapped) IP followed by the LE port.
fn addr_bytes(addr: &NetAddr) -> [u8; 18] {
    let ip16 = match normalize_ip(addr.ip) {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    let mut out = [0u8; 18];
    out[..16].copy_from_slice(&ip16);
    out[16..].copy_from_slice(&addr.port.to_le_bytes());
    out
}

/// Netgroup as in Core's NetGroupManager without asmap: IPv4 /16, IPv6 /32.
/// Fixed width, so concatenated groups cannot be parsed ambiguously.
fn group(ip: IpAddr) -> [u8; 5] {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [4, o[0], o[1], 0, 0]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [6, o[0], o[1], o[2], o[3]]
        }
    }
}

/// Netgroup key for an IP address, as `group` computes it. Two addresses with the
/// same key share a netgroup, and Core avoids more than one outbound peer per group.
pub fn netgroup(ip: IpAddr) -> [u8; 5] {
    group(ip)
}

/// Subset of Core's CNetAddr::IsRoutable(). Rejects unspecified, loopback, multicast,
/// private, link-local, CGNAT, and documentation ranges.
fn is_routable(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || o[0] == 0
                || o[0] == 10
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

const TAG_TRIED_1: &[u8] = b"T1";
const TAG_TRIED_2: &[u8] = b"T2";
const TAG_NEW_1: &[u8] = b"U1";
const TAG_NEW_2: &[u8] = b"U2";

fn tried_bucket(secret: u64, addr: &NetAddr) -> usize {
    let hash1 = keyed_hash(secret, &[TAG_TRIED_1, &addr_bytes(addr)[..]]);
    let hash2 = keyed_hash(
        secret,
        &[
            TAG_TRIED_2,
            &group(addr.ip)[..],
            &(hash1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP).to_le_bytes()[..],
        ],
    );
    (hash2 % ADDRMAN_TRIED_BUCKET_COUNT as u64) as usize
}

fn new_bucket(secret: u64, addr: &NetAddr, source: IpAddr) -> usize {
    let src_group = group(source);
    let hash1 = keyed_hash(secret, &[TAG_NEW_1, &group(addr.ip)[..], &src_group[..]]);
    let hash2 = keyed_hash(
        secret,
        &[
            TAG_NEW_2,
            &src_group[..],
            &(hash1 % ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP).to_le_bytes()[..],
        ],
    );
    (hash2 % ADDRMAN_NEW_BUCKET_COUNT as u64) as usize
}

/// Slot within a bucket. `new` selects the table, like Core's 'N'/'K' tag.
fn bucket_position(secret: u64, new: bool, bucket: usize, addr: &NetAddr) -> usize {
    let tag: &[u8] = if new { b"N" } else { b"K" };
    let h = keyed_hash(
        secret,
        &[tag, &(bucket as u32).to_le_bytes()[..], &addr_bytes(addr)[..]],
    );
    (h % ADDRMAN_BUCKET_SIZE as u64) as usize
}

/// Keyed hash over the concatenated parts. Stands in for Core's
/// `HashWriter{} << nKey << ... << GetCheapHash()`.
fn keyed_hash(secret: u64, parts: &[&[u8]]) -> u64 {
    let mut buf = Vec::with_capacity(64);
    for part in parts {
        buf.extend_from_slice(part);
    }
    let (k0, k1) = sip_keys(secret);
    siphash24(k0, k1, &buf)
}

/// The 64-bit secret is k0. k1 is a fixed bijection of it, so the whole key is one u64.
fn sip_keys(secret: u64) -> (u64, u64) {
    (secret, secret.rotate_left(32) ^ 0x9e37_79b9_7f4a_7c15)
}

fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// SipHash-2-4 (2 compression rounds per block, 4 finalization rounds).
fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let m = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
        v[3] ^= m;
        sip_round(&mut v);
        sip_round(&mut v);
        v[0] ^= m;
    }
    let mut last = ((data.len() as u64) & 0xff) << 56;
    for (i, &b) in chunks.remainder().iter().enumerate() {
        last |= (b as u64) << (8 * i);
    }
    v[3] ^= last;
    sip_round(&mut v);
    sip_round(&mut v);
    v[0] ^= last;
    v[2] ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// Probability weight for selecting an entry. Mirrors AddrInfo::GetChance().
fn get_chance(entry: &Entry, now: i64) -> f64 {
    let mut chance = 1.0;
    if now - (entry.last_try as i64) < 600 {
        chance *= 0.01;
    }
    chance * 0.66f64.powi(entry.attempts.min(8) as i32)
}

/// Mirrors AddrInfo::IsTerrible(). Entries that may be overwritten in the new table.
fn is_terrible(entry: &Entry, now: i64) -> bool {
    let last_try = entry.last_try as i64;
    let seen = entry.addr.time as i64;
    let last_success = entry.last_success as i64;
    if now - last_try <= 60 {
        return false;
    }
    if seen > now + 600 {
        return true;
    }
    if now - seen > ADDRMAN_HORIZON_SECS {
        return true;
    }
    if last_success == 0 && entry.attempts >= ADDRMAN_RETRIES {
        return true;
    }
    now - last_success > ADDRMAN_MIN_FAIL_SECS && entry.attempts >= ADDRMAN_MAX_FAILURES
}

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Random u64 from std's RandomState, which is seeded from the OS.
fn random_u64() -> u64 {
    RandomState::new().build_hasher().finish()
}

/// Bounds-checked little-endian reader for `AddrMan::decode`.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "peers file: truncated"))?;
        let bytes = &self.buf[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

/// xorshift64* generator for table randomization. Not a source of secret keys.
#[derive(Debug, Clone)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        // A zero state would stay at zero forever.
        Self {
            state: if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// True with probability `p`. Values of `p` at or above 1.0 always succeed.
    fn chance(&mut self, p: f64) -> bool {
        let r = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        r < p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn fresh(ip: IpAddr) -> NetAddr {
        NetAddr::new(ip, 8333, 1, now_secs())
    }

    #[test]
    fn add_counts_and_rejects_duplicates_and_unroutable() {
        let mut am = AddrMan::new_seeded(7, 1);
        let src = fresh(v4(51, 0, 0, 1));
        let a = fresh(v4(34, 1, 2, 3));
        assert!(am.add(a, src));
        assert_eq!(am.size(), 1);
        assert_eq!(am.new_size(), 1);
        // Same record again carries no newer time, so nothing is placed.
        assert!(!am.add(a, src));
        assert_eq!(am.size(), 1);
        assert!(!am.add(fresh(v4(127, 0, 0, 1)), src));
        assert!(!am.add(fresh(v4(192, 168, 1, 1)), src));
        assert_eq!(am.size(), 1);
    }

    #[test]
    fn mark_good_moves_new_to_tried() {
        let mut am = AddrMan::new_seeded(7, 2);
        let src = fresh(v4(51, 0, 0, 1));
        let a = fresh(v4(34, 1, 2, 3));
        assert!(am.add(a, src));
        assert!(am.mark_good(&a));
        assert_eq!((am.new_size(), am.tried_size(), am.size()), (0, 1, 1));
        assert_eq!(am.select(true), None);
        assert_eq!(am.select(false), Some(a));
        assert!(!am.mark_good(&a));
        assert!(!am.mark_good(&fresh(v4(45, 6, 7, 8))));
    }

    #[test]
    fn bucket_hashing_is_keyed_and_in_range() {
        let src = v4(51, 0, 0, 1);
        // SipHash-2-4 reference vector: key 00..0f, empty message.
        assert_eq!(
            siphash24(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908, &[]),
            0x726f_db47_dd0e_0e31
        );
        let mut moved = 0;
        for i in 0..64u8 {
            let a = NetAddr::new(v4(34, 1, i, 7), 8333, 0, 0);
            let bucket = new_bucket(42, &a, src);
            assert_eq!(bucket, new_bucket(42, &a, src));
            assert!(bucket < ADDRMAN_NEW_BUCKET_COUNT);
            assert!(tried_bucket(42, &a) < ADDRMAN_TRIED_BUCKET_COUNT);
            assert!(bucket_position(42, true, bucket, &a) < ADDRMAN_BUCKET_SIZE);
            if new_bucket(43, &a, src) != bucket {
                moved += 1;
            }
        }
        assert!(moved > 32, "a different key should relocate most addresses");
    }

    #[test]
    fn select_is_reproducible_for_a_seed() {
        let src = fresh(v4(51, 0, 0, 1));
        let build = || {
            let mut am = AddrMan::new_seeded(9, 5);
            let mut known = Vec::new();
            for i in 0..20u8 {
                let a = fresh(v4(34, i, 2, 3));
                if am.add(a, src) {
                    known.push(a);
                }
            }
            (am, known)
        };
        let (mut am1, known) = build();
        let (mut am2, _) = build();
        assert!(known.len() >= 15, "most addresses should land in the table");

        let seq1: Vec<Option<NetAddr>> = (0..50).map(|_| am1.select(false)).collect();
        let seq2: Vec<Option<NetAddr>> = (0..50).map(|_| am2.select(false)).collect();
        assert_eq!(seq1, seq2);
        for got in seq1 {
            assert!(known.contains(&got.expect("table is non-empty")));
        }
    }

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("addrman-{}-{name}.dat", std::process::id()))
    }

    fn populated() -> AddrMan {
        let mut am = AddrMan::new_seeded(0x5eed, 11);
        for i in 0..60u8 {
            let source = fresh(v4(51, i % 3, 0, 1));
            am.add(fresh(v4(34, i, 2, 3)), source);
        }
        let good: Vec<NetAddr> = (0..60u8)
            .step_by(7)
            .map(|i| fresh(v4(34, i, 2, 3)))
            .filter(|a| am.contains(a))
            .collect();
        for addr in &good {
            am.attempt(addr, true);
            am.mark_good(addr);
        }
        am
    }

    #[test]
    fn save_and_load_round_trip() {
        let am = populated();
        assert!(am.tried_size() > 0 && am.new_size() > 0);
        let path = temp_file("roundtrip");
        am.save(&path).unwrap();
        assert!(!path.with_extension("dat.new").exists());

        let loaded = AddrMan::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(loaded.size(), am.size());
        assert_eq!(loaded.new_size(), am.new_size());
        assert_eq!(loaded.tried_size(), am.tried_size());
        assert_eq!(loaded.encode(), am.encode(), "a reloaded table encodes identically");
        for entry in am.entries.values() {
            assert!(loaded.contains(&entry.addr));
            assert_eq!(loaded.is_tried(&entry.addr), entry.in_tried);
        }
    }

    #[test]
    fn load_rejects_corrupt_and_truncated_files() {
        let am = populated();
        let mut bytes = am.encode();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        assert_eq!(
            AddrMan::decode(&bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let bytes = am.encode();
        assert!(AddrMan::decode(&bytes[..bytes.len() - 3]).is_err());
        assert!(AddrMan::load(&temp_file("missing")).is_err());
    }

    #[test]
    fn get_addresses_is_capped_by_count_and_percent() {
        let mut am = populated();
        let size = am.size();
        assert_eq!(am.get_addresses(1000, 23).len(), size * 23 / 100);
        assert_eq!(am.get_addresses(3, 100).len(), 3usize.min(size));
        let sample = am.get_addresses(1000, 100);
        assert_eq!(sample.len(), size);
        let unique: std::collections::HashSet<_> = sample.iter().map(addr_key).collect();
        assert_eq!(unique.len(), size);
    }

    #[test]
    fn local_addresses_are_kept_only_when_enabled() {
        let src = fresh(v4(51, 0, 0, 1));
        let local = NetAddr::new(v4(127, 0, 0, 1), 18444, 1, now_secs());
        let mut am = AddrMan::new_seeded(3, 3);
        assert!(!am.add(local, src));
        am.set_accept_local(true);
        assert!(am.add(local, src));
        assert!(am.contains(&local));
    }
}
