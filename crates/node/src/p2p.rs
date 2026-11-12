//! P2P connection manager. Port of the network-facing parts of `src/net.cpp`
//! and `src/net_processing.cpp`: listeners, outbound dialing, address discovery
//! and relay, `peers.dat`, one task per peer, and one manager task that owns
//! `SyncManager`, the address table and every peer's outbound queue. The node
//! lock is held only while a single call runs.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::block::{Header, Version};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::address::{AddrV2Message, Address};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::ServiceFlags;
use bitcoin::CompactTarget;
use btc_chain::{BlockStatus, BlockTree, IndexId, ValidationError};
use btc_consensus::ChainParams;
use btc_network::addrman::{netgroup, AddrMan, NetAddr};
use btc_network::message::{decode_payload, MessageHeader, NetworkMessage as Wire, HEADER_SIZE};
use btc_network::peer::{LocalVersion, Peer, CONNECT_TIMEOUT};
use btc_network::sync::{ChainView, PeerId, SyncAction, SyncManager, MAX_HEADERS_RESULTS};
use btc_primitives::{Block as PrimBlock, BlockHash, BlockHeader as PrimHeader, Tx as PrimTx, Txid};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{interval, sleep, timeout};

use crate::node::{Node, SharedNode};

const TICK_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Automatic outbound dials give up after this long.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Minimum wait between DNS seed lookups while the address table is empty.
const SEED_RETRY: Duration = Duration::from_secs(60);
const PEER_QUEUE: usize = 1024;
const EVENT_QUEUE: usize = 4096;
/// `MAX_INV_SZ`.
const MAX_INV_ITEMS: usize = 50_000;
/// `MAX_ADDR_TO_SEND`: largest `addr` message accepted or sent.
const MAX_ADDR_TO_SEND: usize = 1000;
/// `MAX_PCT_ADDR_TO_SEND`: share of the table in a `getaddr` reply.
const MAX_PCT_ADDR_TO_SEND: usize = 23;
/// `MAX_ADDR_RATE_PER_SECOND`: refill rate of the per-peer address token bucket.
const MAX_ADDR_RATE_PER_SECOND: f64 = 0.1;
/// Tokens granted when we send `getaddr`, so the reply is accepted in full
/// (Core's `m_addr_token_bucket += MAX_ADDR_TO_SEND`).
const GETADDR_TOKEN_GRANT: f64 = 1000.0;
/// Only messages with at most this many addresses are relayed.
const ADDR_RELAY_MAX: usize = 10;
/// Relayed addresses must have been seen within this window.
const ADDR_FRESH_SECS: u32 = 10 * 60;
/// Timestamps further in the future than this are rewritten.
const ADDR_FUTURE_SECS: u32 = 10 * 60;
/// Timestamps at or below this are treated as unset, as in Core.
const ADDR_MIN_TIME: u32 = 100_000_000;
/// Timestamp given to an undated address: five days ago.
const ADDR_UNDATED_AGE_SECS: u32 = 5 * 24 * 60 * 60;
/// Fresh addresses are relayed to this many peers.
const ADDR_RELAY_PEERS: usize = 2;

/// Settings for the P2P layer. `Default` is a node with no listener, no
/// `-connect` list and no data directory.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// Listen address for inbound peers. None disables the listener.
    pub listen: Option<SocketAddr>,
    /// `-connect`: only these peers are dialed, and automatic outbound is off.
    pub connect: Vec<SocketAddr>,
    /// Automatic full-relay outbound connections (`-maxconnections`, at most 8).
    pub max_outbound: usize,
    /// Inbound connection limit (`-maxconnections` minus the outbound slots).
    pub max_inbound: usize,
    pub user_agent: String,
    /// `-addnode`: kept connected in addition to automatic outbound peers.
    pub add_nodes: Vec<SocketAddr>,
    /// `-seednode`: asked for addresses once, then disconnected.
    pub seed_nodes: Vec<SocketAddr>,
    /// `-dnsseed`: resolve `ChainParams::seeds` while the address table is empty.
    pub dns_seed: bool,
    /// Address advertised to peers (`-externalip` with the p2p port). Only used while listening.
    pub advertise: Option<SocketAddr>,
    /// Directory for `peers.dat`. None keeps the address table in memory only.
    pub datadir: Option<PathBuf>,
    /// Keep loopback and private addresses in the table (regtest and tests).
    pub accept_local: bool,
    /// SOCKS5 proxy for outbound connections (`-proxy=`, e.g. Tor's SOCKS
    /// port). When set, inbound listening should be disabled: the proxy
    /// carries clearnet IPs only, onion peers are not supported yet.
    pub proxy: Option<SocketAddr>,
    /// Maximum random delay before relaying a new transaction inventory
    /// to a peer (relay jitter, Dandelion-style). Zero disables jitter.
    pub relay_jitter: Duration,
    /// Interval between checks for free automatic outbound slots.
    pub outbound_interval: Duration,
    /// Interval between `peers.dat` writes.
    pub dump_interval: Duration,
    /// How long a `-seednode` connection waits for an `addr` reply before it is dropped.
    pub seed_timeout: Duration,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen: None,
            connect: Vec::new(),
            max_outbound: 8,
            max_inbound: 117,
            user_agent: format!("/btc-rust:{}/", env!("CARGO_PKG_VERSION")),
            add_nodes: Vec::new(),
            seed_nodes: Vec::new(),
            dns_seed: true,
            advertise: None,
            datadir: None,
            accept_local: false,
            proxy: None,
            relay_jitter: Duration::ZERO,
            outbound_interval: Duration::from_millis(500),
            dump_interval: Duration::from_secs(15 * 60),
            seed_timeout: Duration::from_secs(30),
        }
    }
}

/// Serves the P2P network until `shutdown` is notified.
pub async fn run_p2p(node: SharedNode, config: P2pConfig, shutdown: Arc<Notify>) -> io::Result<()> {
    let listener = match config.listen {
        Some(addr) => Some(TcpListener::bind(addr).await?),
        None => None,
    };
    let addrman = Arc::new(Mutex::new(load_addrman(&config)));
    run_with_listener(node, listener, config, addrman, shutdown).await;
    Ok(())
}

/// Starts from `peers.dat` when present. An unreadable file is reported and
/// replaced by an empty table, which the next write overwrites.
fn load_addrman(config: &P2pConfig) -> AddrMan {
    let mut addrman = match config.datadir.as_deref().map(peers_path) {
        Some(path) if path.exists() => AddrMan::load(&path).unwrap_or_else(|err| {
            eprintln!("warning: ignoring unreadable {}: {err}", path.display());
            AddrMan::new()
        }),
        _ => AddrMan::new(),
    };
    addrman.set_accept_local(config.accept_local);
    addrman
}

fn peers_path(datadir: &Path) -> PathBuf {
    datadir.join("peers.dat")
}

async fn run_with_listener(
    node: SharedNode,
    listener: Option<TcpListener>,
    config: P2pConfig,
    addrman: Arc<Mutex<AddrMan>>,
    shutdown: Arc<Notify>,
) {
    let params = lock(&node).params.clone();
    let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
    let ctx = Arc::new(Ctx {
        node: node.clone(),
        params,
        user_agent: config.user_agent.clone(),
        events: events_tx,
        next_id: AtomicU64::new(1),
        inbound: Arc::new(Semaphore::new(config.max_inbound)),
        advertise: config.advertise.filter(|_| listener.is_some()),
        proxy: config.proxy,
        relay_jitter: config.relay_jitter,
    });

    let mut tasks = JoinSet::new();
    if let Some(listener) = listener {
        tasks.spawn(accept_loop(listener, ctx.clone()));
    }
    for addr in config.connect.iter().chain(&config.add_nodes).copied() {
        tasks.spawn(dial_loop(addr, ctx.clone(), Link::Fixed));
    }
    for addr in config.seed_nodes.iter().copied() {
        let ctx = ctx.clone();
        tasks.spawn(async move { dial_once(addr, &ctx, Link::Seed).await });
    }
    Manager::new(node, ctx, config, addrman).run(events_rx, shutdown).await;
    // Dropping `tasks` aborts the listener and the fixed-peer dialers.
}

/// Shared handles for connection tasks.
struct Ctx {
    node: SharedNode,
    params: ChainParams,
    user_agent: String,
    events: mpsc::Sender<Event>,
    next_id: AtomicU64,
    inbound: Arc<Semaphore>,
    /// Our address as peers should see it, when listening.
    advertise: Option<SocketAddr>,
    /// SOCKS5 proxy for outbound dials (`-proxy=`).
    proxy: Option<SocketAddr>,
    /// Max delay before relaying a transaction inventory.
    relay_jitter: Duration,
}

impl Ctx {
    fn height(&self) -> i32 {
        lock(&self.node).chainstate.height() as i32
    }
}

/// Why a connection exists. Only `Auto` counts toward `max_outbound` and only
/// `Auto` dials are retried through the address table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    Inbound,
    /// Automatic full-relay outbound, chosen from the address table.
    Auto,
    /// `-connect` or `-addnode`: redialed forever.
    Fixed,
    /// `-seednode`: one connection, dropped after the `addr` reply.
    Seed,
}

async fn accept_loop(listener: TcpListener, ctx: Arc<Ctx>) {
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let Ok(permit) = ctx.inbound.clone().try_acquire_owned() else {
            continue;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let peer = Peer::from_stream(stream, addr, &ctx.params);
            serve_connection(peer, &ctx, addr, Link::Inbound).await;
            drop(permit);
        });
    }
}

/// Keeps a connection to `addr` alive, redialing after each disconnect.
async fn dial_loop(addr: SocketAddr, ctx: Arc<Ctx>, link: Link) {
    loop {
        dial_once(addr, &ctx, link).await;
        sleep(RETRY_INTERVAL).await;
    }
}

/// One outbound attempt, then serve the connection until it ends.
async fn dial_once(addr: SocketAddr, ctx: &Ctx, link: Link) {
    let limit = if link == Link::Auto { DIAL_TIMEOUT } else { CONNECT_TIMEOUT };
    match timeout(limit, Peer::connect_via_proxy(addr, ctx.proxy, &ctx.params)).await {
        Ok(Ok(peer)) => serve_connection(peer, ctx, addr, link).await,
        _ => {
            let _ = ctx.events.send(Event::DialFailed { addr, link }).await;
        }
    }
}

/// Handshake, then forward messages both ways until the connection ends.
async fn serve_connection(mut peer: Peer<TcpStream>, ctx: &Ctx, addr: SocketAddr, link: Link) {
    let local = LocalVersion {
        user_agent: ctx.user_agent.clone(),
        start_height: ctx.height(),
        ..LocalVersion::default()
    };
    let Ok(info) = peer.handshake(&local).await else {
        if link != Link::Inbound {
            let _ = ctx.events.send(Event::DialFailed { addr, link }).await;
        }
        return;
    };

    let id = ctx.next_id.fetch_add(1, Ordering::Relaxed);
    let (out_tx, out_rx) = mpsc::channel(PEER_QUEUE);
    let (events_tx, mut events_rx) = mpsc::channel::<Wire>(PEER_QUEUE);
    let connected = Event::Connected {
        id,
        start_height: info.start_height,
        outbound: out_tx,
        addr,
        link,
    };
    if ctx.events.send(connected).await.is_err() {
        return;
    }

    let events = ctx.events.clone();
    let forwarder = tokio::spawn(async move {
        while let Some(msg) = events_rx.recv().await {
            if events.send(Event::Message { id, msg }).await.is_err() {
                break;
            }
        }
    });
    let _ = peer.run(out_rx, events_tx).await;
    forwarder.abort();
    let _ = ctx.events.send(Event::Closed { id }).await;
}

enum Event {
    Connected {
        id: PeerId,
        start_height: i32,
        outbound: mpsc::Sender<Wire>,
        addr: SocketAddr,
        link: Link,
    },
    Message {
        id: PeerId,
        msg: Wire,
    },
    Closed {
        id: PeerId,
    },
    /// An outbound attempt or handshake failed.
    DialFailed {
        addr: SocketAddr,
        link: Link,
    },
    /// DNS seed lookup finished.
    Resolved(Vec<SocketAddr>),
}

/// Manager-side state of one connected peer.
struct PeerState {
    outbound: mpsc::Sender<Wire>,
    addr: SocketAddr,
    link: Link,
    /// Core's `m_addr_token_bucket`: one token per address accepted.
    addr_tokens: f64,
    addr_refilled: Instant,
    /// Inbound peers get one `getaddr` reply.
    getaddr_recvd: bool,
    /// Seed connections are dropped at this instant if no `addr` arrived first.
    seed_deadline: Option<Instant>,
}

/// Owns the sync state, the address table and every peer's outbound queue.
struct Manager {
    node: SharedNode,
    ctx: Arc<Ctx>,
    magic: [u8; 4],
    config: P2pConfig,
    addrman: Arc<Mutex<AddrMan>>,
    sync: SyncManager,
    peers: HashMap<PeerId, PeerState>,
    /// Automatic outbound dials in flight.
    dialing: HashSet<SocketAddr>,
    last_seed: Option<Instant>,
    last_dump: Instant,
    started: Instant,
    /// A block arrived: request more right away instead of waiting a tick.
    refill: bool,
}

/// Random relay delay in [0, max], drawn from the OS RNG. (Previously a
/// xorshift over the wall clock and a counter: an observer who knows roughly
/// when the node relayed could predict the delays that jitter is meant to hide.)
fn relay_delay(max: Duration) -> Duration {
    let max_nanos = max.as_nanos() as u64;
    if max_nanos == 0 {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        // No OS entropy: fail safe with the maximum delay, never a guessable one.
        return max;
    }
    // Multiply-shift range reduction: uniform up to 2^-64 bias, no modulo skew.
    let r = u64::from_le_bytes(bytes) as u128;
    Duration::from_nanos(((r * max_nanos as u128) >> 64) as u64)
}

impl Manager {
    fn new(node: SharedNode, ctx: Arc<Ctx>, config: P2pConfig, addrman: Arc<Mutex<AddrMan>>) -> Self {
        let magic = ctx.params.magic;
        Self {
            node,
            ctx,
            magic,
            config,
            addrman,
            sync: SyncManager::new(),
            peers: HashMap::new(),
            dialing: HashSet::new(),
            last_seed: None,
            last_dump: Instant::now(),
            started: Instant::now(),
            refill: false,
        }
    }

    async fn run(mut self, mut events: mpsc::Receiver<Event>, shutdown: Arc<Notify>) {
        let stop = shutdown.notified();
        tokio::pin!(stop);
        let mut ticker = interval(TICK_INTERVAL);
        let mut outbound = interval(self.config.outbound_interval.max(Duration::from_millis(1)));
        loop {
            tokio::select! {
                _ = &mut stop => break,
                _ = ticker.tick() => self.tick(),
                _ = outbound.tick() => self.fill_outbound(),
                event = events.recv() => match event {
                    Some(event) => self.on_event(event),
                    None => break,
                },
            }
            if std::mem::take(&mut self.refill) {
                self.tick();
            }
        }
        self.dump();
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Connected {
                id,
                start_height,
                outbound,
                addr,
                link,
            } => self.on_connected(id, start_height, outbound, addr, link),
            Event::Message { id, msg } => self.on_message(id, msg),
            Event::Closed { id } => self.drop_peer(id),
            Event::DialFailed { addr, link } => {
                if link == Link::Auto {
                    self.dialing.remove(&addr);
                    lock_addrman(&self.addrman).attempt(&net_addr(addr, 0, 0), true);
                }
            }
            Event::Resolved(addrs) => {
                let now = unix_now();
                let mut am = lock_addrman(&self.addrman);
                for addr in addrs {
                    am.add(net_addr(addr, 0, now), net_addr(addr, 0, now));
                }
            }
        }
    }

    fn on_connected(
        &mut self,
        id: PeerId,
        start_height: i32,
        outbound: mpsc::Sender<Wire>,
        addr: SocketAddr,
        link: Link,
    ) {
        let now = Instant::now();
        self.peers.insert(
            id,
            PeerState {
                outbound,
                addr,
                link,
                addr_tokens: 1.0,
                addr_refilled: now,
                getaddr_recvd: false,
                seed_deadline: (link == Link::Seed).then(|| now + self.config.seed_timeout),
            },
        );
        self.sync.peer_connected(id, start_height);
        if link == Link::Inbound {
            return;
        }
        if link == Link::Auto {
            self.dialing.remove(&addr);
        }
        lock_addrman(&self.addrman).mark_good(&net_addr(addr, 0, 0));

        self.send(id, to_wire(self.magic, &NetworkMessage::GetAddr));
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.addr_tokens += GETADDR_TOKEN_GRANT;
        }
        if let Some(own) = self.ctx.advertise.filter(|_| link != Link::Seed) {
            let entry = (unix_now(), Address::new(&own, ServiceFlags::NONE));
            self.send(id, to_wire(self.magic, &NetworkMessage::Addr(vec![entry])));
        }
    }

    fn on_message(&mut self, id: PeerId, msg: Wire) {
        if !self.peers.contains_key(&id) {
            return;
        }
        let msg = match from_wire(self.magic, msg) {
            Inbound::Message(msg) => msg,
            Inbound::Ignored => return,
            Inbound::Malformed => return self.drop_peer(id),
        };

        let replies = match msg {
            NetworkMessage::GetHeaders(req) => {
                let node = lock(&self.node);
                let headers = headers_reply(&node, &req.locator_hashes, &req.stop_hash);
                vec![to_wire(self.magic, &NetworkMessage::Headers(headers))]
            }
            NetworkMessage::GetData(items) => {
                let node = lock(&self.node);
                data_replies(&node, self.magic, &items)
            }
            NetworkMessage::MemPool => {
                let node = lock(&self.node);
                mempool_replies(&node, self.magic)
            }
            NetworkMessage::GetAddr => self.getaddr_replies(id),
            NetworkMessage::Addr(list) => {
                let total = list.len();
                let addrs = list
                    .iter()
                    .filter_map(|(time, addr)| addr_v1_to_net(*time, addr))
                    .collect();
                self.on_addr(id, total, addrs);
                return;
            }
            NetworkMessage::AddrV2(list) => {
                let total = list.len();
                let addrs = list.iter().filter_map(addr_v2_to_net).collect();
                self.on_addr(id, total, addrs);
                return;
            }
            other => {
                let actions = {
                    let node = lock(&self.node);
                    self.sync.on_message(&NodeChainView::new(&node), id, other)
                };
                self.execute(actions);
                return;
            }
        };
        for reply in replies {
            self.send(id, reply);
        }
    }

    /// `ProcessMessage` for `addr` and `addrv2`: rate limit, store, relay.
    /// `total` counts every entry in the message, including ones we cannot store.
    fn on_addr(&mut self, id: PeerId, total: usize, mut addrs: Vec<NetAddr>) {
        if total > MAX_ADDR_TO_SEND {
            self.drop_peer(id);
            return;
        }
        let now = unix_now();
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        let admitted = admit_addresses(
            &mut peer.addr_tokens,
            &mut peer.addr_refilled,
            Instant::now(),
            addrs.len(),
        );
        addrs.truncate(admitted);
        let source = net_addr(peer.addr, 0, now);
        let is_seed = peer.link == Link::Seed;

        for addr in &mut addrs {
            if addr.time <= ADDR_MIN_TIME || addr.time > now + ADDR_FUTURE_SECS {
                addr.time = now.saturating_sub(ADDR_UNDATED_AGE_SECS);
            }
        }
        let own = self.ctx.advertise;
        addrs.retain(|addr| {
            !own.is_some_and(|me| me.ip() == addr.ip && me.port() == addr.port)
        });

        let mut am = lock_addrman(&self.addrman);
        let usable: Vec<NetAddr> = addrs.iter().copied().filter(|addr| am.accepts_ip(addr.ip)).collect();
        if total <= ADDR_RELAY_MAX {
            let fresh: Vec<NetAddr> = usable
                .iter()
                .copied()
                .filter(|addr| addr.time > now.saturating_sub(ADDR_FRESH_SECS))
                .collect();
            if !fresh.is_empty() {
                drop(am);
                self.relay_addrs(id, &fresh);
                am = lock_addrman(&self.addrman);
            }
        }
        for addr in &usable {
            am.add(*addr, source);
        }
        drop(am);

        if is_seed {
            self.drop_peer(id);
        }
    }

    /// `RelayAddress`: sends fresh addresses to up to two other peers, chosen at random.
    fn relay_addrs(&mut self, source: PeerId, addrs: &[NetAddr]) {
        let mut targets: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(id, peer)| **id != source && peer.link != Link::Seed)
            .map(|(id, _)| *id)
            .collect();
        for i in 0..targets.len().min(ADDR_RELAY_PEERS) {
            let j = i + random_below((targets.len() - i) as u64) as usize;
            targets.swap(i, j);
        }
        let entries: Vec<(u32, Address)> = addrs.iter().map(to_v1_entry).collect();
        let wire = to_wire(self.magic, &NetworkMessage::Addr(entries));
        for id in targets.into_iter().take(ADDR_RELAY_PEERS) {
            self.send(id, wire.clone());
        }
    }

    /// `getaddr` from an inbound peer gets one reply: a random sample of the
    /// table, plus our own address when advertised.
    fn getaddr_replies(&mut self, id: PeerId) -> Vec<Wire> {
        let Some(peer) = self.peers.get_mut(&id) else {
            return Vec::new();
        };
        if peer.link != Link::Inbound || peer.getaddr_recvd {
            return Vec::new();
        }
        peer.getaddr_recvd = true;

        let own = self.ctx.advertise;
        let reserve = usize::from(own.is_some());
        let sample = lock_addrman(&self.addrman).get_addresses(MAX_ADDR_TO_SEND - reserve, MAX_PCT_ADDR_TO_SEND);
        let mut entries: Vec<(u32, Address)> = sample.iter().map(to_v1_entry).collect();
        if let Some(own) = own {
            entries.push((unix_now(), Address::new(&own, ServiceFlags::NONE)));
        }
        if entries.is_empty() {
            return Vec::new();
        }
        vec![to_wire(self.magic, &NetworkMessage::Addr(entries))]
    }

    fn tick(&mut self) {
        let now = self.started.elapsed().as_secs();
        let actions = {
            let node = lock(&self.node);
            self.sync.tick(&NodeChainView::new(&node), now)
        };
        self.execute(actions);

        let (tips, txs) = {
            let mut node = lock(&self.node);
            (node.take_new_tips(), node.take_new_txs())
        };
        self.announce(&tips, &txs);

        let at = Instant::now();
        let expired: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.seed_deadline.is_some_and(|deadline| deadline <= at))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.drop_peer(id);
        }
        if self.last_dump.elapsed() >= self.config.dump_interval {
            self.dump();
        }
    }

    /// Opens automatic outbound connections until `max_outbound` are in flight
    /// or connected. Addresses come from the table; with an empty table, DNS seeds are resolved.
    fn fill_outbound(&mut self) {
        let max = if self.config.connect.is_empty() {
            self.config.max_outbound
        } else {
            0
        };
        if max == 0 {
            return;
        }
        let auto = self.peers.values().filter(|peer| peer.link == Link::Auto).count() + self.dialing.len();
        if auto >= max {
            return;
        }
        if lock_addrman(&self.addrman).size() == 0 {
            self.maybe_resolve_seeds();
            return;
        }

        // Each `select` can be costly (it retries while the chance is low), so the
        // number of draws per tick is bounded. Rejected draws are cheap to repeat later.
        let mut free = max - auto;
        let mut draws = 2 * free + 2;
        while free > 0 && draws > 0 {
            draws -= 1;
            let candidate = lock_addrman(&self.addrman).select(false);
            let Some(candidate) = candidate else {
                break;
            };
            let addr = SocketAddr::new(candidate.ip, candidate.port);
            if !self.dial_allowed(addr) {
                continue;
            }
            self.dialing.insert(addr);
            let ctx = self.ctx.clone();
            tokio::spawn(async move { dial_once(addr, &ctx, Link::Auto).await });
            free -= 1;
        }
    }

    /// Whether an automatic dial to `addr` makes sense now: not us, not a
    /// fixed peer (those have their own loops), not already connected or dialing,
    /// and not in a netgroup we already use for outbound.
    fn dial_allowed(&self, addr: SocketAddr) -> bool {
        if self.ctx.advertise.is_some_and(|me| me == addr) {
            return false;
        }
        if self.config.connect.contains(&addr) || self.config.add_nodes.contains(&addr) {
            return false;
        }
        if self.dialing.contains(&addr) || self.peers.values().any(|peer| peer.addr == addr) {
            return false;
        }
        let group = netgroup(addr.ip());
        let busy_dial = self.dialing.iter().any(|other| netgroup(other.ip()) == group);
        let busy_peer = self
            .peers
            .values()
            .any(|peer| peer.link == Link::Auto && netgroup(peer.addr.ip()) == group);
        !busy_dial && !busy_peer
    }

    /// Starts a DNS seed lookup, at most once per `SEED_RETRY`.
    fn maybe_resolve_seeds(&mut self) {
        // Defence in depth: seed lookups are cleartext DNS and bypass the
        // SOCKS proxy, so they never run while a proxy is configured.
        if !self.config.dns_seed
            || self.config.proxy.is_some()
            || self.ctx.params.seeds.is_empty()
        {
            return;
        }
        if self.last_seed.is_some_and(|at| at.elapsed() < SEED_RETRY) {
            return;
        }
        self.last_seed = Some(Instant::now());
        let seeds = self.ctx.params.seeds.clone();
        let port = self.ctx.params.default_port;
        let events = self.ctx.events.clone();
        tokio::spawn(async move {
            let found = resolve_seeds(&seeds, port).await;
            let _ = events.send(Event::Resolved(found)).await;
        });
    }

    /// Relays new tips as `headers` (so a peer learns every new block from one
    /// message) and new transactions as `inv`.
    fn announce(&self, tips: &[BlockHash], txs: &[Txid]) {
        let mut messages = Vec::new();
        if !tips.is_empty() {
            let headers: Vec<Header> = {
                let node = lock(&self.node);
                tips.iter()
                    .filter_map(|hash| node.chainstate.header_of(hash))
                    .map(|(header, _)| to_bitcoin_header(&header))
                    .collect()
            };
            for chunk in headers.chunks(MAX_HEADERS_RESULTS) {
                messages.push(to_wire(self.magic, &NetworkMessage::Headers(chunk.to_vec())));
            }
        }
        if !txs.is_empty() {
            let items: Vec<Inventory> = txs.iter().map(|txid| Inventory::Transaction(*txid)).collect();
            for chunk in items.chunks(MAX_INV_ITEMS) {
                messages.push(to_wire(self.magic, &NetworkMessage::Inv(chunk.to_vec())));
            }
        }
        // Relay jitter: inventory is a network fingerprint, so each peer
        // gets it after its own random delay in [0, relay_jitter]. This
        // flattens the arrival pattern a network observer sees.
        for message in messages {
            for peer in self.peers.values() {
                let jitter = self.config.relay_jitter;
                let outbound = peer.outbound.clone();
                if jitter.is_zero() {
                    let _ = outbound.try_send(message.clone());
                } else {
                    let message = message.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(relay_delay(jitter)).await;
                        let _ = outbound.try_send(message);
                    });
                }
            }
        }
    }

    fn execute(&mut self, actions: Vec<SyncAction>) {
        for action in actions {
            match action {
                SyncAction::Send(id, msg) => {
                    let wire = to_wire(self.magic, &msg);
                    self.send(id, wire);
                }
                SyncAction::AcceptHeaders(id, headers) => {
                    let headers: Vec<PrimHeader> = headers.iter().map(to_primitive_header).collect();
                    let result = lock(&self.node).submit_headers(&headers);
                    if let Err(err) = result {
                        if !matches!(err, ValidationError::Duplicate) {
                            self.drop_peer(id);
                        }
                    }
                }
                SyncAction::AcceptBlock(id, block) => {
                    let Some(block) = to_primitive_block(&block) else {
                        self.drop_peer(id);
                        continue;
                    };
                    let result = lock(&self.node).submit_block(&block);
                    self.refill = true;
                    if let Err(err) = result {
                        if !matches!(err, ValidationError::Duplicate) {
                            self.drop_peer(id);
                        }
                    }
                }
                SyncAction::AcceptTx(_, tx) => {
                    if let Some(tx) = to_primitive_tx(&tx) {
                        let _ = lock(&self.node).submit_tx(tx);
                    }
                }
                SyncAction::Disconnect(id, _) => self.drop_peer(id),
            }
        }
    }

    fn send(&self, id: PeerId, msg: Wire) {
        if let Some(peer) = self.peers.get(&id) {
            let _ = peer.outbound.try_send(msg);
        }
    }

    fn drop_peer(&mut self, id: PeerId) {
        self.sync.peer_disconnected(id);
        self.peers.remove(&id);
    }

    /// Writes `peers.dat` when a data directory is configured.
    fn dump(&mut self) {
        self.last_dump = Instant::now();
        let Some(dir) = self.config.datadir.as_deref() else {
            return;
        };
        let path = peers_path(dir);
        if let Err(err) = lock_addrman(&self.addrman).save(&path) {
            eprintln!("warning: cannot write {}: {err}", path.display());
        }
    }
}

/// Resolves DNS seed entries. Each is `host`, `host:port`, or an `ip:port`
/// literal; a bare host uses the chain's default port.
async fn resolve_seeds(seeds: &[String], default_port: u16) -> Vec<SocketAddr> {
    let mut found = Vec::new();
    for seed in seeds {
        if let Ok(addr) = seed.parse::<SocketAddr>() {
            found.push(addr);
            continue;
        }
        let parsed = seed
            .rsplit_once(':')
            .filter(|(host, _)| !host.contains(':'))
            .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)));
        let (host, port) = parsed.unwrap_or((seed.as_str(), default_port));
        if let Ok(addrs) = lookup_host((host, port)).await {
            found.extend(addrs);
        }
    }
    found
}

/// Core's address token bucket. The bucket refills at `MAX_ADDR_RATE_PER_SECOND`
/// up to `MAX_ADDR_TO_SEND`, and each admitted address costs one token. Returns
/// how many of `wanted` addresses may be processed.
fn admit_addresses(tokens: &mut f64, last: &mut Instant, now: Instant, wanted: usize) -> usize {
    let cap = MAX_ADDR_TO_SEND as f64;
    if *tokens < cap {
        let elapsed = now.saturating_duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * MAX_ADDR_RATE_PER_SECOND).min(cap);
    }
    *last = now;
    let admitted = (tokens.floor().max(0.0) as usize).min(wanted);
    *tokens -= admitted as f64;
    admitted
}

fn addr_v1_to_net(time: u32, addr: &Address) -> Option<NetAddr> {
    let sock = addr.socket_addr().ok()?;
    Some(net_addr(sock, addr.services.to_u64(), time))
}

fn addr_v2_to_net(msg: &AddrV2Message) -> Option<NetAddr> {
    let sock = msg.socket_addr().ok()?;
    Some(net_addr(sock, msg.services.to_u64(), msg.time))
}

fn to_v1_entry(addr: &NetAddr) -> (u32, Address) {
    let sock = SocketAddr::new(addr.ip, addr.port);
    (addr.time, Address::new(&sock, ServiceFlags::from(addr.services)))
}

fn net_addr(addr: SocketAddr, services: u64, time: u32) -> NetAddr {
    NetAddr::new(addr.ip(), addr.port(), services, time)
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as u32)
        .unwrap_or(0)
}

/// Uniform-ish value below `n` (`n > 0`), from std's OS-seeded hasher.
fn random_below(n: u64) -> u64 {
    RandomState::new().build_hasher().finish() % n
}

fn lock_addrman(addrman: &Mutex<AddrMan>) -> MutexGuard<'_, AddrMan> {
    addrman.lock().unwrap_or_else(PoisonError::into_inner)
}

fn lock(node: &SharedNode) -> MutexGuard<'_, Node> {
    node.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Chain view over a locked node, for `SyncManager`.
pub struct NodeChainView<'a>(&'a Node);

impl<'a> NodeChainView<'a> {
    pub fn new(node: &'a Node) -> Self {
        Self(node)
    }
}

impl ChainView for NodeChainView<'_> {
    fn locator(&self) -> Vec<BlockHash> {
        let chainstate = &self.0.chainstate;
        header_locator(&chainstate.tree, chainstate.best_header())
    }

    fn header_known(&self, hash: &BlockHash) -> bool {
        self.0.chainstate.tree.lookup(hash).is_some()
    }

    fn have_block_data(&self, hash: &BlockHash) -> bool {
        let tree = &self.0.chainstate.tree;
        tree.lookup(hash)
            .is_some_and(|id| tree.get(id).status.0 & BlockStatus::HAVE_DATA != 0)
    }

    fn best_header_height(&self) -> u32 {
        let chainstate = &self.0.chainstate;
        chainstate.tree.get(chainstate.best_header()).height
    }

    fn blocks_to_download(&self, after_tip: &BlockHash, max: usize) -> Vec<BlockHash> {
        let chainstate = &self.0.chainstate;
        let (tree, chain) = (&chainstate.tree, &chainstate.chain);
        let Some(mut cursor) = tree.lookup(after_tip) else {
            return Vec::new();
        };
        let mut missing = Vec::new();
        while !chain.contains(tree, cursor) {
            let entry = tree.get(cursor);
            if entry.status.is_failed() {
                return Vec::new();
            }
            if entry.status.0 & BlockStatus::HAVE_DATA == 0 {
                missing.push(entry.hash);
            }
            match entry.prev {
                Some(prev) => cursor = prev,
                None => break,
            }
        }
        missing.reverse();
        missing.truncate(max);
        missing
    }
}

/// `CBlockLocator` starting at `start`: exponentially spaced back to genesis.
fn header_locator(tree: &BlockTree, start: IndexId) -> Vec<BlockHash> {
    let mut hashes = Vec::new();
    let mut step: u32 = 1;
    let mut cursor = Some(start);
    while let Some(current) = cursor {
        let entry = tree.get(current);
        hashes.push(entry.hash);
        if entry.height == 0 {
            break;
        }
        cursor = tree.get_ancestor(current, entry.height.saturating_sub(step));
        if hashes.len() > 10 {
            step = step.saturating_mul(2);
        }
    }
    hashes
}

/// `ProcessGetHeaders`: from the first locator hash on the active chain (or
/// genesis), up to `MAX_HEADERS_RESULTS` headers, ending at `stop` if it is found.
fn headers_reply(node: &Node, locator: &[BlockHash], stop: &BlockHash) -> Vec<Header> {
    let (tree, chain) = (&node.chainstate.tree, &node.chainstate.chain);
    let fork = locator
        .iter()
        .filter_map(|hash| tree.lookup(hash))
        .find(|&id| chain.contains(tree, id))
        .or_else(|| chain.genesis());
    let mut out = Vec::new();
    let Some(mut cursor) = fork else {
        return out;
    };
    while let Some(next) = chain.next(tree, cursor) {
        let entry = tree.get(next);
        out.push(to_bitcoin_header(&entry.header));
        if entry.hash == *stop || out.len() == MAX_HEADERS_RESULTS {
            break;
        }
        cursor = next;
    }
    out
}

/// Answers `getdata`: blocks and mempool transactions we have, `notfound` for the rest.
fn data_replies(node: &Node, magic: [u8; 4], items: &[Inventory]) -> Vec<Wire> {
    let mut replies = Vec::new();
    let mut missing = Vec::new();
    for item in items {
        match *item {
            Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                let tree = &node.chainstate.tree;
                let stored = tree
                    .lookup(&hash)
                    .is_some_and(|id| tree.get(id).status.0 & BlockStatus::HAVE_DATA != 0);
                match stored.then(|| node.chainstate.get_block(&hash)).flatten() {
                    Some(block) => replies.push(raw("block", serialize(&block))),
                    None => missing.push(*item),
                }
            }
            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                match node.mempool.get(&txid) {
                    Some(entry) => replies.push(raw("tx", serialize(&entry.tx))),
                    None => missing.push(*item),
                }
            }
            Inventory::WTx(wtxid) => {
                let found = node
                    .mempool
                    .sorted_by_fee_rate()
                    .into_iter()
                    .find(|entry| entry.tx.wtxid() == wtxid);
                match found {
                    Some(entry) => replies.push(raw("tx", serialize(&entry.tx))),
                    None => missing.push(*item),
                }
            }
            _ => missing.push(*item),
        }
    }
    if !missing.is_empty() {
        replies.push(to_wire(magic, &NetworkMessage::NotFound(missing)));
    }
    replies
}

/// Answers `mempool` with one `inv` per batch of mempool transactions.
fn mempool_replies(node: &Node, magic: [u8; 4]) -> Vec<Wire> {
    let items: Vec<Inventory> = node
        .mempool
        .sorted_by_fee_rate()
        .into_iter()
        .map(|entry| Inventory::Transaction(entry.tx.txid()))
        .collect();
    items
        .chunks(MAX_INV_ITEMS)
        .map(|chunk| to_wire(magic, &NetworkMessage::Inv(chunk.to_vec())))
        .collect()
}

fn raw(command: &str, payload: Vec<u8>) -> Wire {
    Wire::Unknown {
        command: command.to_string(),
        payload,
    }
}

/// Converts a message from `bitcoin::p2p` into the framing layer's form.
fn to_wire(magic: [u8; 4], msg: &NetworkMessage) -> Wire {
    match msg {
        NetworkMessage::Version(version) => Wire::Version(version.clone()),
        NetworkMessage::Verack => Wire::Verack,
        NetworkMessage::Ping(nonce) => Wire::Ping(*nonce),
        NetworkMessage::Pong(nonce) => Wire::Pong(*nonce),
        other => {
            let frame = serialize(&RawNetworkMessage::new(
                bitcoin::p2p::Magic::from_bytes(magic),
                other.clone(),
            ));
            let payload = frame[HEADER_SIZE..].to_vec();
            match decode_payload(other.cmd(), &payload) {
                Ok(wire) => wire,
                Err(_) => Wire::Unknown {
                    command: other.cmd().to_string(),
                    payload,
                },
            }
        }
    }
}

enum Inbound {
    Message(NetworkMessage),
    /// A command this node does not handle.
    Ignored,
    Malformed,
}

/// Parses a framed payload into `bitcoin::p2p` types.
fn from_wire(magic: [u8; 4], msg: Wire) -> Inbound {
    let (command, payload): (String, Vec<u8>) = match msg {
        Wire::Version(version) => return Inbound::Message(NetworkMessage::Version(version)),
        Wire::Verack => return Inbound::Message(NetworkMessage::Verack),
        Wire::Ping(nonce) => return Inbound::Message(NetworkMessage::Ping(nonce)),
        Wire::Pong(nonce) => return Inbound::Message(NetworkMessage::Pong(nonce)),
        Wire::Inv(payload) => ("inv".into(), payload),
        Wire::GetData(payload) => ("getdata".into(), payload),
        Wire::Headers(payload) => ("headers".into(), payload),
        Wire::GetHeaders(payload) => ("getheaders".into(), payload),
        Wire::Addr(payload) => ("addr".into(), payload),
        Wire::Unknown { command, payload } => (command, payload),
    };
    let Ok(header) = MessageHeader::new(magic, &command, &payload) else {
        return Inbound::Malformed;
    };
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(&payload);
    match deserialize::<RawNetworkMessage>(&frame) {
        Ok(raw) => match raw.into_payload() {
            NetworkMessage::Unknown { .. } => Inbound::Ignored,
            msg => Inbound::Message(msg),
        },
        Err(_) => Inbound::Malformed,
    }
}

fn to_bitcoin_header(header: &PrimHeader) -> Header {
    Header {
        version: Version::from_consensus(header.version),
        prev_blockhash: header.prev_blockhash,
        merkle_root: header.merkle_root,
        time: header.time,
        bits: CompactTarget::from_consensus(header.bits),
        nonce: header.nonce,
    }
}

fn to_primitive_header(header: &Header) -> PrimHeader {
    PrimHeader::new(
        header.version.to_consensus(),
        header.prev_blockhash,
        header.merkle_root,
        header.time,
        header.bits.to_consensus(),
        header.nonce,
    )
}

fn to_primitive_block(block: &bitcoin::Block) -> Option<PrimBlock> {
    deserialize(&serialize(block)).ok()
}

fn to_primitive_tx(tx: &bitcoin::Transaction) -> Option<PrimTx> {
    deserialize(&serialize(tx)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    use bitcoin::ScriptBuf;
    use btc_chain::chainstate::MemBlockStore;
    use btc_consensus::regtest_genesis_block;
    use btc_validation::coins::CoinsViewMemory;

    fn op_true() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    #[test]
    fn relay_delay_is_bounded_and_spread_across_the_window() {
        assert_eq!(relay_delay(Duration::ZERO), Duration::ZERO);
        let max = Duration::from_secs(2);
        let samples: Vec<Duration> = (0..4000).map(|_| relay_delay(max)).collect();
        assert!(samples.iter().all(|d| *d < max));
        let distinct: std::collections::HashSet<_> = samples.iter().collect();
        assert!(distinct.len() > 3990, "delays must not repeat");
        let mean = samples.iter().map(|d| d.as_secs_f64()).sum::<f64>() / samples.len() as f64;
        assert!((0.9..1.1).contains(&mean), "mean {mean} should be ~1s");
        // Each quarter of the window is hit.
        for q in 0..4 {
            let lo = Duration::from_millis(500 * q);
            assert!(samples.iter().any(|d| *d >= lo && *d < lo + Duration::from_millis(500)));
        }
    }

    fn magic() -> [u8; 4] {
        ChainParams::regtest().magic
    }

    fn regtest_node() -> Node {
        Node::new(
            ChainParams::regtest(),
            regtest_genesis_block(),
            Box::new(CoinsViewMemory::new()),
            Box::<MemBlockStore>::default(),
        )
        .unwrap()
    }

    fn block_at(node: &Node, height: u32) -> PrimBlock {
        let hash = node.chainstate.block_hash_at(height).unwrap();
        node.chainstate.get_block(&hash).unwrap()
    }

    fn decoded(wire: Wire) -> NetworkMessage {
        match from_wire(magic(), wire) {
            Inbound::Message(msg) => msg,
            _ => panic!("message did not decode"),
        }
    }

    fn config(connect: Vec<SocketAddr>) -> P2pConfig {
        P2pConfig {
            connect,
            user_agent: "/p2p-test:0.0.1/".to_string(),
            accept_local: true,
            ..P2pConfig::default()
        }
    }

    fn table() -> Arc<Mutex<AddrMan>> {
        let mut am = AddrMan::new();
        am.set_accept_local(true);
        Arc::new(Mutex::new(am))
    }

    fn local(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    async fn wait_for_tip(follower: &SharedNode, leader: &SharedNode) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let follower_tip = lock(follower).chainstate.tip_hash();
            let leader_tip = lock(leader).chainstate.tip_hash();
            if follower_tip == leader_tip {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "follower stuck at {follower_tip} while leader is at {leader_tip}"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    #[test]
    fn p2p_blocks_to_download_follows_headers_to_fork_point() {
        let mut src = regtest_node();
        src.generate(10, &op_true()).unwrap();
        let blocks: Vec<PrimBlock> = (1..=10).map(|h| block_at(&src, h)).collect();
        let headers: Vec<PrimHeader> = blocks.iter().map(|b| b.header).collect();
        let hashes: Vec<BlockHash> = blocks.iter().map(|b| b.block_hash()).collect();
        let tip = hashes[9];

        let mut dst = regtest_node();
        dst.submit_headers(&headers).unwrap();
        {
            let view = NodeChainView::new(&dst);
            assert_eq!(view.blocks_to_download(&tip, 100), hashes);
            assert_eq!(view.blocks_to_download(&tip, 4), hashes[..4].to_vec());
            assert!(view.blocks_to_download(&BlockHash::all_zeros(), 4).is_empty());
            assert_eq!(view.best_header_height(), 10);
            assert!(view.header_known(&tip));
            assert!(!view.have_block_data(&tip));
        }

        dst.submit_block(&blocks[0]).unwrap();
        dst.submit_block(&blocks[1]).unwrap();
        let view = NodeChainView::new(&dst);
        assert_eq!(view.blocks_to_download(&tip, 100), hashes[2..].to_vec());
        assert!(view.have_block_data(&hashes[1]));
    }

    #[test]
    fn p2p_getheaders_replies_from_locator_fork_point() {
        let mut node = regtest_node();
        node.generate(20, &op_true()).unwrap();
        let hash_at = |height| node.chainstate.block_hash_at(height).unwrap();
        let genesis = hash_at(0);
        let none = BlockHash::all_zeros();

        let headers = headers_reply(&node, &[hash_at(5), genesis], &none);
        assert_eq!(headers.len(), 15);
        assert_eq!(headers[0].prev_blockhash, hash_at(5));
        assert_eq!(headers[14].block_hash(), hash_at(20));

        let headers = headers_reply(&node, &[hash_at(5)], &hash_at(10));
        assert_eq!(headers.len(), 5);
        assert_eq!(headers[4].block_hash(), hash_at(10));

        let unknown = BlockHash::from_byte_array([7; 32]);
        let headers = headers_reply(&node, &[unknown], &none);
        assert_eq!(headers.len(), 20);
        assert_eq!(headers[0].prev_blockhash, genesis);
    }

    #[test]
    fn p2p_getheaders_caps_reply_at_2000() {
        let mut node = regtest_node();
        node.generate(2001, &op_true()).unwrap();
        let genesis = node.chainstate.block_hash_at(0).unwrap();
        let headers = headers_reply(&node, &[genesis], &BlockHash::all_zeros());
        assert_eq!(headers.len(), MAX_HEADERS_RESULTS);
        assert_eq!(headers[0].prev_blockhash, genesis);
    }

    #[test]
    fn p2p_getdata_serves_blocks_and_reports_missing() {
        let mut node = regtest_node();
        node.generate(3, &op_true()).unwrap();
        let wanted = node.chainstate.block_hash_at(2).unwrap();
        let missing = BlockHash::from_byte_array([9; 32]);
        let items = [Inventory::Block(wanted), Inventory::Block(missing)];

        let replies = data_replies(&node, magic(), &items);
        assert_eq!(replies.len(), 2);
        match decoded(replies[0].clone()) {
            NetworkMessage::Block(block) => assert_eq!(block.block_hash(), wanted),
            other => panic!("expected block, got {other:?}"),
        }
        assert_eq!(
            decoded(replies[1].clone()),
            NetworkMessage::NotFound(vec![Inventory::Block(missing)])
        );
    }

    #[test]
    fn p2p_messages_survive_wire_round_trip() {
        let mut node = regtest_node();
        node.generate(2, &op_true()).unwrap();
        let hash = node.chainstate.block_hash_at(1).unwrap();
        let headers = headers_reply(&node, &[hash], &BlockHash::all_zeros());

        let cases = [
            NetworkMessage::Headers(headers),
            NetworkMessage::Inv(vec![Inventory::Block(hash)]),
            NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![hash], BlockHash::all_zeros())),
            NetworkMessage::Ping(5),
            NetworkMessage::MemPool,
        ];
        for msg in cases {
            assert_eq!(decoded(to_wire(magic(), &msg)), msg);
        }

        let unknown = Wire::Unknown {
            command: "wtxidrelay-x".to_string(),
            payload: vec![0; 3],
        };
        assert!(matches!(from_wire(magic(), unknown), Inbound::Ignored));
        assert!(matches!(from_wire(magic(), Wire::Inv(vec![0xfd, 0x01])), Inbound::Malformed));
    }

    #[tokio::test]
    async fn p2p_nodes_sync_over_tcp() {
        let a = regtest_node().shared();
        lock(&a).generate(20, &op_true()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop_a = Arc::new(Notify::new());
        tokio::spawn(run_with_listener(a.clone(), Some(listener), config(Vec::new()), table(), stop_a.clone()));

        let b = regtest_node().shared();
        let stop_b = Arc::new(Notify::new());
        tokio::spawn(run_p2p(b.clone(), config(vec![addr]), stop_b.clone()));
        wait_for_tip(&b, &a).await;

        lock(&a).generate(3, &op_true()).unwrap();
        wait_for_tip(&b, &a).await;
        assert_eq!(lock(&b).chainstate.height(), 23);

        stop_a.notify_one();
        stop_b.notify_one();
    }

    #[tokio::test]
    async fn wallet_tx_relays_to_peer_mempool() {
        let dir = std::env::temp_dir().join(format!("p2p-txrelay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = regtest_node().shared();
        let to = {
            let mut node = lock(&a);
            node.attach_wallet(btc_wallet::Wallet::create(&dir.join("w.json")).unwrap()).unwrap();
            let script = node.wallet.as_mut().unwrap().new_script(btc_wallet::ScriptKind::P2wpkh).unwrap();
            node.generate(101, &script).unwrap();
            script
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop_a = Arc::new(Notify::new());
        tokio::spawn(run_with_listener(a.clone(), Some(listener), config(Vec::new()), table(), stop_a.clone()));
        let b = regtest_node().shared();
        let stop_b = Arc::new(Notify::new());
        tokio::spawn(run_p2p(b.clone(), config(vec![addr]), stop_b.clone()));
        wait_for_tip(&b, &a).await;

        let txid = lock(&a).wallet_send(to, 100_000_000, None, false).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !lock(&b).mempool.contains(&txid) {
            assert!(Instant::now() < deadline, "tx never reached peer mempool");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        stop_a.notify_one();
        stop_b.notify_one();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Core's token bucket: starts at 1, refills at 0.1 per second, caps at 1000,
    /// and a `getaddr` reply adds 1000.
    #[test]
    fn addr_rate_limit_admits_refill_and_burst() {
        let t0 = Instant::now();
        let mut tokens = 1.0;
        let mut last = t0;
        assert_eq!(admit_addresses(&mut tokens, &mut last, t0, 5), 1);
        assert_eq!(admit_addresses(&mut tokens, &mut last, t0, 5), 0);
        assert_eq!(admit_addresses(&mut tokens, &mut last, t0 + Duration::from_secs(10), 5), 1);
        tokens += GETADDR_TOKEN_GRANT;
        assert_eq!(admit_addresses(&mut tokens, &mut last, t0 + Duration::from_secs(10), 2000), 1000);
        let later = t0 + Duration::from_secs(100_000);
        assert_eq!(admit_addresses(&mut tokens, &mut last, later, 2000), 1000);
        assert_eq!(admit_addresses(&mut tokens, &mut last, later, 2000), 0);
    }

    #[test]
    fn dns_seed_entries_parse_without_lookup() {
        let seeds = vec![
            "127.0.0.1:18444".to_string(),
            "[::1]:18445".to_string(),
        ];
        let found = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(resolve_seeds(&seeds, 8333));
        assert_eq!(found, vec![local(18444), "[::1]:18445".parse().unwrap()]);
    }

    /// B and C both connect to A. C advertises its own address, and B must
    /// learn it through A's `addr` relay. C starts after B so that B is
    /// already connected when A relays C's address.
    #[tokio::test]
    async fn addr_relay_teaches_peers_a_new_address() {
        let a = regtest_node().shared();
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let stop_a = Arc::new(Notify::new());
        tokio::spawn(run_with_listener(a.clone(), Some(listener_a), config(Vec::new()), table(), stop_a.clone()));

        let b = regtest_node().shared();
        let addrman_b = table();
        let stop_b = Arc::new(Notify::new());
        tokio::spawn(run_with_listener(b.clone(), None, config(vec![addr_a]), addrman_b.clone(), stop_b.clone()));
        sleep(Duration::from_millis(500)).await;

        let c = regtest_node().shared();
        let listener_c = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_c = listener_c.local_addr().unwrap();
        let stop_c = Arc::new(Notify::new());
        let config_c = P2pConfig {
            advertise: Some(addr_c),
            listen: Some(addr_c),
            ..config(vec![addr_a])
        };
        tokio::spawn(run_with_listener(c.clone(), Some(listener_c), config_c, table(), stop_c.clone()));

        let learned = NetAddr::new(addr_c.ip(), addr_c.port(), 0, 0);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !lock_addrman(&addrman_b).contains(&learned) {
            assert!(Instant::now() < deadline, "B never learned C's address {addr_c}");
            sleep(Duration::from_millis(50)).await;
        }

        stop_a.notify_one();
        stop_b.notify_one();
        stop_c.notify_one();
    }

    /// With no `-connect` list, the outbound loop dials an address from the table
    /// and syncs from it.
    #[tokio::test]
    async fn outbound_loop_dials_address_from_table() {
        let a = regtest_node().shared();
        lock(&a).generate(20, &op_true()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener.local_addr().unwrap();
        let stop_a = Arc::new(Notify::new());
        tokio::spawn(run_with_listener(a.clone(), Some(listener), config(Vec::new()), table(), stop_a.clone()));

        let known = table();
        let source = NetAddr::new(addr_a.ip(), addr_a.port(), 0, unix_now());
        lock_addrman(&known).add(source, source);

        let e = regtest_node().shared();
        let stop_e = Arc::new(Notify::new());
        let config_e = P2pConfig {
            outbound_interval: Duration::from_millis(100),
            ..config(Vec::new())
        };
        tokio::spawn(run_with_listener(e.clone(), None, config_e, known, stop_e.clone()));
        wait_for_tip(&e, &a).await;

        stop_a.notify_one();
        stop_e.notify_one();
    }
}
