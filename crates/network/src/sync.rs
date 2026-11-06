//! Headers-first block sync. Pure port of the block-sync parts of
//! `src/net_processing.cpp` (`PeerManagerImpl`): header download with the
//! 2000-header continuation, unconnecting-header accounting, inv-driven
//! `getheaders`, transaction inventory filtering, and block download with a
//! per-peer in-flight cap and a moving window.
//!
//! Nothing here performs IO. The caller feeds messages and clock ticks in,
//! reads the chain through [`ChainView`], and carries out the returned
//! [`SyncAction`]s.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::{Block, BlockHash, Transaction};

/// Identifies a connected peer.
pub type PeerId = u64;

/// `MAX_HEADERS_RESULTS`: a full `headers` batch means more headers may follow.
pub const MAX_HEADERS_RESULTS: usize = 2000;
/// `MAX_NUM_UNCONNECTING_HEADERS_MSGS`: consecutive unusable `headers` messages before disconnect.
pub const MAX_NUM_UNCONNECTING_HEADERS_MSGS: u32 = 10;
/// `MAX_BLOCKS_IN_TRANSIT_PER_PEER`.
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;
/// `BLOCK_DOWNLOAD_WINDOW`: blocks requested from the first one still missing.
pub const BLOCK_DOWNLOAD_WINDOW: usize = 1024;
/// Simplified stall rule: any request older than this drops the peer. Core uses
/// an adaptive 2..64 s window-head timeout; a fixed 2 s is too tight here.
pub const BLOCK_STALLING_TIMEOUT_SECS: u64 = 60;
/// Bound on remembered transaction inventories, so repeated announcements are not re-fetched.
pub const MAX_RECENT_TX_INV: usize = 10_000;

/// The chain state that sync decisions depend on.
pub trait ChainView {
    /// Block locator starting at our best header, for `getheaders`.
    fn locator(&self) -> Vec<BlockHash>;
    /// Whether the header is known.
    fn header_known(&self, hash: &BlockHash) -> bool;
    /// Whether the full block data is stored.
    fn have_block_data(&self, hash: &BlockHash) -> bool;
    fn best_header_height(&self) -> u32;
    /// Hashes on the path to `after_tip` whose block data we lack, in height order, at most `max`.
    fn blocks_to_download(&self, after_tip: &BlockHash, max: usize) -> Vec<BlockHash>;
}

/// Work for the caller to carry out.
#[derive(Clone, Debug, PartialEq)]
pub enum SyncAction {
    /// Send a message to a peer.
    Send(PeerId, NetworkMessage),
    /// Validate and store headers, in order. The first one connects to a known header.
    AcceptHeaders(PeerId, Vec<Header>),
    AcceptBlock(PeerId, Block),
    AcceptTx(PeerId, Transaction),
    /// Drop the peer. The manager has already forgotten it, which requeues its blocks.
    Disconnect(PeerId, &'static str),
}

#[derive(Default)]
struct PeerState {
    start_height: i32,
    best_known: Option<BlockHash>,
    unconnecting: u32,
}

struct InFlight {
    peer: PeerId,
    requested_at: u64,
}

#[derive(Default)]
struct RecentSet {
    set: HashSet<Inventory>,
    order: VecDeque<Inventory>,
}

impl RecentSet {
    /// Returns `true` if `item` was not already present.
    fn insert(&mut self, item: Inventory) -> bool {
        if !self.set.insert(item) {
            return false;
        }
        self.order.push_back(item);
        if self.order.len() > MAX_RECENT_TX_INV {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        true
    }
}

/// Header and block download state for all connected peers.
#[derive(Default)]
pub struct SyncManager {
    peers: BTreeMap<PeerId, PeerState>,
    sync_peer: Option<PeerId>,
    in_flight: HashMap<BlockHash, InFlight>,
    recent_tx: RecentSet,
}

impl SyncManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// The peer currently used for header download, if any.
    pub fn sync_peer(&self) -> Option<PeerId> {
        self.sync_peer
    }

    pub fn peer_connected(&mut self, id: PeerId, start_height: i32) {
        self.forget(id);
        self.peers.insert(
            id,
            PeerState {
                start_height,
                ..Default::default()
            },
        );
    }

    /// Forgets the peer. Its in-flight blocks become requestable again.
    pub fn peer_disconnected(&mut self, id: PeerId) {
        self.forget(id);
    }

    /// Clears the in-flight entry for `hash`, whichever peer it was requested from.
    pub fn block_received(&mut self, hash: &BlockHash) {
        self.in_flight.remove(hash);
    }

    /// Handles one message from `id`. Messages from unknown peers are ignored.
    ///
    /// `getheaders` and `getdata` are not served here; the node answers them.
    pub fn on_message(
        &mut self,
        chain: &dyn ChainView,
        id: PeerId,
        msg: NetworkMessage,
    ) -> Vec<SyncAction> {
        if !self.peers.contains_key(&id) {
            return Vec::new();
        }
        match msg {
            NetworkMessage::Headers(headers) => self.on_headers(chain, id, headers),
            NetworkMessage::Inv(items) => self.on_inv(chain, id, &items),
            NetworkMessage::Block(block) => {
                self.block_received(&block.block_hash());
                vec![SyncAction::AcceptBlock(id, block)]
            }
            NetworkMessage::Tx(tx) => {
                self.recent_tx
                    .insert(Inventory::Transaction(tx.compute_txid()));
                self.recent_tx.insert(Inventory::WTx(tx.compute_wtxid()));
                vec![SyncAction::AcceptTx(id, tx)]
            }
            NetworkMessage::Ping(nonce) => vec![SyncAction::Send(id, NetworkMessage::Pong(nonce))],
            _ => Vec::new(),
        }
    }

    /// Periodic work: stall detection, sync peer selection, and block requests.
    pub fn tick(&mut self, chain: &dyn ChainView, now_secs: u64) -> Vec<SyncAction> {
        let mut out = Vec::new();

        let mut oldest: BTreeMap<PeerId, u64> = BTreeMap::new();
        for flight in self.in_flight.values() {
            let entry = oldest.entry(flight.peer).or_insert(flight.requested_at);
            *entry = (*entry).min(flight.requested_at);
        }
        let stalled: Vec<PeerId> = oldest
            .into_iter()
            .filter(|&(_, since)| now_secs.saturating_sub(since) > BLOCK_STALLING_TIMEOUT_SECS)
            .map(|(id, _)| id)
            .collect();
        for id in stalled {
            out.push(self.disconnect(id, "block download stalled"));
        }

        if self.sync_peer.is_none() {
            let best = i64::from(chain.best_header_height());
            let chosen = self
                .peers
                .iter()
                .filter(|(_, p)| i64::from(p.start_height) > best)
                .max_by_key(|(id, p)| (p.start_height, Reverse(**id)))
                .map(|(id, _)| *id);
            if let Some(id) = chosen {
                self.sync_peer = Some(id);
                out.push(SyncAction::Send(
                    id,
                    getheaders(chain.locator(), BlockHash::all_zeros()),
                ));
            }
        }

        let ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for id in ids {
            let Some(best) = self.peers.get(&id).and_then(|p| p.best_known) else {
                continue;
            };
            let busy = self.in_flight.values().filter(|f| f.peer == id).count();
            let budget = MAX_BLOCKS_IN_TRANSIT_PER_PEER.saturating_sub(busy);
            if budget == 0 {
                continue;
            }
            let picks: Vec<BlockHash> = chain
                .blocks_to_download(&best, BLOCK_DOWNLOAD_WINDOW)
                .into_iter()
                .filter(|h| !self.in_flight.contains_key(h) && !chain.have_block_data(h))
                .take(budget)
                .collect();
            if picks.is_empty() {
                continue;
            }
            for hash in &picks {
                self.in_flight.insert(
                    *hash,
                    InFlight {
                        peer: id,
                        requested_at: now_secs,
                    },
                );
            }
            let items = picks.into_iter().map(Inventory::Block).collect();
            out.push(SyncAction::Send(id, NetworkMessage::GetData(items)));
        }
        out
    }

    fn on_headers(
        &mut self,
        chain: &dyn ChainView,
        id: PeerId,
        headers: Vec<Header>,
    ) -> Vec<SyncAction> {
        if headers.is_empty() {
            return Vec::new();
        }
        let Some(peer) = self.peers.get_mut(&id) else {
            return Vec::new();
        };
        let last = headers[headers.len() - 1].block_hash();
        let continuous = headers
            .windows(2)
            .all(|w| w[1].prev_blockhash == w[0].block_hash());
        let connects = continuous && chain.header_known(&headers[0].prev_blockhash);
        if !connects {
            peer.unconnecting += 1;
            let strikes = peer.unconnecting;
            if strikes >= MAX_NUM_UNCONNECTING_HEADERS_MSGS {
                return vec![self.disconnect(id, "too many unconnecting headers")];
            }
            return vec![SyncAction::Send(
                id,
                getheaders(chain.locator(), BlockHash::all_zeros()),
            )];
        }

        peer.unconnecting = 0;
        peer.best_known = Some(last);
        let full = headers.len() == MAX_HEADERS_RESULTS;
        let mut out = vec![SyncAction::AcceptHeaders(id, headers)];
        if full {
            out.push(SyncAction::Send(
                id,
                getheaders(vec![last], BlockHash::all_zeros()),
            ));
        }
        out
    }

    fn on_inv(
        &mut self,
        chain: &dyn ChainView,
        id: PeerId,
        items: &[Inventory],
    ) -> Vec<SyncAction> {
        let mut out = Vec::new();
        let mut want_tx = Vec::new();
        let mut asked_headers = false;
        for item in items {
            match *item {
                Inventory::Block(hash) => {
                    if chain.header_known(&hash) {
                        if let Some(peer) = self.peers.get_mut(&id) {
                            if peer.best_known.is_none() {
                                peer.best_known = Some(hash);
                            }
                        }
                    } else if !asked_headers {
                        asked_headers = true;
                        out.push(SyncAction::Send(id, getheaders(chain.locator(), hash)));
                    }
                }
                Inventory::Transaction(_) | Inventory::WTx(_) if self.recent_tx.insert(*item) => {
                    want_tx.push(*item);
                }
                _ => {}
            }
        }
        if !want_tx.is_empty() {
            out.push(SyncAction::Send(id, NetworkMessage::GetData(want_tx)));
        }
        out
    }

    fn disconnect(&mut self, id: PeerId, reason: &'static str) -> SyncAction {
        self.forget(id);
        SyncAction::Disconnect(id, reason)
    }

    fn forget(&mut self, id: PeerId) {
        self.peers.remove(&id);
        self.in_flight.retain(|_, f| f.peer != id);
        if self.sync_peer == Some(id) {
            self.sync_peer = None;
        }
    }
}

fn getheaders(locator: Vec<BlockHash>, stop: BlockHash) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, stop))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::{CompactTarget, TxMerkleNode, Txid};

    struct FakeChain {
        locator: Vec<BlockHash>,
        known: HashSet<BlockHash>,
        have: HashSet<BlockHash>,
        best_height: u32,
        path: Vec<BlockHash>,
    }

    impl FakeChain {
        fn new() -> Self {
            Self {
                locator: vec![hash(1)],
                known: HashSet::from([hash(1)]),
                have: HashSet::new(),
                best_height: 0,
                path: Vec::new(),
            }
        }

        fn extend(&mut self, headers: &[Header]) {
            for h in headers {
                self.known.insert(h.block_hash());
                self.path.push(h.block_hash());
            }
        }
    }

    impl ChainView for FakeChain {
        fn locator(&self) -> Vec<BlockHash> {
            self.locator.clone()
        }
        fn header_known(&self, hash: &BlockHash) -> bool {
            self.known.contains(hash)
        }
        fn have_block_data(&self, hash: &BlockHash) -> bool {
            self.have.contains(hash)
        }
        fn best_header_height(&self) -> u32 {
            self.best_height
        }
        fn blocks_to_download(&self, _after_tip: &BlockHash, max: usize) -> Vec<BlockHash> {
            self.path
                .iter()
                .filter(|h| !self.have.contains(*h))
                .take(max)
                .copied()
                .collect()
        }
    }

    fn hash(b: u8) -> BlockHash {
        BlockHash::from_byte_array([b; 32])
    }

    fn chain_of(prev: BlockHash, n: usize, salt: u32) -> Vec<Header> {
        let mut out = Vec::with_capacity(n);
        let mut prev = prev;
        for i in 0..n {
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time: salt + i as u32,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            };
            prev = header.block_hash();
            out.push(header);
        }
        out
    }

    fn getdata_blocks(out: &[SyncAction], peer: PeerId) -> Vec<BlockHash> {
        out.iter()
            .filter_map(|a| match a {
                SyncAction::Send(p, NetworkMessage::GetData(items)) if *p == peer => Some(items),
                _ => None,
            })
            .flatten()
            .filter_map(|item| match item {
                Inventory::Block(h) => Some(*h),
                _ => None,
            })
            .collect()
    }

    fn block_inv(hash: BlockHash) -> NetworkMessage {
        NetworkMessage::Inv(vec![Inventory::Block(hash)])
    }

    #[test]
    fn initial_tick_sends_getheaders_to_one_peer() {
        let chain = FakeChain::new();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 100);
        sync.peer_connected(2, 50);

        let out = sync.tick(&chain, 0);
        match out.as_slice() {
            [SyncAction::Send(1, NetworkMessage::GetHeaders(m))] => {
                assert_eq!(m.locator_hashes, vec![hash(1)]);
                assert_eq!(m.stop_hash, BlockHash::all_zeros());
            }
            other => panic!("unexpected actions: {other:?}"),
        }
        assert_eq!(sync.sync_peer(), Some(1));
        assert!(sync.tick(&chain, 0).is_empty());
    }

    #[test]
    fn full_headers_batch_requests_continuation() {
        let chain = FakeChain::new();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 5000);
        sync.peer_connected(2, 5000);

        let headers = chain_of(hash(1), MAX_HEADERS_RESULTS, 1000);
        let last = headers[headers.len() - 1].block_hash();
        let out = sync.on_message(&chain, 1, NetworkMessage::Headers(headers.clone()));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], SyncAction::AcceptHeaders(1, headers));
        match &out[1] {
            SyncAction::Send(1, NetworkMessage::GetHeaders(m)) => {
                assert_eq!(m.locator_hashes, vec![last]);
                assert_eq!(m.stop_hash, BlockHash::all_zeros());
            }
            other => panic!("unexpected action: {other:?}"),
        }

        let short = chain_of(hash(1), 5, 2000);
        let out = sync.on_message(&chain, 2, NetworkMessage::Headers(short.clone()));
        assert_eq!(out, vec![SyncAction::AcceptHeaders(2, short)]);
    }

    #[test]
    fn unconnecting_headers_disconnect_after_limit() {
        let chain = FakeChain::new();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 100);

        let orphan = chain_of(hash(9), 3, 0);
        for _ in 0..MAX_NUM_UNCONNECTING_HEADERS_MSGS - 1 {
            let out = sync.on_message(&chain, 1, NetworkMessage::Headers(orphan.clone()));
            assert!(matches!(
                out.as_slice(),
                [SyncAction::Send(1, NetworkMessage::GetHeaders(_))]
            ));
        }
        let out = sync.on_message(&chain, 1, NetworkMessage::Headers(orphan));
        assert!(matches!(out.as_slice(), [SyncAction::Disconnect(1, _)]));
        assert_eq!(sync.sync_peer(), None);
    }

    #[test]
    fn non_continuous_headers_count_and_a_good_batch_resets() {
        let chain = FakeChain::new();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 100);

        let mut broken = chain_of(hash(1), 2, 0);
        broken[1].prev_blockhash = hash(7);
        for _ in 0..9 {
            let out = sync.on_message(&chain, 1, NetworkMessage::Headers(broken.clone()));
            assert!(matches!(out.as_slice(), [SyncAction::Send(1, _)]));
        }
        let good = chain_of(hash(1), 1, 5);
        let out = sync.on_message(&chain, 1, NetworkMessage::Headers(good));
        assert!(matches!(out.as_slice(), [SyncAction::AcceptHeaders(1, _)]));
        for _ in 0..9 {
            sync.on_message(&chain, 1, NetworkMessage::Headers(broken.clone()));
        }
        let out = sync.on_message(&chain, 1, NetworkMessage::Headers(broken));
        assert!(matches!(out.as_slice(), [SyncAction::Disconnect(1, _)]));
    }

    #[test]
    fn blocks_are_scheduled_up_to_16_per_peer() {
        let mut chain = FakeChain::new();
        let headers = chain_of(hash(1), 40, 0);
        chain.extend(&headers);
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 40);

        let out = sync.on_message(&chain, 1, block_inv(headers[39].block_hash()));
        assert!(out.is_empty());

        let out = sync.tick(&chain, 0);
        assert_eq!(getdata_blocks(&out, 1), chain.path[..16].to_vec());
        assert!(getdata_blocks(&sync.tick(&chain, 0), 1).is_empty());
    }

    #[test]
    fn disconnect_requeues_blocks_to_another_peer() {
        let mut chain = FakeChain::new();
        let headers = chain_of(hash(1), 20, 0);
        chain.extend(&headers);
        let tip = headers[19].block_hash();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 20);
        sync.peer_connected(2, 20);
        sync.on_message(&chain, 1, block_inv(tip));
        sync.on_message(&chain, 2, block_inv(tip));

        let out = sync.tick(&chain, 0);
        assert_eq!(getdata_blocks(&out, 1), chain.path[..16].to_vec());
        assert_eq!(getdata_blocks(&out, 2), chain.path[16..20].to_vec());

        sync.peer_disconnected(1);
        let out = sync.tick(&chain, 0);
        assert_eq!(getdata_blocks(&out, 2), chain.path[..12].to_vec());
    }

    #[test]
    fn stalling_peer_is_disconnected_and_its_blocks_reassigned() {
        let mut chain = FakeChain::new();
        let headers = chain_of(hash(1), 20, 0);
        chain.extend(&headers);
        let tip = headers[19].block_hash();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 20);
        sync.on_message(&chain, 1, block_inv(tip));
        sync.tick(&chain, 0);

        sync.peer_connected(2, 20);
        sync.on_message(&chain, 2, block_inv(tip));
        let out = sync.tick(&chain, BLOCK_STALLING_TIMEOUT_SECS);
        assert!(!out.iter().any(|a| matches!(a, SyncAction::Disconnect(..))));
        assert_eq!(getdata_blocks(&out, 2), chain.path[16..20].to_vec());

        let out = sync.tick(&chain, BLOCK_STALLING_TIMEOUT_SECS + 1);
        assert!(out
            .iter()
            .any(|a| matches!(a, SyncAction::Disconnect(1, _))));
        assert_eq!(getdata_blocks(&out, 2), chain.path[..12].to_vec());
    }

    #[test]
    fn received_block_is_accepted_and_leaves_flight() {
        let mut chain = FakeChain::new();
        let headers = chain_of(hash(1), 3, 0);
        chain.extend(&headers);
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 3);
        sync.on_message(&chain, 1, block_inv(headers[2].block_hash()));
        sync.tick(&chain, 0);
        assert_eq!(sync.in_flight.len(), 3);

        let block = Block {
            header: headers[0],
            txdata: Vec::new(),
        };
        let out = sync.on_message(&chain, 1, NetworkMessage::Block(block.clone()));
        assert_eq!(out, vec![SyncAction::AcceptBlock(1, block)]);
        assert_eq!(sync.in_flight.len(), 2);
    }

    #[test]
    fn inv_for_unknown_block_requests_headers() {
        let chain = FakeChain::new();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 100);

        let unknown = hash(5);
        let out = sync.on_message(&chain, 1, block_inv(unknown));
        match out.as_slice() {
            [SyncAction::Send(1, NetworkMessage::GetHeaders(m))] => {
                assert_eq!(m.locator_hashes, vec![hash(1)]);
                assert_eq!(m.stop_hash, unknown);
            }
            other => panic!("unexpected actions: {other:?}"),
        }
    }

    #[test]
    fn tx_inv_is_requested_once_and_tx_is_accepted() {
        let chain = FakeChain::new();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 0);
        sync.peer_connected(2, 0);

        let txid = Txid::from_byte_array([3; 32]);
        let items = vec![Inventory::Transaction(txid)];
        let out = sync.on_message(&chain, 1, NetworkMessage::Inv(items.clone()));
        assert_eq!(
            out,
            vec![SyncAction::Send(1, NetworkMessage::GetData(items))]
        );
        assert!(sync
            .on_message(
                &chain,
                2,
                NetworkMessage::Inv(vec![Inventory::Transaction(txid)])
            )
            .is_empty());

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let fetched = tx.clone();
        let out = sync.on_message(&chain, 1, NetworkMessage::Tx(tx));
        assert_eq!(out, vec![SyncAction::AcceptTx(1, fetched)]);
    }

    #[test]
    fn ping_is_answered_and_server_messages_are_not() {
        let chain = FakeChain::new();
        let mut sync = SyncManager::new();
        sync.peer_connected(1, 0);

        let out = sync.on_message(&chain, 1, NetworkMessage::Ping(42));
        assert_eq!(out, vec![SyncAction::Send(1, NetworkMessage::Pong(42))]);
        assert!(sync
            .on_message(&chain, 1, NetworkMessage::Pong(7))
            .is_empty());
        let getheaders = getheaders(vec![hash(1)], BlockHash::all_zeros());
        assert!(sync.on_message(&chain, 1, getheaders).is_empty());
        assert!(sync
            .on_message(&chain, 9, NetworkMessage::Ping(1))
            .is_empty());
    }
}
