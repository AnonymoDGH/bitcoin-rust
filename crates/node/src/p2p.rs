//! P2P connection manager. Port of the network-facing parts of `src/net.cpp`
//! and `src/net_processing.cpp`: listeners, outbound dialing, one task per
//! peer, and one manager task that owns `SyncManager` and applies its actions
//! to the node. The node lock is held only while a single call runs.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bitcoin::block::{Header, Version};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::CompactTarget;
use btc_chain::{BlockStatus, BlockTree, IndexId, ValidationError};
use btc_consensus::ChainParams;
use btc_network::message::{decode_payload, MessageHeader, NetworkMessage as Wire, HEADER_SIZE};
use btc_network::peer::{LocalVersion, Peer};
use btc_network::sync::{ChainView, PeerId, SyncAction, SyncManager, MAX_HEADERS_RESULTS};
use btc_primitives::{Block as PrimBlock, BlockHash, BlockHeader as PrimHeader, Tx as PrimTx, Txid};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{interval, sleep};

use crate::node::{Node, SharedNode};

const TICK_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_secs(10);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const PEER_QUEUE: usize = 1024;
const EVENT_QUEUE: usize = 4096;
/// `MAX_INV_SZ`.
const MAX_INV_ITEMS: usize = 50_000;
/// Core's default `-maxconnections` (125) minus the eight outbound slots.
const MAX_INBOUND_PEERS: usize = 117;

#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub listen: Option<SocketAddr>,
    pub connect: Vec<SocketAddr>,
    pub max_outbound: usize,
    pub user_agent: String,
}

/// Serves the P2P network until `shutdown` is notified.
pub async fn run_p2p(node: SharedNode, config: P2pConfig, shutdown: Arc<Notify>) -> io::Result<()> {
    let listener = match config.listen {
        Some(addr) => Some(TcpListener::bind(addr).await?),
        None => None,
    };
    run_with_listener(node, listener, config, shutdown).await;
    Ok(())
}

async fn run_with_listener(
    node: SharedNode,
    listener: Option<TcpListener>,
    config: P2pConfig,
    shutdown: Arc<Notify>,
) {
    let params = lock(&node).params.clone();
    let magic = params.magic;
    let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
    let ctx = Arc::new(Ctx {
        node: node.clone(),
        params,
        user_agent: config.user_agent,
        events: events_tx,
        next_id: AtomicU64::new(1),
        outbound: Arc::new(Semaphore::new(config.max_outbound)),
        inbound: Arc::new(Semaphore::new(MAX_INBOUND_PEERS)),
    });

    let mut tasks = JoinSet::new();
    if let Some(listener) = listener {
        tasks.spawn(accept_loop(listener, ctx.clone()));
    }
    for addr in config.connect {
        tasks.spawn(dial_loop(addr, ctx.clone()));
    }
    Manager::new(node, magic).run(events_rx, shutdown).await;
    // Dropping `tasks` aborts the listener and the dialers.
}

/// Shared handles for connection tasks.
struct Ctx {
    node: SharedNode,
    params: ChainParams,
    user_agent: String,
    events: mpsc::Sender<Event>,
    next_id: AtomicU64,
    outbound: Arc<Semaphore>,
    inbound: Arc<Semaphore>,
}

impl Ctx {
    fn height(&self) -> i32 {
        lock(&self.node).chainstate.height() as i32
    }
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
            serve_connection(peer, &ctx).await;
            drop(permit);
        });
    }
}

async fn dial_loop(addr: SocketAddr, ctx: Arc<Ctx>) {
    loop {
        if let Ok(permit) = ctx.outbound.clone().acquire_owned().await {
            if let Ok(peer) = Peer::connect(addr, &ctx.params).await {
                serve_connection(peer, &ctx).await;
            }
            drop(permit);
        }
        sleep(RETRY_INTERVAL).await;
    }
}

/// Handshake, then forward messages both ways until the connection ends.
async fn serve_connection(mut peer: Peer<TcpStream>, ctx: &Ctx) {
    let local = LocalVersion {
        user_agent: ctx.user_agent.clone(),
        start_height: ctx.height(),
        ..LocalVersion::default()
    };
    let Ok(info) = peer.handshake(&local).await else {
        return;
    };

    let id = ctx.next_id.fetch_add(1, Ordering::Relaxed);
    let (out_tx, out_rx) = mpsc::channel(PEER_QUEUE);
    let (events_tx, mut events_rx) = mpsc::channel::<Wire>(PEER_QUEUE);
    let connected = Event::Connected {
        id,
        start_height: info.start_height,
        outbound: out_tx,
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
    },
    Message {
        id: PeerId,
        msg: Wire,
    },
    Closed {
        id: PeerId,
    },
}

/// Owns the sync state and every peer's outbound queue.
struct Manager {
    node: SharedNode,
    magic: [u8; 4],
    sync: SyncManager,
    peers: HashMap<PeerId, mpsc::Sender<Wire>>,
    started: Instant,
}

impl Manager {
    fn new(node: SharedNode, magic: [u8; 4]) -> Self {
        Self {
            node,
            magic,
            sync: SyncManager::new(),
            peers: HashMap::new(),
            started: Instant::now(),
        }
    }

    async fn run(mut self, mut events: mpsc::Receiver<Event>, shutdown: Arc<Notify>) {
        let stop = shutdown.notified();
        tokio::pin!(stop);
        let mut ticker = interval(TICK_INTERVAL);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                _ = ticker.tick() => self.tick(),
                event = events.recv() => match event {
                    Some(event) => self.on_event(event),
                    None => break,
                },
            }
        }
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Connected {
                id,
                start_height,
                outbound,
            } => {
                self.peers.insert(id, outbound);
                self.sync.peer_connected(id, start_height);
            }
            Event::Message { id, msg } => self.on_message(id, msg),
            Event::Closed { id } => self.drop_peer(id),
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
        for message in messages {
            for outbound in self.peers.values() {
                let _ = outbound.try_send(message.clone());
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
        if let Some(outbound) = self.peers.get(&id) {
            let _ = outbound.try_send(msg);
        }
    }

    fn drop_peer(&mut self, id: PeerId) {
        self.sync.peer_disconnected(id);
        self.peers.remove(&id);
    }
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
            listen: None,
            connect,
            max_outbound: 8,
            user_agent: "/p2p-test:0.0.1/".to_string(),
        }
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
        tokio::spawn(run_with_listener(a.clone(), Some(listener), config(Vec::new()), stop_a.clone()));

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
}
