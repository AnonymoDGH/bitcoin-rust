//! Chain manager. Port of `ChainstateManager::ProcessNewBlock(Headers)`,
//! `AcceptBlockHeader`, `AcceptBlock`, `ActivateBestChain`,
//! `ConnectTip`/`DisconnectTip`, `InvalidateBlock` (validation.cpp).

use std::collections::HashMap;

use btc_consensus::ChainParams;
use btc_primitives::{Block, BlockHash, BlockHeader, Tx};
use btc_validation::block_verify::{check_block, check_block_header};
use btc_validation::coins::{CoinsView, CoinsViewCache, CoinsViewWrite};
use btc_validation::undo::BlockUndo;

use crate::connect::{connect_block, disconnect_block, ConnectOptions, DisconnectResult};
use crate::contextual::{contextual_check_block, contextual_check_block_header};
use crate::{ActiveChain, BlockStatus, BlockTree, IndexId, ValidationError};

/// Block + undo storage. `MemBlockStore` keeps everything in RAM; the node
/// plugs in the flat-file store.
pub trait BlockStore: Send {
    fn put_block(&mut self, hash: &BlockHash, block: &Block);
    fn get_block(&self, hash: &BlockHash) -> Option<Block>;
    fn put_undo(&mut self, hash: &BlockHash, undo: &BlockUndo);
    fn get_undo(&self, hash: &BlockHash) -> Option<BlockUndo>;
    /// Every stored block as (hash, prev hash, has undo), any order. Used to
    /// rebuild the block index on startup (`LoadBlockIndex`).
    fn known_blocks(&self) -> Vec<(BlockHash, BlockHash, bool)> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct MemBlockStore {
    pub blocks: HashMap<BlockHash, Block>,
    pub undos: HashMap<BlockHash, BlockUndo>,
}

impl BlockStore for MemBlockStore {
    fn put_block(&mut self, hash: &BlockHash, block: &Block) {
        self.blocks.insert(*hash, block.clone());
    }
    fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        self.blocks.get(hash).cloned()
    }
    fn put_undo(&mut self, hash: &BlockHash, undo: &BlockUndo) {
        self.undos.insert(*hash, undo.clone());
    }
    fn get_undo(&self, hash: &BlockHash) -> Option<BlockUndo> {
        self.undos.get(hash).cloned()
    }
    fn known_blocks(&self) -> Vec<(BlockHash, BlockHash, bool)> {
        self.blocks
            .iter()
            .map(|(h, b)| (*h, b.header.prev_blockhash, self.undos.contains_key(h)))
            .collect()
    }
}

/// Tip changes, for mempool / wallet / RPC listeners (`CValidationInterface`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainEvent {
    BlockConnected { hash: BlockHash, height: u32 },
    /// Transactions of the disconnected block (to resurrect into the mempool).
    BlockDisconnected { hash: BlockHash, height: u32, txs: Vec<Tx> },
}

pub struct Chainstate {
    pub params: ChainParams,
    pub tree: BlockTree,
    pub chain: ActiveChain,
    pub coins: Box<dyn CoinsViewWrite + Send>,
    pub store: Box<dyn BlockStore>,
    pub connect_opts: ConnectOptions,
    /// `m_best_header`: most-work header accepted so far.
    best_header: IndexId,
    events: Vec<ChainEvent>,
    /// Reason each block was marked `FAILED_VALID` (blocks failed by hand or
    /// as a side effect of a failed descendant are absent).
    invalid_reasons: HashMap<IndexId, ValidationError>,
}

impl Chainstate {
    /// Loads `genesis` (must hash to `params.genesis_hash`): header indexed,
    /// block stored, tip = genesis. Genesis outputs are NOT added to the UTXO
    /// set (Core behaviour).
    pub fn new(
        params: ChainParams,
        genesis: Block,
        coins: Box<dyn CoinsViewWrite + Send>,
        mut store: Box<dyn BlockStore>,
    ) -> Result<Self, ValidationError> {
        let hash = genesis.block_hash();
        if hash != params.genesis_hash {
            return Err(ValidationError::Other("bad-genesis"));
        }
        let mut tree = BlockTree::new();
        let id = tree
            .insert_header(genesis.header)
            .map_err(|_| ValidationError::Other("bad-genesis"))?;
        let entry = tree.get_mut(id);
        entry.status.raise_validity(BlockStatus::VALID_SCRIPTS);
        entry.status.0 |= BlockStatus::HAVE_DATA;
        entry.n_tx = genesis.txdata.len() as u32;
        store.put_block(&hash, &genesis);

        let mut chain = ActiveChain::new();
        chain.set_tip(&tree, Some(id));
        let mut state = Self {
            params,
            tree,
            chain,
            coins,
            store,
            connect_opts: ConnectOptions::default(),
            best_header: id,
            events: Vec::new(),
            invalid_reasons: HashMap::new(),
        };
        state.load_block_index()?;
        Ok(state)
    }

    /// `LoadBlockIndex` + `LoadChainTip`: re-index stored blocks, restore the
    /// tip from the coins view's best block, then connect anything beyond it.
    fn load_block_index(&mut self) -> Result<(), ValidationError> {
        let known = self.store.known_blocks();
        if known.len() <= 1 {
            return Ok(());
        }
        let mut children: HashMap<BlockHash, Vec<(BlockHash, bool)>> = HashMap::new();
        for (hash, prev, has_undo) in known {
            children.entry(prev).or_default().push((hash, has_undo));
        }
        let mut queue = vec![self.params.genesis_hash];
        while let Some(parent) = queue.pop() {
            for (hash, has_undo) in children.remove(&parent).unwrap_or_default() {
                let Some(block) = self.store.get_block(&hash) else { continue };
                let Ok(id) = self.tree.insert_header(block.header) else { continue };
                let entry = self.tree.get_mut(id);
                entry.status.0 |= BlockStatus::HAVE_DATA;
                entry.status.raise_validity(BlockStatus::VALID_TRANSACTIONS);
                if has_undo {
                    entry.status.0 |= BlockStatus::HAVE_UNDO;
                }
                entry.n_tx = block.txdata.len() as u32;
                if self.tree.get(id).chain_work > self.tree.get(self.best_header).chain_work {
                    self.best_header = id;
                }
                queue.push(hash);
            }
        }
        if let Some(tip) = self.coins.best_block().and_then(|h| self.tree.lookup(&h)) {
            self.chain.set_tip(&self.tree, Some(tip));
            let mut cursor = Some(tip);
            while let Some(id) = cursor {
                self.tree.get_mut(id).status.raise_validity(BlockStatus::VALID_SCRIPTS);
                cursor = self.tree.get(id).prev;
            }
        }
        self.activate_best_chain()
    }
    pub fn tip(&self) -> IndexId {
        self.chain.tip().expect("the active chain always holds genesis")
    }
    pub fn tip_hash(&self) -> BlockHash {
        self.tree.get(self.tip()).hash
    }
    pub fn height(&self) -> u32 {
        self.tree.get(self.tip()).height
    }
    /// Most-work valid header known (`m_best_header`).
    pub fn best_header(&self) -> IndexId {
        self.best_header
    }
    pub fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        self.store.get_block(hash)
    }
    /// The UTXO set, for miner and mempool reads.
    pub fn coins_view(&self) -> &dyn CoinsView {
        &*self.coins
    }
    /// Median time past of the active tip.
    pub fn median_time_past_tip(&self) -> i64 {
        self.tree.median_time_past(self.tip())
    }
    /// Hash of the active-chain block at `height`.
    pub fn block_hash_at(&self, height: u32) -> Option<BlockHash> {
        self.chain.get(height).map(|id| self.tree.get(id).hash)
    }
    /// Header and height of any indexed block, active or not.
    pub fn header_of(&self, hash: &BlockHash) -> Option<(BlockHeader, u32)> {
        self.tree.lookup(hash).map(|id| {
            let entry = self.tree.get(id);
            (entry.header, entry.height)
        })
    }
    /// `ProcessNewBlockHeaders`: check_block_header + contextual header check
    /// for each header in order; returns the last accepted id (the best
    /// header when `headers` is empty).
    pub fn process_new_block_headers(&mut self, headers: &[BlockHeader], now: i64) -> Result<IndexId, ValidationError> {
        let mut last = self.best_header;
        for header in headers {
            last = self.accept_header(header, now)?;
        }
        Ok(last)
    }
    /// `ProcessNewBlock`: accept header, `check_block` (pow + merkle),
    /// `contextual_check_block`, store, then `activate_best_chain`.
    /// Returns Ok(true) if the block was new. Invalid blocks get
    /// FAILED_VALID and descendants FAILED_CHILD.
    pub fn process_new_block(&mut self, block: &Block, now: i64) -> Result<bool, ValidationError> {
        let id = self.accept_header(&block.header, now)?;
        if self.tree.get(id).status.0 & BlockStatus::HAVE_DATA != 0 {
            return Ok(false);
        }

        let prev = self.tree.get(id).prev;
        let checked = check_block(block, &self.params, true, true)
            .map_err(ValidationError::from)
            .and_then(|()| contextual_check_block(block, &self.tree, prev, &self.params));
        if let Err(err) = checked {
            self.mark_failed(id, Some(err.clone()));
            return Err(err);
        }

        self.store.put_block(&block.block_hash(), block);
        let entry = self.tree.get_mut(id);
        entry.n_tx = block.txdata.len() as u32;
        entry.status.0 |= BlockStatus::HAVE_DATA;
        entry.status.raise_validity(BlockStatus::VALID_TRANSACTIONS);

        self.activate_best_chain()?;
        if self.tree.get(id).status.is_failed() {
            return Err(self.invalid_reason(id));
        }
        Ok(true)
    }
    /// `ActivateBestChain`: move to the most-work candidate with data,
    /// disconnecting to the fork point then connecting forward; on a failed
    /// connect mark it invalid and retry with the next best candidate.
    pub fn activate_best_chain(&mut self) -> Result<(), ValidationError> {
        while let Some(best) = self.find_most_work_chain() {
            let tip = self.tip();
            if best == tip || self.tree.get(best).chain_work <= self.tree.get(tip).chain_work {
                break;
            }
            let fork = self
                .chain
                .find_fork(&self.tree, best)
                .ok_or(ValidationError::Other("no-fork-point"))?;
            while self.tip() != fork {
                self.disconnect_tip()?;
            }

            let mut path = Vec::new();
            let mut cursor = best;
            while cursor != fork {
                path.push(cursor);
                cursor = self.tree.get(cursor).prev.ok_or(ValidationError::Other("no-fork-point"))?;
            }
            for id in path.into_iter().rev() {
                if let Err(err) = self.connect_tip(id) {
                    self.mark_failed(id, Some(err));
                    break;
                }
            }
        }
        Ok(())
    }
    /// `InvalidateBlock`: mark failed, disconnect if in the active chain, reactivate.
    pub fn invalidate_block(&mut self, hash: &BlockHash) -> Result<(), ValidationError> {
        let id = self.tree.lookup(hash).ok_or(ValidationError::Other("block-not-found"))?;
        if self.tree.get(id).height == 0 {
            return Err(ValidationError::Other("cannot-invalidate-genesis"));
        }
        self.mark_failed(id, None);
        while self.chain.contains(&self.tree, id) {
            self.disconnect_tip()?;
        }
        self.activate_best_chain()
    }
    /// Drains queued `ChainEvent`s in order.
    pub fn take_events(&mut self) -> Vec<ChainEvent> {
        std::mem::take(&mut self.events)
    }

    /// `AcceptBlockHeader`: returns the id of a new or already known valid header.
    fn accept_header(&mut self, header: &BlockHeader, now: i64) -> Result<IndexId, ValidationError> {
        let hash = header.block_hash();
        if let Some(id) = self.tree.lookup(&hash) {
            if self.tree.get(id).status.is_failed() {
                return Err(ValidationError::Duplicate);
            }
            return Ok(id);
        }

        check_block_header(header, &self.params)?;
        let prev = self
            .tree
            .lookup(&header.prev_blockhash)
            .ok_or(ValidationError::PrevBlkNotFound)?;
        if self.tree.get(prev).status.is_failed() {
            return Err(ValidationError::BadPrevBlk);
        }
        contextual_check_block_header(header, &self.tree, prev, &self.params, now)?;

        let id = self.tree.insert_header(*header).expect("prev and hash were checked above");
        if self.tree.get(id).chain_work > self.tree.get(self.best_header).chain_work {
            self.best_header = id;
        }
        Ok(id)
    }

    /// `ConnectTip`: applies the block at `id` (whose prev is the tip) to the UTXO set.
    fn connect_tip(&mut self, id: IndexId) -> Result<(), ValidationError> {
        let (hash, height) = {
            let entry = self.tree.get(id);
            (entry.hash, entry.height)
        };
        let block = self
            .store
            .get_block(&hash)
            .ok_or(ValidationError::Other("block-data-missing"))?;

        let summary = {
            let mut cache = CoinsViewCache::new(&mut *self.coins);
            let summary = connect_block(&block, &self.tree, id, &mut cache, &self.params, self.connect_opts)?;
            // Undo must be on disk before the UTXO set points at this block.
            self.store.put_undo(&hash, &summary.undo);
            cache.flush_with_best(hash);
            summary
        };

        let entry = self.tree.get_mut(id);
        entry.status.raise_validity(BlockStatus::VALID_SCRIPTS);
        entry.status.0 |= BlockStatus::HAVE_UNDO;
        self.chain.set_tip(&self.tree, Some(id));
        self.events.push(ChainEvent::BlockConnected { hash, height });
        Ok(())
    }

    /// `DisconnectTip`: undoes the active tip using its stored undo data.
    fn disconnect_tip(&mut self) -> Result<(), ValidationError> {
        let id = self.tip();
        let (hash, height, prev) = {
            let entry = self.tree.get(id);
            (entry.hash, entry.height, entry.prev)
        };
        let block = self
            .store
            .get_block(&hash)
            .ok_or(ValidationError::Other("block-data-missing"))?;
        let undo = self.store.get_undo(&hash).ok_or(ValidationError::BadUndo)?;

        {
            let mut cache = CoinsViewCache::new(&mut *self.coins);
            if disconnect_block(&block, &undo, height, &mut cache) != DisconnectResult::Ok {
                return Err(ValidationError::BadUndo);
            }
            let prev_hash = prev.map(|p| self.tree.get(p).hash).unwrap_or(hash);
            cache.flush_with_best(prev_hash);
        }

        self.chain.set_tip(&self.tree, prev);
        self.events.push(ChainEvent::BlockDisconnected {
            hash,
            height,
            txs: block.txdata,
        });
        Ok(())
    }

    /// Marks `id` `FAILED_VALID` and every descendant `FAILED_CHILD`.
    fn mark_failed(&mut self, id: IndexId, reason: Option<ValidationError>) {
        let descendants: Vec<IndexId> = self
            .tree
            .ids()
            .filter(|&other| self.is_ancestor(id, other))
            .collect();
        self.tree.get_mut(id).status.0 |= BlockStatus::FAILED_VALID;
        for descendant in descendants {
            self.tree.get_mut(descendant).status.0 |= BlockStatus::FAILED_CHILD;
        }
        if let Some(reason) = reason {
            self.invalid_reasons.insert(id, reason);
        }
    }

    fn invalid_reason(&self, id: IndexId) -> ValidationError {
        self.invalid_reasons
            .get(&id)
            .cloned()
            .unwrap_or(ValidationError::BadPrevBlk)
    }

    fn is_ancestor(&self, ancestor: IndexId, id: IndexId) -> bool {
        let ancestor_height = self.tree.get(ancestor).height;
        id != ancestor
            && self.tree.get(id).height > ancestor_height
            && self.tree.get_ancestor(id, ancestor_height) == Some(ancestor)
    }

    /// Most-work block whose whole path to the active chain has data and no
    /// failures. Equal work goes to the earlier `sequence_id`.
    fn find_most_work_chain(&self) -> Option<IndexId> {
        let mut best: Option<IndexId> = None;
        for id in self.tree.ids() {
            if !self.is_candidate(id) {
                continue;
            }
            best = match best {
                Some(current) if !self.prefers(id, current) => Some(current),
                _ => Some(id),
            };
        }
        best
    }

    fn is_candidate(&self, id: IndexId) -> bool {
        let mut cursor = id;
        loop {
            if self.chain.contains(&self.tree, cursor) {
                return true;
            }
            let entry = self.tree.get(cursor);
            if entry.status.0 & BlockStatus::HAVE_DATA == 0 || entry.status.is_failed() {
                return false;
            }
            match entry.prev {
                Some(prev) => cursor = prev,
                None => return false,
            }
        }
    }

    fn prefers(&self, a: IndexId, b: IndexId) -> bool {
        let (ea, eb) = (self.tree.get(a), self.tree.get(b));
        ea.chain_work > eb.chain_work || (ea.chain_work == eb.chain_work && ea.sequence_id < eb.sequence_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, ScriptBuf, TxMerkleNode};
    use bitcoin_hashes::Hash as _;
    use btc_primitives::{TxIn, TxOut};
    use btc_validation::block_verify::{block_merkle_root, BlockError};
    use btc_validation::coins::CoinsViewMemory;

    use crate::contextual::bip34_height_script;

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const FEE: i64 = 1_000;
    const NOW: i64 = 2_000_000_000;

    fn op_true() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    fn subsidy(height: u32) -> i64 {
        ChainParams::regtest().block_subsidy(height)
    }

    /// Increments the nonce until the header meets the regtest target.
    fn grind(mut header: BlockHeader) -> BlockHeader {
        let params = ChainParams::regtest();
        while check_block_header(&header, &params).is_err() {
            header.nonce += 1;
        }
        header
    }

    /// Regtest block on top of `parent`: BIP34 coinbase paying OP_TRUE (the
    /// `tag` byte keeps coinbases distinct across branches), then `txs`.
    fn mine(parent: &BlockHeader, parent_height: u32, txs: Vec<Tx>, cb_value: i64, tag: u8) -> Block {
        let height = parent_height + 1;
        let mut script_sig = bip34_height_script(height);
        script_sig.extend_from_slice(&[0x01, tag]);
        let mut input = TxIn::new(OutPoint::null());
        input.script_sig = ScriptBuf::from_bytes(script_sig);
        let mut txdata = vec![Tx::new(1, vec![input], vec![TxOut::new(cb_value, op_true())], 0)];
        txdata.extend(txs);

        let header = BlockHeader::new(
            0x2000_0000,
            parent.block_hash(),
            TxMerkleNode::all_zeros(),
            parent.time + 600,
            REGTEST_BITS,
            0,
        );
        let mut block = Block::new(header, txdata);
        block.header.merkle_root = block_merkle_root(&block).0;
        block.header = grind(block.header);
        block
    }

    /// `count` blocks on top of `parent` with plain subsidy coinbases.
    fn build_chain(parent: (BlockHeader, u32), count: u32, tag: u8) -> Vec<Block> {
        let (mut header, mut height) = parent;
        let mut blocks = Vec::new();
        for _ in 0..count {
            let block = mine(&header, height, vec![], subsidy(height + 1), tag);
            header = block.header;
            height += 1;
            blocks.push(block);
        }
        blocks
    }

    /// Builds `count` blocks on `parent` and processes each one as new.
    fn extend(cs: &mut Chainstate, parent: BlockHash, count: u32, tag: u8) -> Vec<Block> {
        let blocks = build_chain(cs.header_of(&parent).expect("parent is known"), count, tag);
        for block in &blocks {
            assert_eq!(cs.process_new_block(block, NOW), Ok(true));
        }
        blocks
    }

    /// Hard-coded regtest genesis (Core's `CreateGenesisBlock`).
    fn regtest_genesis() -> Block {
        const TIMESTAMP: &[u8] = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        const PUBKEY: &str = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";

        let mut script_sig = vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, TIMESTAMP.len() as u8];
        script_sig.extend_from_slice(TIMESTAMP);
        let mut script_pubkey = vec![0x41];
        script_pubkey.extend((0..PUBKEY.len()).step_by(2).map(|i| u8::from_str_radix(&PUBKEY[i..i + 2], 16).unwrap()));
        script_pubkey.push(0xac);

        let mut input = TxIn::new(OutPoint::null());
        input.script_sig = ScriptBuf::from_bytes(script_sig);
        let coinbase = Tx::new(1, vec![input], vec![TxOut::new(50 * 100_000_000, ScriptBuf::from_bytes(script_pubkey))], 0);
        let mut block = Block::new(
            BlockHeader::new(1, BlockHash::all_zeros(), TxMerkleNode::all_zeros(), 1_296_688_602, REGTEST_BITS, 2),
            vec![coinbase],
        );
        block.header.merkle_root = block_merkle_root(&block).0;
        block
    }

    fn new_chain() -> Chainstate {
        Chainstate::new(
            ChainParams::regtest(),
            regtest_genesis(),
            Box::new(CoinsViewMemory::new()),
            Box::new(MemBlockStore::default()),
        )
        .expect("regtest genesis loads")
    }

    fn genesis_hash() -> BlockHash {
        ChainParams::regtest().genesis_hash
    }

    fn coinbase_outpoint(block: &Block) -> OutPoint {
        OutPoint { txid: block.txdata[0].txid(), vout: 0 }
    }

    #[test]
    fn genesis_must_match_params() {
        let cs = new_chain();
        assert_eq!(cs.tip_hash(), genesis_hash());
        assert_eq!(cs.height(), 0);
        assert_eq!(cs.best_header(), cs.tip());

        let mut wrong = regtest_genesis();
        wrong.header.nonce = 3;
        let err = Chainstate::new(
            ChainParams::regtest(),
            wrong,
            Box::new(CoinsViewMemory::new()),
            Box::new(MemBlockStore::default()),
        )
        .err();
        assert_eq!(err, Some(ValidationError::Other("bad-genesis")));
    }

    #[test]
    fn ten_block_chain_reports_tip_and_events() {
        let mut cs = new_chain();
        let blocks = extend(&mut cs, genesis_hash(), 10, 0);

        assert_eq!(cs.height(), 10);
        assert_eq!(cs.tip_hash(), blocks[9].block_hash());
        assert_eq!(cs.block_hash_at(5), Some(blocks[4].block_hash()));
        assert_eq!(cs.block_hash_at(11), None);
        let (header, height) = cs.header_of(&blocks[2].block_hash()).unwrap();
        assert_eq!((header, height), (blocks[2].header, 3));
        // Blocks 0..=10 are 600 s apart: the median of the last 11 is block 5.
        assert_eq!(cs.median_time_past_tip(), 1_296_688_602 + 3_000);
        assert!(cs.get_block(&blocks[9].block_hash()).is_some());

        let expected: Vec<ChainEvent> = blocks
            .iter()
            .enumerate()
            .map(|(i, block)| ChainEvent::BlockConnected { hash: block.block_hash(), height: i as u32 + 1 })
            .collect();
        assert_eq!(cs.take_events(), expected);
        assert!(cs.take_events().is_empty());
    }

    #[test]
    fn longer_fork_reorgs_with_five_disconnects_and_seven_connects() {
        let mut cs = new_chain();
        let main = extend(&mut cs, genesis_hash(), 10, 0);
        cs.take_events();

        let branch = extend(&mut cs, main[4].block_hash(), 7, 1);
        assert_eq!(cs.height(), 12);
        assert_eq!(cs.tip_hash(), branch[6].block_hash());

        let events = cs.take_events();
        assert_eq!(events.len(), 12);
        for (event, height) in events[..5].iter().zip((6..=10).rev()) {
            assert!(matches!(event, ChainEvent::BlockDisconnected { height: h, .. } if *h == height));
        }
        for (i, event) in events[5..].iter().enumerate() {
            assert_eq!(
                *event,
                ChainEvent::BlockConnected { hash: branch[i].block_hash(), height: i as u32 + 6 }
            );
        }
        match &events[0] {
            ChainEvent::BlockDisconnected { txs, .. } => assert_eq!(txs.len(), 1),
            other => panic!("expected a disconnect, got {other:?}"),
        }

        let coins = cs.coins_view();
        assert!(coins.get_coin(&coinbase_outpoint(&main[7])).is_none(), "old height-8 coinbase is gone");
        assert!(coins.get_coin(&coinbase_outpoint(&main[3])).is_some(), "shared height-4 coinbase stays");
        assert!(coins.get_coin(&coinbase_outpoint(&branch[2])).is_some(), "new height-8 coinbase exists");
        assert!(coins.get_coin(&coinbase_outpoint(&branch[6])).is_some(), "new height-12 coinbase exists");
    }

    #[test]
    fn overpaying_coinbase_fails_and_its_children_are_never_activated() {
        let mut cs = new_chain();
        extend(&mut cs, genesis_hash(), 10, 0);
        cs.take_events();
        let (tip_header, tip_height) = cs.header_of(&cs.tip_hash()).unwrap();

        let bad = mine(&tip_header, tip_height, vec![], subsidy(11) + 1, 9);
        let child = mine(&bad.header, 11, vec![], subsidy(12), 9);
        assert_eq!(cs.process_new_block_headers(&[bad.header, child.header], NOW).map(|id| cs.tree.get(id).height), Ok(12));

        assert_eq!(
            cs.process_new_block(&bad, NOW),
            Err(ValidationError::BadCbAmount { actual: subsidy(11) + 1, limit: subsidy(11) })
        );
        assert_eq!(cs.height(), 10);
        assert_eq!(cs.tip_hash(), tip_header.block_hash());
        assert!(cs.take_events().is_empty());

        let bad_id = cs.tree.lookup(&bad.block_hash()).unwrap();
        let child_id = cs.tree.lookup(&child.block_hash()).unwrap();
        assert!(cs.tree.get(bad_id).status.0 & BlockStatus::FAILED_VALID != 0);
        assert!(cs.tree.get(child_id).status.0 & BlockStatus::FAILED_CHILD != 0);

        assert_eq!(cs.process_new_block(&child, NOW), Err(ValidationError::Duplicate));
        let grandchild = mine(&child.header, 12, vec![], subsidy(13), 9);
        assert_eq!(cs.process_new_block(&grandchild, NOW), Err(ValidationError::BadPrevBlk));
        assert_eq!(cs.height(), 10);

        // Honest blocks on the old tip still extend the chain.
        let tip = cs.tip_hash();
        extend(&mut cs, tip, 1, 2);
        assert_eq!(cs.height(), 11);
    }

    #[test]
    fn spend_of_matured_coinbase_survives_reorg_round_trip() {
        let mut cs = new_chain();
        let main = extend(&mut cs, genesis_hash(), 101, 0);
        let coinbase_1 = coinbase_outpoint(&main[0]);

        let input = TxIn::new(coinbase_1);
        let spend = Tx::new(1, vec![input], vec![TxOut::new(subsidy(1) - FEE, op_true())], 0);
        let spend_outpoint = OutPoint { txid: spend.txid(), vout: 0 };
        let block_102 = mine(&main[100].header, 101, vec![spend.clone()], subsidy(102) + FEE, 0);
        assert_eq!(cs.process_new_block(&block_102, NOW), Ok(true));
        assert!(cs.coins_view().get_coin(&coinbase_1).is_none());
        assert!(cs.coins_view().get_coin(&spend_outpoint).is_some());

        // A two-block branch from 101 has more work than 102 and reorgs it out.
        let alt = extend(&mut cs, main[100].block_hash(), 2, 1);
        assert_eq!(cs.tip_hash(), alt[1].block_hash());
        assert!(cs.coins_view().get_coin(&coinbase_1).is_some(), "spent coin is restored");
        assert!(cs.coins_view().get_coin(&spend_outpoint).is_none());

        // Extending the original 102 back to 104 reorgs the spend back in.
        let main_again = extend(&mut cs, block_102.block_hash(), 2, 0);
        assert_eq!(cs.tip_hash(), main_again[1].block_hash());
        assert_eq!(cs.height(), 104);
        assert!(cs.coins_view().get_coin(&coinbase_1).is_none());
        assert!(cs.coins_view().get_coin(&spend_outpoint).is_some());
    }

    #[test]
    fn invalidate_block_rolls_back_and_mining_resumes() {
        let mut cs = new_chain();
        let main = extend(&mut cs, genesis_hash(), 10, 0);
        cs.take_events();

        cs.invalidate_block(&main[7].block_hash()).unwrap();
        assert_eq!(cs.height(), 7);
        assert_eq!(cs.tip_hash(), main[6].block_hash());
        let events = cs.take_events();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| matches!(e, ChainEvent::BlockDisconnected { .. })));

        let (tip_header, _) = cs.header_of(&cs.tip_hash()).unwrap();
        let replacement = mine(&tip_header, 7, vec![], subsidy(8), 5);
        assert_eq!(cs.process_new_block(&replacement, NOW), Ok(true));
        assert_eq!(cs.height(), 8);
        assert_eq!(cs.tip_hash(), replacement.block_hash());
        assert_eq!(cs.process_new_block(&main[7], NOW), Err(ValidationError::Duplicate));
        assert_eq!(cs.invalidate_block(&BlockHash::from_byte_array([3; 32])), Err(ValidationError::Other("block-not-found")));
    }

    #[test]
    fn duplicate_block_is_not_new() {
        let mut cs = new_chain();
        let (header, height) = cs.header_of(&genesis_hash()).unwrap();
        let block = mine(&header, height, vec![], subsidy(1), 0);
        assert_eq!(cs.process_new_block(&block, NOW), Ok(true));
        assert_eq!(cs.process_new_block(&block, NOW), Ok(false));
        assert_eq!(cs.height(), 1);
    }

    #[test]
    fn headers_first_then_blocks_and_header_errors() {
        let mut cs = new_chain();
        let (header, height) = cs.header_of(&genesis_hash()).unwrap();
        let blocks = build_chain((header, height), 10, 0);
        let headers: Vec<BlockHeader> = blocks.iter().map(|block| block.header).collect();

        let best = cs.process_new_block_headers(&headers, NOW).unwrap();
        assert_eq!(cs.tree.get(best).height, 10);
        assert_eq!(cs.best_header(), best);
        assert_eq!(cs.height(), 0);
        assert!(cs.get_block(&blocks[0].block_hash()).is_none());

        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(cs.process_new_block(block, NOW), Ok(true));
            assert_eq!(cs.height(), i as u32 + 1);
        }
        assert_eq!(cs.process_new_block(&blocks[3], NOW), Ok(false));

        let stray = grind(BlockHeader::new(
            0x2000_0000,
            BlockHash::from_byte_array([9; 32]),
            TxMerkleNode::all_zeros(),
            1_296_688_602 + 600,
            REGTEST_BITS,
            0,
        ));
        assert_eq!(cs.process_new_block_headers(&[stray], NOW), Err(ValidationError::PrevBlkNotFound));

        let no_work = BlockHeader::new(0x2000_0000, blocks[9].block_hash(), TxMerkleNode::all_zeros(), 1_296_688_602 + 6_600, 0x0300_0001, 0);
        assert_eq!(
            cs.process_new_block_headers(&[no_work], NOW),
            Err(ValidationError::Block(BlockError::HighHash))
        );
    }
}
