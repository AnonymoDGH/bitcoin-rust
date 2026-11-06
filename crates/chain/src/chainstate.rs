//! Chain manager. Port of `ChainstateManager::ProcessNewBlock(Headers)`,
//! `AcceptBlockHeader`, `AcceptBlock`, `ActivateBestChain`,
//! `ConnectTip`/`DisconnectTip`, `InvalidateBlock` (validation.cpp).

use std::collections::HashMap;

use btc_consensus::ChainParams;
use btc_primitives::{Block, BlockHash, BlockHeader, Tx};
use btc_validation::coins::CoinsViewWrite;
use btc_validation::undo::BlockUndo;

use crate::connect::ConnectOptions;
use crate::{ActiveChain, BlockTree, IndexId, ValidationError};

/// Block + undo storage. `MemBlockStore` keeps everything in RAM; the node
/// plugs in the flat-file store.
pub trait BlockStore: Send {
    fn put_block(&mut self, hash: &BlockHash, block: &Block);
    fn get_block(&self, hash: &BlockHash) -> Option<Block>;
    fn put_undo(&mut self, hash: &BlockHash, undo: &BlockUndo);
    fn get_undo(&self, hash: &BlockHash) -> Option<BlockUndo>;
}

#[derive(Default)]
pub struct MemBlockStore {
    pub blocks: HashMap<BlockHash, Block>,
    pub undos: HashMap<BlockHash, BlockUndo>,
}

impl BlockStore for MemBlockStore {
    fn put_block(&mut self, hash: &BlockHash, block: &Block) {
        todo!()
    }
    fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        todo!()
    }
    fn put_undo(&mut self, hash: &BlockHash, undo: &BlockUndo) {
        todo!()
    }
    fn get_undo(&self, hash: &BlockHash) -> Option<BlockUndo> {
        todo!()
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
    // implementer may add private fields (best header, candidates, events…)
}

impl Chainstate {
    /// Loads `genesis` (must hash to `params.genesis_hash`): header indexed,
    /// block stored, tip = genesis. Genesis outputs are NOT added to the UTXO
    /// set (Core behaviour).
    pub fn new(
        params: ChainParams,
        genesis: Block,
        coins: Box<dyn CoinsViewWrite + Send>,
        store: Box<dyn BlockStore>,
    ) -> Result<Self, ValidationError> {
        todo!()
    }
    pub fn tip(&self) -> IndexId {
        todo!()
    }
    pub fn tip_hash(&self) -> BlockHash {
        todo!()
    }
    pub fn height(&self) -> u32 {
        todo!()
    }
    /// Most-work valid header known (`m_best_header`).
    pub fn best_header(&self) -> IndexId {
        todo!()
    }
    pub fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        todo!()
    }
    /// `ProcessNewBlockHeaders`: check_block_header + contextual header check
    /// for each header in order; returns the last accepted id.
    pub fn process_new_block_headers(&mut self, headers: &[BlockHeader], now: i64) -> Result<IndexId, ValidationError> {
        todo!()
    }
    /// `ProcessNewBlock`: accept header, `check_block` (pow + merkle),
    /// `contextual_check_block`, store, then `activate_best_chain`.
    /// Returns Ok(true) if the block was new. Invalid blocks get
    /// FAILED_VALID and descendants FAILED_CHILD.
    pub fn process_new_block(&mut self, block: &Block, now: i64) -> Result<bool, ValidationError> {
        todo!()
    }
    /// `ActivateBestChain`: move to the most-work candidate with data,
    /// disconnecting to the fork point then connecting forward; on a failed
    /// connect mark it invalid and retry with the next best candidate.
    pub fn activate_best_chain(&mut self) -> Result<(), ValidationError> {
        todo!()
    }
    /// `InvalidateBlock`: mark failed, disconnect if in the active chain, reactivate.
    pub fn invalidate_block(&mut self, hash: &BlockHash) -> Result<(), ValidationError> {
        todo!()
    }
    /// Drains queued `ChainEvent`s in order.
    pub fn take_events(&mut self) -> Vec<ChainEvent> {
        todo!()
    }
}
