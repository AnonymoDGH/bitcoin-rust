//! Block tree. Port of `chain.{h,cpp}` (`CBlockIndex`, `CChain`, skip list,
//! `GetMedianTimePast`, `LastCommonAncestor`) and `pow.cpp::GetNextWorkRequired`.

use btc_consensus::ChainParams;
use btc_primitives::{BlockHash, BlockHeader};
use primitive_types::U256;

/// Arena index of a `BlockIndex` inside a `BlockTree`.
pub type IndexId = usize;

/// `BlockStatus` bit flags (chain.h).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BlockStatus(pub u32);

impl BlockStatus {
    pub const VALID_TREE: u32 = 2;
    pub const VALID_TRANSACTIONS: u32 = 3;
    pub const VALID_CHAIN: u32 = 4;
    pub const VALID_SCRIPTS: u32 = 5;
    pub const VALID_MASK: u32 = 7;
    pub const HAVE_DATA: u32 = 8;
    pub const HAVE_UNDO: u32 = 16;
    pub const FAILED_VALID: u32 = 32;
    pub const FAILED_CHILD: u32 = 64;
    pub const FAILED_MASK: u32 = Self::FAILED_VALID | Self::FAILED_CHILD;

    /// `IsValid(nUpTo)`.
    pub fn is_valid(self, up_to: u32) -> bool {
        todo!()
    }
    /// `RaiseValidity(nUpTo)`: returns true if the level changed.
    pub fn raise_validity(&mut self, up_to: u32) -> bool {
        todo!()
    }
    pub fn is_failed(self) -> bool {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct BlockIndex {
    pub hash: BlockHash,
    pub header: BlockHeader,
    pub height: u32,
    pub prev: Option<IndexId>,
    /// Skip-list pointer (`pskip`).
    pub skip: Option<IndexId>,
    /// Total work up to and including this block (`nChainWork`).
    pub chain_work: U256,
    pub status: BlockStatus,
    /// Number of transactions (0 until block data is known).
    pub n_tx: u32,
    /// Insertion order, used as tie-breaker (`nSequenceId`).
    pub sequence_id: u64,
}

/// All known headers (`BlockMap` + `m_block_index`).
#[derive(Clone, Debug, Default)]
pub struct BlockTree {
    // implementer's choice
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexError {
    UnknownPrev,
    Duplicate(IndexId),
}

impl BlockTree {
    pub fn new() -> Self {
        todo!()
    }
    /// `AddToBlockIndex`. The first inserted header is the genesis (its prev
    /// must be all zeros). Others need a known prev. Sets height, skip,
    /// chain_work (prev work + `work_from_bits`), status VALID_TREE.
    pub fn insert_header(&mut self, header: BlockHeader) -> Result<IndexId, IndexError> {
        todo!()
    }
    pub fn get(&self, id: IndexId) -> &BlockIndex {
        todo!()
    }
    pub fn get_mut(&mut self, id: IndexId) -> &mut BlockIndex {
        todo!()
    }
    pub fn lookup(&self, hash: &BlockHash) -> Option<IndexId> {
        todo!()
    }
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
    /// Every id, in insertion order.
    pub fn ids(&self) -> std::ops::Range<IndexId> {
        todo!()
    }
    /// `GetAncestor(height)` using the skip list (O(log n)).
    pub fn get_ancestor(&self, id: IndexId, height: u32) -> Option<IndexId> {
        todo!()
    }
    /// `GetMedianTimePast()`: median of the last 11 block times ending at `id`.
    pub fn median_time_past(&self, id: IndexId) -> i64 {
        todo!()
    }
    /// `LastCommonAncestor(a, b)`.
    pub fn last_common_ancestor(&self, a: IndexId, b: IndexId) -> IndexId {
        todo!()
    }
    /// `GetNextWorkRequired(pindexLast=prev, pblock=header)`, including the
    /// testnet min-difficulty walk-back. Uses `btc_consensus::pow`.
    pub fn next_work_required(&self, prev: IndexId, header: &BlockHeader, params: &ChainParams) -> u32 {
        todo!()
    }
}

/// The active chain (`CChain`): `chain[h]` is the id at height `h`.
#[derive(Clone, Debug, Default)]
pub struct ActiveChain {
    // implementer's choice
}

impl ActiveChain {
    pub fn new() -> Self {
        todo!()
    }
    pub fn tip(&self) -> Option<IndexId> {
        todo!()
    }
    pub fn genesis(&self) -> Option<IndexId> {
        todo!()
    }
    /// Height of the tip, `None` when empty.
    pub fn height(&self) -> Option<u32> {
        todo!()
    }
    pub fn get(&self, height: u32) -> Option<IndexId> {
        todo!()
    }
    pub fn contains(&self, tree: &BlockTree, id: IndexId) -> bool {
        todo!()
    }
    /// Successor of `id` in this chain, if `id` is in it.
    pub fn next(&self, tree: &BlockTree, id: IndexId) -> Option<IndexId> {
        todo!()
    }
    /// `SetTip`: rebuild so `id` is the tip (walk prev pointers).
    pub fn set_tip(&mut self, tree: &BlockTree, id: Option<IndexId>) {
        todo!()
    }
    /// `FindFork`: last block of this chain that is an ancestor of `id`.
    pub fn find_fork(&self, tree: &BlockTree, id: IndexId) -> Option<IndexId> {
        todo!()
    }
    /// `GetLocator`: tip, then exponentially spaced back to genesis.
    pub fn locator(&self, tree: &BlockTree) -> Vec<BlockHash> {
        todo!()
    }
}
