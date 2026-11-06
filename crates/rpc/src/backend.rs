//! The node interface the RPC layer is written against.

use bitcoin::Network;
use btc_primitives::{Block, BlockHash, BlockHeader, OutPoint, ScriptBuf, Tx, TxOut, Txid};

/// Subset of `getblockchaininfo` the RPC layer renders.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub bestblockhash: BlockHash,
    pub difficulty: f64,
    pub mediantime: i64,
    pub chainwork: String,
}

/// Subset of `getmempoolinfo` the RPC layer renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MempoolInfo {
    pub size: u64,
    pub bytes: u64,
}

/// Everything the JSON-RPC methods need from the node.
///
/// Errors from the mutating methods carry the rejection reason verbatim, which
/// the RPC layer forwards to the client as Core does.
pub trait RpcBackend: Send + Sync + 'static {
    fn get_block_count(&self) -> u32;
    fn get_best_block_hash(&self) -> BlockHash;
    fn get_block_hash(&self, height: u32) -> Option<BlockHash>;
    /// Returns the block, its height and its confirmations (-1 when not in the active chain).
    fn get_block(&self, hash: &BlockHash) -> Option<(Block, u32, i64)>;
    /// Returns the header, its height and its confirmations (-1 when not in the active chain).
    fn get_block_header(&self, hash: &BlockHash) -> Option<(BlockHeader, u32, i64)>;
    fn get_blockchain_info(&self) -> BlockchainInfo;
    fn get_raw_mempool(&self) -> Vec<Txid>;
    fn get_mempool_info(&self) -> MempoolInfo;
    fn get_raw_transaction(&self, txid: &Txid) -> Option<Tx>;
    fn send_raw_transaction(&self, tx: Tx) -> Result<Txid, String>;
    /// `Ok(())` when the block was accepted, otherwise the BIP22 rejection reason.
    fn submit_block(&self, block: Block) -> Result<(), String>;
    fn generate_to_script(&self, n: u32, script: ScriptBuf) -> Result<Vec<BlockHash>, String>;
    /// Returns the output, its confirmations and whether it is a coinbase output.
    fn get_tx_out(&self, outpoint: &OutPoint) -> Option<(TxOut, u32, bool)>;
    fn network(&self) -> Network;
    fn stop(&self);
}
