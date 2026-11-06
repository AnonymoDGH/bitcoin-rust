//! Block assembly. Port of `BlockAssembler::CreateNewBlock`,
//! `addPackageTxs` (ancestor fee-rate selection) and `IncrementExtraNonce` /
//! nonce grinding from `node/miner.cpp` and `rpc/mining.cpp::GenerateBlock`.

use btc_primitives::{Block, ScriptBuf};
use btc_validation::mempool::Mempool;

use crate::chainstate::Chainstate;

#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub block: Block,
    pub height: u32,
    /// Per-tx fees (coinbase entry = -total fees, as Core).
    pub fees: Vec<i64>,
    pub sigop_costs: Vec<u64>,
}

/// `CreateNewBlock` on top of the current tip: coinbase (BIP34 height push +
/// extra nonce, pays subsidy + fees to `coinbase_script`), mempool txs by
/// ancestor fee rate (parents before children, only txs whose inputs exist in
/// the UTXO set or earlier in the block, final at height/MTP), under weight
/// and sigop limits, witness commitment, merkle root, nBits from
/// `next_work_required`, time = max(MTP+1, now).
pub fn create_new_block(chainstate: &Chainstate, mempool: &Mempool, coinbase_script: ScriptBuf, now: i64) -> BlockTemplate {
    todo!()
}

/// Grind header nonce (bumping time on wrap is the caller's job). Returns true
/// once `block_hash <= target(bits)`; false after `max_tries`.
pub fn mine_block(block: &mut Block, max_tries: u64) -> bool {
    todo!()
}
