//! Applying and undoing a block on the UTXO set. Port of
//! `Chainstate::ConnectBlock`, `DisconnectBlock`, `UpdateCoins`,
//! `ApplyTxInUndo` (validation.cpp).

use btc_consensus::ChainParams;
use btc_primitives::Block;
use btc_validation::coins::CoinsViewCache;
use btc_validation::undo::BlockUndo;

use crate::{BlockTree, IndexId, ValidationError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectOptions {
    /// Run script verification (false = assumevalid-style skip).
    pub check_scripts: bool,
    /// Worker threads for script checks (<=1 = serial).
    pub script_threads: usize,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self { check_scripts: true, script_threads: 1 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectSummary {
    pub undo: BlockUndo,
    pub fees: i64,
    pub sigop_cost: u64,
}

/// `ConnectBlock` for the block indexed at `id` (whose prev must be the
/// current tip of `coins`). Genesis (`height == 0`) is a no-op returning empty
/// undo. Runs, in Core order: BIP30 check (skip once BIP34 is active, except
/// Core's two historical exceptions only matter on mainnet), per-tx
/// `check_transaction` is assumed done by `check_block`; for each non-coinbase
/// tx: `check_tx_inputs`, BIP68 sequence locks (CSV active), sigop cost limit,
/// script checks with `block_script_flags`; then coinbase value <= fees +
/// subsidy. Applies all coin changes to `coins` (caller flushes on success).
pub fn connect_block(
    block: &Block,
    tree: &BlockTree,
    id: IndexId,
    coins: &mut CoinsViewCache<'_>,
    params: &ChainParams,
    opts: ConnectOptions,
) -> Result<ConnectSummary, ValidationError> {
    todo!()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectResult {
    Ok,
    /// Rolled back, but the UTXO set was inconsistent (Core DISCONNECT_UNCLEAN).
    Unclean,
    Failed,
}

/// `DisconnectBlock`: remove outputs created by `block` (at `height`) and
/// restore spent coins from `undo`, processing transactions in reverse.
pub fn disconnect_block(
    block: &Block,
    undo: &BlockUndo,
    height: u32,
    coins: &mut CoinsViewCache<'_>,
) -> DisconnectResult {
    todo!()
}
