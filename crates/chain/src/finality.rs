//! Lock-time rules. Port of `IsFinalTx`, `CalculateSequenceLocks`,
//! `EvaluateSequenceLocks`, `SequenceLocks` (consensus/tx_verify.cpp).

use btc_primitives::Tx;

/// `LOCKTIME_THRESHOLD`: below = block height, at or above = unix time.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// `IsFinalTx(tx, nBlockHeight, nBlockTime)`.
pub fn is_final_tx(tx: &Tx, block_height: i32, block_time: i64) -> bool {
    todo!()
}

/// `(min_height, min_time)` pair returned by `CalculateSequenceLocks`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceLock {
    pub min_height: i32,
    pub min_time: i64,
}

/// `CalculateSequenceLocks`. `enforce_bip68` = `LOCKTIME_VERIFY_SEQUENCE`
/// flag and tx version >= 2. `prev_heights[i]` is the height of the coin spent
/// by input i; entries for disabled inputs are set to 0 as Core does.
/// `ancestor_mtp(h)` returns the median-time-past of the ancestor at height
/// `h` of the block being validated (Core: `block.GetAncestor(max(h-1,0))`;
/// the caller passes `max(coin_height - 1, 0)`).
pub fn calculate_sequence_locks(
    tx: &Tx,
    enforce_bip68: bool,
    prev_heights: &mut [i32],
    ancestor_mtp: &dyn Fn(i32) -> i64,
) -> SequenceLock {
    todo!()
}

/// `EvaluateSequenceLocks`: `block_height` is the new block's height and
/// `prev_mtp` the median-time-past of its parent.
pub fn evaluate_sequence_locks(block_height: i32, prev_mtp: i64, lock: SequenceLock) -> bool {
    todo!()
}
