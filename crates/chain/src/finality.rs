//! Lock-time rules. Port of `IsFinalTx`, `CalculateSequenceLocks`,
//! `EvaluateSequenceLocks`, `SequenceLocks` (consensus/tx_verify.cpp).

use btc_primitives::{Tx, TxIn};

/// `LOCKTIME_THRESHOLD`: below = block height, at or above = unix time.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// `IsFinalTx(tx, nBlockHeight, nBlockTime)`.
pub fn is_final_tx(tx: &Tx, block_height: i32, block_time: i64) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    let block_value = if tx.lock_time < LOCKTIME_THRESHOLD {
        i64::from(block_height)
    } else {
        block_time
    };
    if i64::from(tx.lock_time) < block_value {
        return true;
    }
    tx.vin.iter().all(|txin| txin.sequence.0 == TxIn::SEQUENCE_FINAL)
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
    assert_eq!(prev_heights.len(), tx.vin.len());
    let mut lock = SequenceLock {
        min_height: -1,
        min_time: -1,
    };
    if !(enforce_bip68 && (tx.version as i32) >= 2) {
        return lock;
    }

    for (txin, prev_height) in tx.vin.iter().zip(prev_heights.iter_mut()) {
        let sequence = txin.sequence.0;
        if sequence & TxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            *prev_height = 0;
            continue;
        }
        let coin_height = *prev_height;
        let value = sequence & TxIn::SEQUENCE_LOCKTIME_MASK;
        if sequence & TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            let coin_time = ancestor_mtp(std::cmp::max(coin_height - 1, 0));
            let relative = i64::from(value) << TxIn::SEQUENCE_LOCKTIME_GRANULARITY;
            lock.min_time = lock.min_time.max(coin_time + relative - 1);
        } else {
            lock.min_height = lock.min_height.max(coin_height + value as i32 - 1);
        }
    }
    lock
}

/// `EvaluateSequenceLocks`: `block_height` is the new block's height and
/// `prev_mtp` the median-time-past of its parent.
pub fn evaluate_sequence_locks(block_height: i32, prev_mtp: i64, lock: SequenceLock) -> bool {
    lock.min_height < block_height && lock.min_time < prev_mtp
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Sequence;

    fn tx_with(version: u32, lock_time: u32, sequences: &[u32]) -> Tx {
        let vin = sequences
            .iter()
            .map(|&s| TxIn {
                sequence: Sequence(s),
                ..TxIn::default()
            })
            .collect();
        Tx::new(version, vin, Vec::new(), lock_time)
    }

    #[test]
    fn is_final_tx_zero_lock_time_is_final() {
        let tx = tx_with(2, 0, &[10]);
        assert!(is_final_tx(&tx, 0, 0));
    }

    #[test]
    fn is_final_tx_height_lock() {
        let tx = tx_with(2, 100, &[10]);
        assert!(!is_final_tx(&tx, 99, 0));
        assert!(!is_final_tx(&tx, 100, 0));
        assert!(is_final_tx(&tx, 101, 0));
    }

    #[test]
    fn is_final_tx_time_lock() {
        let lock_time = LOCKTIME_THRESHOLD + 1_000;
        let tx = tx_with(2, lock_time, &[10]);
        assert!(!is_final_tx(&tx, i32::MAX, i64::from(lock_time)));
        assert!(is_final_tx(&tx, 0, i64::from(lock_time) + 1));
    }

    #[test]
    fn is_final_tx_all_final_sequences_override_lock_time() {
        let locked = tx_with(2, 1_000, &[TxIn::SEQUENCE_FINAL, TxIn::SEQUENCE_FINAL]);
        assert!(is_final_tx(&locked, 1, 0));

        let mixed = tx_with(2, 1_000, &[TxIn::SEQUENCE_FINAL, 0]);
        assert!(!is_final_tx(&mixed, 1, 0));
    }

    #[test]
    fn sequence_locks_ignored_for_version_1_or_when_not_enforced() {
        let mut heights = [100];
        let lock = calculate_sequence_locks(&tx_with(1, 0, &[10]), true, &mut heights, &|_| 0);
        assert_eq!(lock, SequenceLock { min_height: -1, min_time: -1 });
        assert_eq!(heights, [100]);

        let mut heights = [100];
        let lock = calculate_sequence_locks(&tx_with(2, 0, &[10]), false, &mut heights, &|_| 0);
        assert_eq!(lock, SequenceLock { min_height: -1, min_time: -1 });
        assert_eq!(heights, [100]);
    }

    #[test]
    fn sequence_locks_disable_flag_zeroes_prev_height() {
        let tx = tx_with(2, 0, &[TxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG | 10]);
        let mut heights = [100];
        let lock = calculate_sequence_locks(&tx, true, &mut heights, &|_| 0);
        assert_eq!(lock, SequenceLock { min_height: -1, min_time: -1 });
        assert_eq!(heights, [0]);
    }

    #[test]
    fn sequence_height_lock_and_evaluation() {
        let tx = tx_with(2, 0, &[10]);
        let mut heights = [100];
        let lock = calculate_sequence_locks(&tx, true, &mut heights, &|_| 0);
        assert_eq!(lock.min_height, 109);
        assert!(!evaluate_sequence_locks(109, 0, lock));
        assert!(evaluate_sequence_locks(110, 0, lock));
    }

    #[test]
    fn sequence_time_lock_with_granularity() {
        let tx = tx_with(2, 0, &[TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1]);
        let mut heights = [100];
        let lock = calculate_sequence_locks(&tx, true, &mut heights, &|h| {
            assert_eq!(h, 99);
            1_000_000
        });
        assert_eq!(lock.min_time, 1_000_000 + 512 - 1);
        assert_eq!(lock.min_height, -1);
        assert!(!evaluate_sequence_locks(1_000, 1_000_511, lock));
        assert!(evaluate_sequence_locks(1_000, 1_000_512, lock));
    }

    #[test]
    fn sequence_time_lock_clamps_ancestor_height_at_zero() {
        let tx = tx_with(2, 0, &[TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1]);
        let mut heights = [0];
        let lock = calculate_sequence_locks(&tx, true, &mut heights, &|h| {
            assert_eq!(h, 0);
            1_000_000
        });
        assert_eq!(lock.min_time, 1_000_511);
    }

    #[test]
    fn sequence_locks_take_maximum_across_inputs() {
        let tx = tx_with(2, 0, &[10, 5]);
        let mut heights = [100, 105];
        let lock = calculate_sequence_locks(&tx, true, &mut heights, &|_| 0);
        assert_eq!(lock.min_height, 109);

        let tx = tx_with(2, 0, &[10, 20]);
        let mut heights = [100, 105];
        let lock = calculate_sequence_locks(&tx, true, &mut heights, &|_| 0);
        assert_eq!(lock.min_height, 124);
    }
}
