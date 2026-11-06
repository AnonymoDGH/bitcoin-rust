//! Proof-of-work helpers: difficulty retargeting and chain work.
//!
//! Ported from `pow.cpp` (`CalculateNextWorkRequired`, `GetNextWorkRequired`)
//! and `chain.cpp` (`GetBitsProof`). All functions are pure; the chain state
//! needed by the C++ versions (ancestor lookups) is passed in explicitly.

use primitive_types::U256;

use crate::compact::{decode_compact, encode_compact, CompactError};
use crate::params::ChainParams;

/// Inputs required to compute the next required work.
///
/// `height` is the height of the block being evaluated (i.e.
/// `pindexLast->nHeight + 1` in Bitcoin Core). The two `first_*` fields refer
/// to the first block of the current retarget window, and `last_non_min_bits`
/// is the bits of the most recent block that was not produced under the
/// testnet minimum-difficulty rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetargetInput {
    /// Height of the new block.
    pub height: u32,
    /// Timestamp of the new block.
    pub block_time: i64,
    /// Timestamp of the previous block.
    pub last_time: i64,
    /// Bits of the previous block.
    pub last_bits: u32,
    /// Timestamp of the first block in the retarget window.
    pub first_time: i64,
    /// Bits of the first block in the retarget window (used by BIP94).
    pub first_bits: u32,
    /// Bits of the last block that was not a minimum-difficulty block.
    pub last_non_min_bits: u32,
}

/// `GetNextWorkRequired()`: decide whether the next block retargets, applies
/// the testnet minimum-difficulty rule, or simply inherits the previous bits.
pub fn next_work_required(input: &RetargetInput, params: &ChainParams) -> u32 {
    let interval = params.difficulty_adjustment_interval();
    if interval <= 0 {
        return input.last_bits;
    }

    if i64::from(input.height) % interval != 0 {
        if params.allow_min_difficulty_blocks {
            // Testnet rule: a block more than twice the target spacing after
            // its parent must use the minimum difficulty.
            if input.block_time > input.last_time + params.target_spacing * 2 {
                return params.pow_limit_bits();
            }
            return input.last_non_min_bits;
        }
        return input.last_bits;
    }

    // Retarget boundary: go back one full interval and recompute.
    if input.height < interval as u32 {
        return input.last_bits;
    }

    calculate_next_work_required(
        input.last_bits,
        input.first_time,
        input.last_time,
        input.first_bits,
        params,
    )
}

/// `CalculateNextWorkRequired()`: the retarget computation itself.
///
/// The observed timespan is clamped to `[target_timespan / 4,
/// target_timespan * 4]`, then the target is scaled by
/// `actual_timespan / target_timespan` and capped at `powLimit`.
///
/// With `enforce_BIP94` the starting target is taken from the first block of
/// the window rather than the previous block, matching the testnet4 rule.
pub fn calculate_next_work_required(
    last_bits: u32,
    first_block_time: i64,
    last_block_time: i64,
    first_of_period_bits: u32,
    params: &ChainParams,
) -> u32 {
    if params.no_retargeting {
        return last_bits;
    }
    if params.target_timespan <= 0 {
        return last_bits;
    }

    let mut actual_timespan = last_block_time - first_block_time;
    let smallest = params.target_timespan / 4;
    let largest = params.target_timespan * 4;
    actual_timespan = actual_timespan.clamp(smallest, largest);

    let basis_bits = if params.enforce_bip94 {
        first_of_period_bits
    } else {
        last_bits
    };

    // An invalid basis cannot produce a meaningful target; keep the previous
    // bits rather than inventing one.
    let Ok(mut target) = decode_compact(basis_bits) else {
        return last_bits;
    };

    // Wrapping multiplication matches arith_uint256 semantics. For every chain
    // parameter set in this crate the product fits in 256 bits.
    target =
        target * U256::from(actual_timespan as u64) / U256::from(params.target_timespan as u64);

    if target > params.pow_limit {
        target = params.pow_limit;
    }

    encode_compact(target)
}

/// `GetBitsProof()`: work represented by a compact target.
///
/// Computes `2**256 / (target + 1)` using the identity
/// `((2**256 - target - 1) / (target + 1)) + 1`, i.e.
/// `(~target / (target + 1)) + 1`.
pub fn work_from_bits(bits: u32) -> Result<U256, CompactError> {
    let target = decode_compact(bits)?;
    Ok((!target / (target + U256::one())) + U256::one())
}

/// Total chain work for a sequence of compact targets.
pub fn chain_work(bits: impl IntoIterator<Item = u32>) -> Result<U256, CompactError> {
    let mut total = U256::zero();
    for bits in bits {
        total += work_from_bits(bits)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_retargeting_returns_previous_bits() {
        let regtest = ChainParams::regtest();
        let input = RetargetInput {
            height: 144,
            block_time: 1_300_000_000,
            last_time: 1_299_999_000,
            last_bits: 0x207f_ffff,
            first_time: 1_299_000_000,
            first_bits: 0x207f_ffff,
            last_non_min_bits: 0x207f_ffff,
        };
        assert_eq!(next_work_required(&input, &regtest), 0x207f_ffff);
        assert_eq!(
            calculate_next_work_required(0x207f_ffff, 1, 2, 0x207f_ffff, &regtest),
            0x207f_ffff
        );
    }

    #[test]
    fn clamp_at_quarter_and_quadruple_timespan() {
        let mainnet = ChainParams::mainnet();
        let timespan = mainnet.target_timespan;

        // Instant blocks: clamp to timespan / 4.
        let fast = calculate_next_work_required(0x1c05_a3f4, 1_000, 1_000, 0x1c05_a3f4, &mainnet);
        let quarter = calculate_next_work_required(
            0x1c05_a3f4,
            1_000,
            1_000 + timespan / 4,
            0x1c05_a3f4,
            &mainnet,
        );
        assert_eq!(fast, quarter);

        // Extremely slow blocks: clamp to timespan * 4, capped by pow limit.
        let slow =
            calculate_next_work_required(0x1c05_a3f4, 0, timespan * 100, 0x1c05_a3f4, &mainnet);
        let quadruple =
            calculate_next_work_required(0x1c05_a3f4, 0, timespan * 4, 0x1c05_a3f4, &mainnet);
        assert_eq!(slow, quadruple);
    }
}
