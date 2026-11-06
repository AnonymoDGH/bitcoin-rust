//! Conversion between compact "bits" and 256-bit targets.
//!
//! Ported from `arith_uint256::SetCompact()` / `arith_uint256::GetCompact()`.
//! A compact value packs an exponent and a 24-bit mantissa:
//!
//! ```text
//! bits = (size << 24) | mantissa
//! target = mantissa << (8 * (size - 3))    (size > 3)
//! target = mantissa >> (8 * (3 - size))    (size <= 3)
//! ```
//!
//! Bit 23 of the mantissa is the sign bit, exactly as in Bitcoin Core.

use primitive_types::U256;
use thiserror::Error;

/// Errors returned when decoding a compact target.
///
/// These mirror the `fNegative`, `fOverflow` and `== 0` checks performed by
/// `DeriveTarget()` before the target is compared against the proof-of-work
/// limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CompactError {
    /// The mantissa's sign bit is set, so the target would be negative.
    #[error("compact target is negative")]
    Negative,
    /// The exponent/mantissa pair does not fit in 256 bits.
    #[error("compact target overflows 256 bits")]
    Overflow,
    /// The encoded target is zero.
    #[error("compact target is zero")]
    Zero,
}

/// Decode a compact target into a 256-bit target.
///
/// Returns an error for negative, overflowing or zero values, matching
/// `DeriveTarget()`.
pub fn decode_compact(bits: u32) -> Result<U256, CompactError> {
    let size = (bits >> 24) as usize;
    let word = bits & 0x007f_ffff;

    if word != 0 && (bits & 0x0080_0000) != 0 {
        return Err(CompactError::Negative);
    }

    // Same overflow test as SetCompact(). Checked before shifting so the shift
    // amount is always in range and the result cannot be silently truncated.
    let overflow =
        word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    if overflow {
        return Err(CompactError::Overflow);
    }

    let target = if size <= 3 {
        U256::from(word >> (8 * (3 - size)))
    } else {
        U256::from(word) << (8 * (size - 3))
    };

    if target.is_zero() {
        Err(CompactError::Zero)
    } else {
        Ok(target)
    }
}

/// Encode a 256-bit target as a compact target.
///
/// Mirrors `arith_uint256::GetCompact(false)`: the mantissa is reduced to its
/// three most significant bytes and the exponent increased when the sign bit
/// would otherwise be set.
pub fn encode_compact(target: U256) -> u32 {
    let size = (bit_len(target) + 7) / 8;

    let mut compact = if size <= 3 {
        target.low_u64() << (8 * (3 - size))
    } else {
        (target >> (8 * (size - 3))).low_u64()
    } as u32;

    let mut size = size as u32;
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }

    compact | (size << 24)
}

/// Number of significant bits in a `U256` (0 for zero), matching
/// `base_uint::bits()`.
fn bit_len(value: U256) -> usize {
    for (index, word) in value.0.iter().enumerate().rev() {
        if *word != 0 {
            return index * 64 + (64 - word.leading_zeros() as usize);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_encodings() {
        // Mainnet pow limit.
        let target = U256::from(0xffffu64) << 208;
        assert_eq!(encode_compact(target), 0x1d00_ffff);
        assert_eq!(decode_compact(0x1d00_ffff).unwrap(), target);

        // Regtest pow limit.
        let target = U256::from(0x7fffffu64) << 232;
        assert_eq!(encode_compact(target), 0x207f_ffff);
        assert_eq!(decode_compact(0x207f_ffff).unwrap(), target);
    }

    #[test]
    fn bit_len_boundaries() {
        assert_eq!(bit_len(U256::zero()), 0);
        assert_eq!(bit_len(U256::one()), 1);
        assert_eq!(bit_len(U256::from(0xffu64)), 8);
        assert_eq!(bit_len(U256::from(0x100u64)), 9);
        assert_eq!(bit_len(U256::MAX), 256);
    }
}
