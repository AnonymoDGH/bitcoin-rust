//! Block subsidy schedule.
//!
//! Ported from `validation.cpp` (`GetBlockSubsidy`) and `consensus/amount.h`.

/// Smallest unit of a bitcoin (1e-8 BTC).
pub const COIN: i64 = 100_000_000;
/// Initial block subsidy: 50 BTC.
pub const INITIAL_SUBSIDY: i64 = 50 * COIN;
/// Total bitcoin supply cap, in satoshis.
pub const MAX_MONEY: i64 = 21_000_000 * COIN;

/// `GetBlockSubsidy()`: the subsidy paid to the coinbase at `height`.
///
/// The subsidy starts at 50 BTC and is halved every `halving_interval` blocks.
/// Once the shift would be undefined (64 or more halvings), the result is
/// zero, exactly as in Bitcoin Core.
pub fn block_subsidy(height: u32, halving_interval: u32) -> i64 {
    if halving_interval == 0 {
        return 0;
    }

    let halvings = height / halving_interval;
    if halvings >= 64 {
        return 0;
    }

    INITIAL_SUBSIDY >> halvings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_constants() {
        assert_eq!(COIN, 100_000_000);
        assert_eq!(INITIAL_SUBSIDY, 5_000_000_000);
        assert_eq!(MAX_MONEY, 2_100_000_000_000_000);

        // A zero interval is not a valid chain parameter; avoid a division by
        // zero and return no subsidy.
        assert_eq!(block_subsidy(1, 0), 0);
    }
}
