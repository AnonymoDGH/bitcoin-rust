//! `btc-consensus`: Rust port of Bitcoin Core's consensus parameters and
//! proof-of-work rules.
//!
//! The module layout mirrors the relevant parts of the reference tree:
//!
//! - [`params`] <- `kernel/chainparams.cpp`, `chainparamsbase.cpp`,
//!   `consensus/params.h`
//! - [`compact`] <- `arith_uint256.{h,cpp}` (`SetCompact` / `GetCompact`)
//! - [`pow`] <- `pow.cpp`, `chain.cpp` (`GetBitsProof`)
//! - [`subsidy`] <- `validation.cpp` (`GetBlockSubsidy`)
//!
//! Arithmetic is performed with [`primitive_types::U256`], which has the same
//! wrapping 256-bit semantics as `arith_uint256`.

pub mod compact;
pub mod params;
pub mod pow;
pub mod subsidy;

pub use compact::{decode_compact, encode_compact, CompactError};
pub use params::{ChainParams, ChainType, Deployments};
pub use pow::{
    calculate_next_work_required, chain_work, next_work_required, work_from_bits, RetargetInput,
};
pub use subsidy::{block_subsidy, COIN, INITIAL_SUBSIDY, MAX_MONEY};

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{BlockHash, TxMerkleNode};
    use bitcoin_hashes::Hash;
    use btc_primitives::BlockHeader;
    use primitive_types::U256;

    /// Rebuild the genesis header from the values used by
    /// `CreateGenesisBlock()` and check it hashes to the value stored in
    /// `ChainParams`.
    fn assert_genesis(header: BlockHeader, params: &ChainParams) {
        assert_eq!(header.block_hash(), params.genesis_hash);
    }

    #[test]
    fn genesis_hashes_match_recomputed_headers() {
        let merkle_root: TxMerkleNode =
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                .parse()
                .unwrap();

        let mainnet = ChainParams::mainnet();
        assert_eq!(
            mainnet.genesis_hash.to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_genesis(
            BlockHeader::new(
                1,
                BlockHash::all_zeros(),
                merkle_root,
                1_231_006_505,
                mainnet.genesis_bits,
                2_083_236_893,
            ),
            &mainnet,
        );

        let testnet = ChainParams::testnet();
        assert_eq!(
            testnet.genesis_hash.to_string(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
        assert_genesis(
            BlockHeader::new(
                1,
                BlockHash::all_zeros(),
                merkle_root,
                1_296_688_602,
                testnet.genesis_bits,
                414_098_458,
            ),
            &testnet,
        );

        let regtest = ChainParams::regtest();
        assert_eq!(
            regtest.genesis_hash.to_string(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
        assert_genesis(
            BlockHeader::new(
                1,
                BlockHash::all_zeros(),
                merkle_root,
                1_296_688_602,
                regtest.genesis_bits,
                2,
            ),
            &regtest,
        );

        // All three chains share the same genesis coinbase and therefore the
        // same merkle root.
        assert_eq!(mainnet.genesis_bits, 0x1d00_ffff);
        assert_eq!(testnet.genesis_bits, 0x1d00_ffff);
        assert_eq!(regtest.genesis_bits, 0x207f_ffff);
    }

    #[test]
    fn compact_bits_roundtrip() {
        for bits in [
            0x1d00_ffffu32, // mainnet genesis / pow limit
            0x1d00_d86a,    // block 32256
            0x1c05_a3f4,    // block 68543
            0x1c01_68fd,
            0x1d00_e1fd,
            0x207f_ffff, // regtest genesis / pow limit
        ] {
            let target = decode_compact(bits).unwrap();
            assert_eq!(
                encode_compact(target),
                bits,
                "roundtrip failed for {bits:#010x}"
            );
        }

        let mainnet = ChainParams::mainnet();
        // 0x1d00ffff encodes powLimit, but decoding it rounds the mantissa
        // down to 0xffff, so the decoded target is at most powLimit.
        assert!(decode_compact(mainnet.genesis_bits).unwrap() <= mainnet.pow_limit);
        assert_eq!(mainnet.pow_limit_bits(), 0x1d00_ffff);

        let regtest = ChainParams::regtest();
        assert_eq!(regtest.pow_limit_bits(), 0x207f_ffff);

        // Reject negative, overflowing and zero targets, like DeriveTarget().
        assert_eq!(decode_compact(0x1d80_ffff), Err(CompactError::Negative));
        assert_eq!(decode_compact(0x2300_0001), Err(CompactError::Overflow));
        assert_eq!(decode_compact(0x1d00_0000), Err(CompactError::Zero));
    }

    #[test]
    fn known_retarget_results_match_core() {
        let mainnet = ChainParams::mainnet();

        // pow_tests.cpp: get_next_work (no clamping).
        let input = RetargetInput {
            height: 32_256,
            block_time: 1_262_152_739,
            last_time: 1_262_152_739,
            last_bits: 0x1d00_ffff,
            first_time: 1_261_130_161,
            first_bits: 0x1d00_ffff,
            last_non_min_bits: 0x1d00_ffff,
        };
        assert_eq!(next_work_required(&input, &mainnet), 0x1d00_d86a);
        assert_eq!(
            calculate_next_work_required(
                input.last_bits,
                input.first_time,
                input.last_time,
                input.first_bits,
                &mainnet,
            ),
            0x1d00_d86a
        );

        // pow_tests.cpp: get_next_work_pow_limit (clamped at pow limit).
        let input = RetargetInput {
            height: 2_016,
            block_time: 1_233_061_996,
            last_time: 1_233_061_996,
            last_bits: 0x1d00_ffff,
            first_time: 1_231_006_505,
            first_bits: 0x1d00_ffff,
            last_non_min_bits: 0x1d00_ffff,
        };
        assert_eq!(next_work_required(&input, &mainnet), 0x1d00_ffff);

        // pow_tests.cpp: get_next_work_lower_limit_actual.
        let input = RetargetInput {
            height: 68_544,
            block_time: 1_279_297_671,
            last_time: 1_279_297_671,
            last_bits: 0x1c05_a3f4,
            first_time: 1_279_008_237,
            first_bits: 0x1c05_a3f4,
            last_non_min_bits: 0x1c05_a3f4,
        };
        assert_eq!(next_work_required(&input, &mainnet), 0x1c01_68fd);

        // pow_tests.cpp: get_next_work_upper_limit_actual.
        let input = RetargetInput {
            height: 46_368,
            block_time: 1_269_211_443,
            last_time: 1_269_211_443,
            last_bits: 0x1c38_7f6f,
            first_time: 1_263_163_443,
            first_bits: 0x1c38_7f6f,
            last_non_min_bits: 0x1c38_7f6f,
        };
        assert_eq!(next_work_required(&input, &mainnet), 0x1d00_e1fd);

        // Between adjustment points the previous bits are carried over.
        let input = RetargetInput {
            height: 100,
            block_time: 1_231_200_000,
            last_time: 1_231_199_900,
            last_bits: 0x1d00_ffff,
            first_time: 1_231_006_505,
            first_bits: 0x1d00_ffff,
            last_non_min_bits: 0x1d00_ffff,
        };
        assert_eq!(next_work_required(&input, &mainnet), 0x1d00_ffff);
    }

    #[test]
    fn testnet_min_difficulty_blocks() {
        let testnet = ChainParams::testnet();
        assert!(testnet.allow_min_difficulty_blocks);

        let input = RetargetInput {
            height: 100,
            // More than 2 * target spacing after the previous block.
            block_time: 1_231_000_000 + 1_201,
            last_time: 1_231_000_000,
            last_bits: 0x1c05_a3f4,
            first_time: 1_230_000_000,
            first_bits: 0x1c05_a3f4,
            last_non_min_bits: 0x1c05_a3f4,
        };
        assert_eq!(next_work_required(&input, &testnet), 0x1d00_ffff);

        // Exactly 2 * spacing is not enough: the comparison is strict.
        let mut input = input;
        input.block_time = input.last_time + 1_200;
        assert_eq!(next_work_required(&input, &testnet), 0x1c05_a3f4);
    }

    #[test]
    fn subsidy_halves_at_known_heights() {
        let mainnet = ChainParams::mainnet();
        assert_eq!(mainnet.block_subsidy(0), 50 * COIN);
        assert_eq!(mainnet.block_subsidy(209_999), 50 * COIN);
        assert_eq!(mainnet.block_subsidy(210_000), 25 * COIN);
        assert_eq!(mainnet.block_subsidy(419_999), 25 * COIN);
        assert_eq!(mainnet.block_subsidy(420_000), 12 * COIN + 50_000_000);
        assert_eq!(mainnet.block_subsidy(630_000), 6 * COIN + 25_000_000);
        assert_eq!(mainnet.block_subsidy(840_000), 3 * COIN + 12_500_000);

        // 50 BTC >> 32 is 1 satoshi; the subsidy reaches zero at halving 33.
        assert_eq!(mainnet.block_subsidy(210_000 * 32), 1);
        assert_eq!(mainnet.block_subsidy(210_000 * 33), 0);
        assert_eq!(mainnet.block_subsidy(210_000 * 64), 0);

        // Regtest halves every 150 blocks.
        let regtest = ChainParams::regtest();
        assert_eq!(regtest.block_subsidy(149), 50 * COIN);
        assert_eq!(regtest.block_subsidy(150), 25 * COIN);
        assert_eq!(regtest.block_subsidy(300), 12 * COIN + 50_000_000);
    }

    #[test]
    fn work_and_chainwork_from_bits() {
        // pow_tests.cpp: GetBitsProof(0x1d00ffff) == 0x100010001.
        assert_eq!(
            work_from_bits(0x1d00_ffff).unwrap(),
            U256::from(0x1_0001_0001u64)
        );
        assert_eq!(
            chain_work([0x1d00_ffff, 0x1d00_ffff]).unwrap(),
            U256::from(0x2_0002_0002u64)
        );

        // 0x21012345 has an overflowing exponent and no work.
        assert!(work_from_bits(0x2101_2345).is_err());
    }
}
