//! Chain selection and consensus parameters.
//!
//! Ported from `kernel/chainparams.cpp`, `chainparamsbase.cpp` and
//! `consensus/params.h`. Only the parameters needed for proof-of-work and
//! subsidy calculations are modelled here.

use bitcoin::BlockHash;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

use crate::compact::encode_compact;
use crate::subsidy::block_subsidy;

/// Mainnet genesis block hash (`hashGenesisBlock`).
pub const MAINNET_GENESIS_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
/// Testnet3 genesis block hash.
pub const TESTNET_GENESIS_HASH: &str =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
/// Regtest genesis block hash.
pub const REGTEST_GENESIS_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

/// Mainnet/testnet proof-of-work limit.
pub const MAINNET_POW_LIMIT: &str =
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// Regtest proof-of-work limit.
pub const REGTEST_POW_LIMIT: &str =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// The chains for which parameters are provided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Main,
    Testnet,
    Regtest,
}

impl ChainType {
    /// The stable name used by Bitcoin Core (`-chain=`).
    pub const fn as_str(self) -> &'static str {
        match self {
            ChainType::Main => "main",
            ChainType::Testnet => "test",
            ChainType::Regtest => "regtest",
        }
    }

    /// Parse a Bitcoin Core chain name (`main`, `test`, `regtest`).
    pub fn for_chain_name(name: &str) -> Option<Self> {
        match name {
            "main" => Some(ChainType::Main),
            "test" | "testnet3" => Some(ChainType::Testnet),
            "regtest" => Some(ChainType::Regtest),
            _ => None,
        }
    }
}

/// Consensus parameters that influence proof of work, chain selection and the
/// block subsidy.
///
/// Field names follow the Bitcoin Core originals where practical.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainParams {
    /// Which network these parameters describe.
    pub chain_type: ChainType,
    /// Data directory name from `CreateBaseChainParams()` (empty for mainnet).
    pub data_dir: String,
    /// `pchMessageStart`: the four network magic bytes.
    pub magic: [u8; 4],
    /// `nDefaultPort`: default peer-to-peer port.
    pub default_port: u16,
    /// RPC port from `CreateBaseChainParams()`.
    pub rpc_port: u16,
    /// `hashGenesisBlock`.
    pub genesis_hash: BlockHash,
    /// `genesis.nBits`.
    pub genesis_bits: u32,
    /// `powLimit`, as a 256-bit target.
    pub pow_limit: U256,
    /// `nSubsidyHalvingInterval`.
    pub halving_interval: u32,
    /// `nPowTargetSpacing`, in seconds.
    pub target_spacing: i64,
    /// `nPowTargetTimespan`, in seconds.
    pub target_timespan: i64,
    /// `fPowAllowMinDifficultyBlocks` (testnet/regtest rule).
    pub allow_min_difficulty_blocks: bool,
    /// `fPowNoRetargeting` (regtest).
    pub no_retargeting: bool,
    /// `enforce_BIP94` (testnet4 timewarp mitigation; off for these chains).
    pub enforce_bip94: bool,
}

impl ChainParams {
    /// Mainnet parameters (`CMainParams`).
    pub fn mainnet() -> Self {
        Self {
            chain_type: ChainType::Main,
            data_dir: String::new(),
            magic: [0xf9, 0xbe, 0xb4, 0xd9],
            default_port: 8333,
            rpc_port: 8332,
            genesis_hash: parse_hash(MAINNET_GENESIS_HASH),
            genesis_bits: 0x1d00_ffff,
            pow_limit: parse_u256_be(MAINNET_POW_LIMIT),
            halving_interval: 210_000,
            target_spacing: 10 * 60,
            target_timespan: 14 * 24 * 60 * 60,
            allow_min_difficulty_blocks: false,
            no_retargeting: false,
            enforce_bip94: false,
        }
    }

    /// Testnet3 parameters (`CTestNetParams`).
    pub fn testnet() -> Self {
        Self {
            chain_type: ChainType::Testnet,
            data_dir: "testnet3".to_string(),
            magic: [0x0b, 0x11, 0x09, 0x07],
            default_port: 18333,
            rpc_port: 18332,
            genesis_hash: parse_hash(TESTNET_GENESIS_HASH),
            genesis_bits: 0x1d00_ffff,
            pow_limit: parse_u256_be(MAINNET_POW_LIMIT),
            halving_interval: 210_000,
            target_spacing: 10 * 60,
            target_timespan: 14 * 24 * 60 * 60,
            allow_min_difficulty_blocks: true,
            no_retargeting: false,
            enforce_bip94: false,
        }
    }

    /// Regtest parameters (`CRegTestParams`).
    pub fn regtest() -> Self {
        Self {
            chain_type: ChainType::Regtest,
            data_dir: "regtest".to_string(),
            magic: [0xfa, 0xbf, 0xb5, 0xda],
            default_port: 18444,
            rpc_port: 18443,
            genesis_hash: parse_hash(REGTEST_GENESIS_HASH),
            genesis_bits: 0x207f_ffff,
            pow_limit: parse_u256_be(REGTEST_POW_LIMIT),
            halving_interval: 150,
            target_spacing: 10 * 60,
            // One day, unlike mainnet/testnet's two weeks.
            target_timespan: 24 * 60 * 60,
            allow_min_difficulty_blocks: true,
            no_retargeting: true,
            enforce_bip94: false,
        }
    }

    /// Parameters for the requested chain.
    pub fn for_chain(chain: ChainType) -> Self {
        match chain {
            ChainType::Main => Self::mainnet(),
            ChainType::Testnet => Self::testnet(),
            ChainType::Regtest => Self::regtest(),
        }
    }

    /// `DifficultyAdjustmentInterval()`: the number of blocks between
    /// retargets (2016 on mainnet/testnet, 144 on regtest).
    pub fn difficulty_adjustment_interval(&self) -> i64 {
        self.target_timespan / self.target_spacing
    }

    /// `UintToArith256(powLimit).GetCompact()`.
    pub fn pow_limit_bits(&self) -> u32 {
        encode_compact(self.pow_limit)
    }

    /// Block subsidy at `height`, using this chain's halving interval.
    pub fn block_subsidy(&self, height: u32) -> i64 {
        block_subsidy(height, self.halving_interval)
    }
}

impl Default for ChainParams {
    fn default() -> Self {
        Self::mainnet()
    }
}

/// Parse a display-order (big-endian) block hash.
fn parse_hash(hex: &str) -> BlockHash {
    hex.parse().expect("hard-coded genesis hash is valid hex")
}

/// Parse a 32-byte big-endian hex integer into a `U256`.
fn parse_u256_be(hex: &str) -> U256 {
    assert_eq!(hex.len(), 64, "expected a 32-byte hex value");
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)
            .expect("hard-coded target is valid hex");
    }
    U256::from_big_endian(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_ports_and_magic() {
        let mainnet = ChainParams::mainnet();
        assert_eq!(mainnet.magic, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!((mainnet.default_port, mainnet.rpc_port), (8333, 8332));

        let testnet = ChainParams::testnet();
        assert_eq!(testnet.magic, [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!((testnet.default_port, testnet.rpc_port), (18333, 18332));

        let regtest = ChainParams::regtest();
        assert_eq!(regtest.magic, [0xfa, 0xbf, 0xb5, 0xda]);
        assert_eq!((regtest.default_port, regtest.rpc_port), (18444, 18443));

        assert_eq!(ChainType::for_chain_name("main"), Some(ChainType::Main));
        assert_eq!(mainnet.difficulty_adjustment_interval(), 2016);
        assert_eq!(regtest.difficulty_adjustment_interval(), 144);
    }
}
