//! Chain selection and consensus parameters.
//!
//! Ported from `kernel/chainparams.cpp`, `chainparamsbase.cpp` and
//! `consensus/params.h`. Only the parameters needed for proof-of-work and
//! subsidy calculations are modelled here.

use bitcoin::{BlockHash, ScriptBuf};
use btc_primitives::Block;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

use crate::compact::{decode_compact, encode_compact};
use crate::genesis::{create_genesis_block, mine_genesis};
use crate::subsidy::{block_subsidy, COIN};

/// Version used for custom genesis blocks (Core uses 1 for all chains).
const GENESIS_VERSION: i32 = 1;
/// `OP_RETURN`, used as the placeholder genesis output script of
/// [`CustomChainSpec::default`].
const OP_RETURN: u8 = 0x6a;

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

/// Version byte marking a confidential output script (see
/// `btc-chain::confidential`): scripts starting `OP_RETURN 0x01 ...`
/// carry a Pedersen commitment plus a range proof.
pub const CT_SCRIPT_VERSION: u8 = 0x01;

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
    /// Whether confidential outputs/transactions (Pedersen commitments +
    /// range and balance proofs, see `btc-chain::confidential`) are valid
    /// on this chain. Off for mainnet/testnet/regtest; on for AnonCoin.
    pub ct_enabled: bool,
    /// `enforce_BIP94` (testnet4 timewarp mitigation; off for these chains).
    pub enforce_bip94: bool,
    /// `bech32_hrp`: human-readable part for segwit/taproot addresses.
    pub bech32_hrp: String,
    /// `base58Prefixes[PUBKEY_ADDRESS]`.
    pub pubkey_address_prefix: u8,
    /// `base58Prefixes[SCRIPT_ADDRESS]`.
    pub script_address_prefix: u8,
    /// Buried deployment heights and script-flag exceptions.
    pub deployments: Deployments,
    /// `vSeeds`: DNS seeds or `host:port` bootstrap nodes.
    pub seeds: Vec<String>,
}

/// Buried soft-fork activation heights (`Consensus::Params`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployments {
    /// BIP34: coinbase must start with the block height.
    pub bip34_height: u32,
    /// BIP65: OP_CHECKLOCKTIMEVERIFY.
    pub bip65_height: u32,
    /// BIP66: strict DER signatures.
    pub bip66_height: u32,
    /// BIP68/112/113: relative lock-time (CSV).
    pub csv_height: u32,
    /// BIP141/143/147: SegWit.
    pub segwit_height: u32,
    /// `script_flag_exceptions`: block hash -> script verify flags bits.
    pub script_flag_exceptions: Vec<(BlockHash, u64)>,
}

impl Deployments {
    /// Every rule active from block 1 (regtest / new chains).
    pub fn all_active() -> Self {
        Self { bip34_height: 1, bip65_height: 1, bip66_height: 1, csv_height: 1, segwit_height: 0, script_flag_exceptions: Vec::new() }
    }
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
            ct_enabled: false,
            enforce_bip94: false,
            deployments: Deployments {
                bip34_height: 227_931,
                bip65_height: 388_381,
                bip66_height: 363_725,
                csv_height: 419_328,
                segwit_height: 481_824,
                script_flag_exceptions: vec![
                    // BIP16 exception: SCRIPT_VERIFY_NONE.
                    (parse_hash("00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"), 0),
                    // Taproot exception: P2SH | WITNESS.
                    (parse_hash("0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"), (1 << 0) | (1 << 11)),
                ],
            },
            bech32_hrp: "bc".to_string(),
            pubkey_address_prefix: 0,
            script_address_prefix: 5,
            seeds: [
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.net",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz",
                "seed.mainnet.achownodes.xyz",
            ]
            .map(String::from)
            .to_vec(),
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
            ct_enabled: false,
            enforce_bip94: false,
            deployments: Deployments {
                bip34_height: 21_111,
                bip65_height: 581_885,
                bip66_height: 330_776,
                csv_height: 770_112,
                segwit_height: 834_624,
                script_flag_exceptions: vec![
                    (parse_hash("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"), 0),
                ],
            },
            bech32_hrp: "tb".to_string(),
            pubkey_address_prefix: 111,
            script_address_prefix: 196,
            seeds: [
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.net",
                "seed.testnet.bitcoin.sprovoost.nl",
                "testnet-seed.bluematt.me",
            ]
            .map(String::from)
            .to_vec(),
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
            ct_enabled: false,
            enforce_bip94: false,
            deployments: Deployments::all_active(),
            bech32_hrp: "bcrt".to_string(),
            pubkey_address_prefix: 111,
            script_address_prefix: 196,
            seeds: Vec::new(),
        }
    }

    /// Parameters for a custom chain described by `spec`, together with its
    /// mined genesis block. `genesis_hash` is the hash of the returned block.
    ///
    /// `chain_type` is set to [`ChainType::Regtest`] because there is no custom
    /// variant; read behaviour from the individual fields, not from
    /// `chain_type`.
    ///
    /// # Panics
    ///
    /// Panics if the spec's genesis target is above its `pow_limit`, or does
    /// not decode (see [`mine_genesis`]).
    pub fn custom(spec: &CustomChainSpec) -> (Self, Block) {
        let mut block = create_genesis_block(
            &spec.genesis_timestamp,
            spec.genesis_output_script.clone(),
            spec.genesis_time,
            0,
            spec.genesis_bits,
            GENESIS_VERSION,
            spec.genesis_reward,
        );
        mine_genesis(&mut block, spec.pow_limit);

        let params = Self {
            chain_type: ChainType::Regtest,
            data_dir: spec.name.clone(),
            magic: spec.magic,
            default_port: spec.default_port,
            rpc_port: spec.rpc_port,
            genesis_hash: block.block_hash(),
            genesis_bits: block.header.bits,
            pow_limit: spec.pow_limit,
            halving_interval: spec.halving_interval,
            target_spacing: spec.target_spacing,
            target_timespan: spec.target_timespan,
            allow_min_difficulty_blocks: spec.allow_min_difficulty_blocks,
            no_retargeting: spec.no_retargeting,
            ct_enabled: spec.ct_enabled,
            enforce_bip94: false,
            deployments: Deployments::all_active(),
            bech32_hrp: spec.bech32_hrp.clone(),
            pubkey_address_prefix: spec.pubkey_address_prefix,
            script_address_prefix: spec.script_address_prefix,
            seeds: spec.seeds.clone(),
        };
        (params, block)
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

/// Everything needed to define a new chain: network identity, genesis block
/// inputs and consensus parameters. Pass it to [`ChainParams::custom`].
///
/// The [`Default`] values are placeholders for a new coin; change the magic,
/// ports, genesis message and address prefixes before launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomChainSpec {
    /// Name, used as the data directory.
    pub name: String,
    /// `pchMessageStart`.
    pub magic: [u8; 4],
    /// Default peer-to-peer port.
    pub default_port: u16,
    /// RPC port.
    pub rpc_port: u16,
    /// Message embedded in the genesis coinbase.
    pub genesis_timestamp: String,
    /// `scriptPubKey` of the genesis coinbase output.
    pub genesis_output_script: ScriptBuf,
    /// Genesis header `nTime`. May be bumped while mining.
    pub genesis_time: u32,
    /// Genesis header `nBits`; also the easiest allowed target when it equals
    /// `pow_limit`.
    pub genesis_bits: u32,
    /// Genesis coinbase value, in satoshis.
    pub genesis_reward: i64,
    /// `nSubsidyHalvingInterval`.
    pub halving_interval: u32,
    /// `nPowTargetSpacing`, in seconds.
    pub target_spacing: i64,
    /// `nPowTargetTimespan`, in seconds.
    pub target_timespan: i64,
    /// `powLimit`, as a 256-bit target.
    pub pow_limit: U256,
    /// `fPowAllowMinDifficultyBlocks`.
    pub allow_min_difficulty_blocks: bool,
    /// `fPowNoRetargeting`.
    pub no_retargeting: bool,
    /// Whether confidential outputs/transactions are valid on this chain.
    pub ct_enabled: bool,
    /// `bech32_hrp`.
    pub bech32_hrp: String,
    /// `base58Prefixes[PUBKEY_ADDRESS]`.
    pub pubkey_address_prefix: u8,
    /// `base58Prefixes[SCRIPT_ADDRESS]`.
    pub script_address_prefix: u8,
    /// `vSeeds`: DNS seeds or `host:port` bootstrap nodes.
    pub seeds: Vec<String>,
}

impl Default for CustomChainSpec {
    fn default() -> Self {
        // 0x1e00ffff: ~16.7M expected hashes per block (256x harder than the
        // old 0x1f00ffff placeholder). At ~150k-440k H/s on one CPU core this
        // is roughly 40-110 s per block, and retargeting every 2016 blocks
        // towards 600 s spacing with pow_limit == genesis target means the
        // difficulty can only ever get harder than this, never easier.
        let genesis_bits = 0x1e00_ffff;
        Self {
            name: "AnonCoin".to_string(),
            magic: [0x5f, 0x4c, 0x7e, 0xa1],
            default_port: 18555,
            rpc_port: 18556,
            genesis_timestamp: "AnonCoin genesis".to_string(),
            // Provably unspendable placeholder.
            genesis_output_script: ScriptBuf::from_bytes(vec![OP_RETURN]),
            // 2026-01-01T00:00:00Z.
            genesis_time: 1_767_225_600,
            genesis_bits,
            genesis_reward: 50 * COIN,
            halving_interval: 210_000,
            target_spacing: 10 * 60,
            target_timespan: 14 * 24 * 60 * 60,
            pow_limit: decode_compact(genesis_bits).expect("hard-coded bits are valid"),
            allow_min_difficulty_blocks: false,
            no_retargeting: false,
            ct_enabled: true,
            bech32_hrp: "an".to_string(),
            pubkey_address_prefix: 65,
            script_address_prefix: 10,
            seeds: Vec::new(),
        }
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
    use bitcoin_hashes::Hash;

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

    #[test]
    fn address_prefixes() {
        let mainnet = ChainParams::mainnet();
        assert_eq!(
            (
                mainnet.bech32_hrp.as_str(),
                mainnet.pubkey_address_prefix,
                mainnet.script_address_prefix
            ),
            ("bc", 0, 5)
        );
        let testnet = ChainParams::testnet();
        assert_eq!(
            (
                testnet.bech32_hrp.as_str(),
                testnet.pubkey_address_prefix,
                testnet.script_address_prefix
            ),
            ("tb", 111, 196)
        );
        let regtest = ChainParams::regtest();
        assert_eq!(
            (
                regtest.bech32_hrp.as_str(),
                regtest.pubkey_address_prefix,
                regtest.script_address_prefix
            ),
            ("bcrt", 111, 196)
        );
    }

    /// Difficulty of the default custom chain, without mining: ~16.7M
    /// expected hashes per block, 600 s spacing, retarget every 2016 blocks.
    #[test]
    fn default_spec_is_hard_by_default() {
        let spec = CustomChainSpec::default();
        assert_eq!(spec.genesis_bits, 0x1e00_ffff);
        assert_eq!(spec.pow_limit, decode_compact(0x1e00_ffff).unwrap());
        assert_eq!(spec.target_spacing, 600);
        assert_eq!(spec.target_timespan, 14 * 24 * 60 * 60);
        assert_eq!(spec.target_timespan / spec.target_spacing, 2016);
        assert!(!spec.allow_min_difficulty_blocks);
        assert!(!spec.no_retargeting);
        assert!(spec.ct_enabled);
    }

    #[test]
    fn custom_params_match_returned_genesis() {
        // Easy bits so the test does not mine the (now hard) default genesis.
        let regtest_limit = decode_compact(0x207f_ffff).unwrap();
        let spec = CustomChainSpec {
            genesis_bits: 0x207f_ffff,
            pow_limit: regtest_limit,
            ..CustomChainSpec::default()
        };
        let (params, block) = ChainParams::custom(&spec);

        assert_eq!(params.genesis_hash, block.block_hash());
        assert_eq!(params.genesis_bits, block.header.bits);
        assert_eq!(params.data_dir, spec.name);
        assert_eq!(params.magic, spec.magic);
        assert_eq!(
            (params.default_port, params.rpc_port),
            (spec.default_port, spec.rpc_port)
        );
        assert_eq!(params.pow_limit, spec.pow_limit);
        assert_eq!(params.pow_limit_bits(), 0x207f_ffff);
        assert_eq!(params.halving_interval, spec.halving_interval);
        assert_eq!(params.target_spacing, 600);
        assert_eq!(params.difficulty_adjustment_interval(), 2016);
        assert_eq!(params.bech32_hrp, spec.bech32_hrp);
        assert_eq!(params.pubkey_address_prefix, spec.pubkey_address_prefix);
        assert_eq!(params.script_address_prefix, spec.script_address_prefix);

        // The genesis hash must satisfy the target it was mined against.
        let target = decode_compact(block.header.bits).unwrap();
        assert!(U256::from_little_endian(&block.block_hash().to_byte_array()) <= target);
        assert_eq!(block.txdata[0].vout[0].value, spec.genesis_reward);
    }

    #[test]
    fn custom_genesis_with_easy_bits_mines_quickly() {
        let regtest_limit = decode_compact(0x207f_ffff).unwrap();
        let spec = CustomChainSpec {
            genesis_bits: 0x207f_ffff,
            pow_limit: regtest_limit,
            ..CustomChainSpec::default()
        };
        let (params, block) = ChainParams::custom(&spec);

        assert_eq!(params.genesis_bits, 0x207f_ffff);
        assert_eq!(params.genesis_hash, block.block_hash());
        assert!(
            U256::from_little_endian(&block.block_hash().to_byte_array())
                <= decode_compact(0x207f_ffff).unwrap()
        );
    }
}
