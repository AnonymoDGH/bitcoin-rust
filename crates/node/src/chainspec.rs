//! Custom chain specification files (`-chainspec=<path>`).
//!
//! A JSON file describes a new coin. Fields that are absent keep the values of
//! [`CustomChainSpec::default`]; unknown fields are rejected so typos do not
//! go unnoticed.

use std::path::Path;

use bitcoin::hex::{DisplayHex, FromHex};
use btc_consensus::{decode_compact, CustomChainSpec};
use btc_primitives::ScriptBuf;
use primitive_types::U256;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainSpecError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid chain spec JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid chain spec field `{field}`: {reason}")]
    Field { field: &'static str, reason: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecFile {
    name: Option<String>,
    magic: Option<String>,
    default_port: Option<u16>,
    rpc_port: Option<u16>,
    genesis_timestamp: Option<String>,
    genesis_output_script: Option<String>,
    genesis_time: Option<u32>,
    genesis_bits: Option<Bits>,
    genesis_reward: Option<i64>,
    halving_interval: Option<u32>,
    target_spacing: Option<i64>,
    target_timespan: Option<i64>,
    pow_limit: Option<String>,
    allow_min_difficulty_blocks: Option<bool>,
    no_retargeting: Option<bool>,
    ct_enabled: Option<bool>,
    bech32_hrp: Option<String>,
    pubkey_address_prefix: Option<u8>,
    script_address_prefix: Option<u8>,
    seeds: Option<Vec<String>>,
}

/// `genesis_bits` as either a JSON number or a hex string (`"1f00ffff"`).
#[derive(Deserialize)]
#[serde(untagged)]
enum Bits {
    Number(u32),
    Hex(String),
}

/// Reads and validates a chain spec file.
pub fn load_chain_spec(path: &Path) -> Result<CustomChainSpec, ChainSpecError> {
    let text = std::fs::read_to_string(path).map_err(|source| ChainSpecError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_chain_spec(&text)
}

/// Parses and validates chain spec JSON.
pub fn parse_chain_spec(json: &str) -> Result<CustomChainSpec, ChainSpecError> {
    let file: SpecFile = serde_json::from_str(json)?;
    let mut spec = CustomChainSpec::default();

    if let Some(name) = file.name {
        spec.name = name;
    }
    if let Some(hex) = file.magic {
        let bytes = field_bytes("magic", &hex)?;
        spec.magic = bytes
            .try_into()
            .map_err(|_| field_err("magic", "expected 4 bytes"))?;
    }
    if let Some(port) = file.default_port {
        spec.default_port = port;
    }
    if let Some(port) = file.rpc_port {
        spec.rpc_port = port;
    }
    if let Some(text) = file.genesis_timestamp {
        spec.genesis_timestamp = text;
    }
    if let Some(hex) = file.genesis_output_script {
        spec.genesis_output_script =
            ScriptBuf::from_bytes(field_bytes("genesis_output_script", &hex)?);
    }
    if let Some(time) = file.genesis_time {
        spec.genesis_time = time;
    }
    if let Some(bits) = file.genesis_bits {
        spec.genesis_bits = match bits {
            Bits::Number(bits) => bits,
            Bits::Hex(hex) => u32::from_str_radix(hex.trim_start_matches("0x"), 16)
                .map_err(|_| field_err("genesis_bits", "expected hex or a number"))?,
        };
    }
    if let Some(reward) = file.genesis_reward {
        spec.genesis_reward = reward;
    }
    if let Some(interval) = file.halving_interval {
        spec.halving_interval = interval;
    }
    if let Some(spacing) = file.target_spacing {
        spec.target_spacing = spacing;
    }
    if let Some(timespan) = file.target_timespan {
        spec.target_timespan = timespan;
    }
    if let Some(hex) = file.pow_limit {
        spec.pow_limit = field_u256("pow_limit", &hex)?;
    }
    if let Some(flag) = file.allow_min_difficulty_blocks {
        spec.allow_min_difficulty_blocks = flag;
    }
    if let Some(flag) = file.no_retargeting {
        spec.no_retargeting = flag;
    }
    if let Some(flag) = file.ct_enabled {
        spec.ct_enabled = flag;
    }
    if let Some(hrp) = file.bech32_hrp {
        spec.bech32_hrp = hrp;
    }
    if let Some(prefix) = file.pubkey_address_prefix {
        spec.pubkey_address_prefix = prefix;
    }
    if let Some(prefix) = file.script_address_prefix {
        spec.script_address_prefix = prefix;
    }
    if let Some(seeds) = file.seeds {
        if seeds.iter().any(|seed| seed.is_empty() || seed.contains(char::is_whitespace)) {
            return Err(field_err("seeds", "entries must be host names or host:port"));
        }
        spec.seeds = seeds;
    }

    validate(&spec)?;
    Ok(spec)
}

/// A complete spec with every field set, for `-printchainspec`.
pub fn example_spec_json() -> String {
    let spec = CustomChainSpec::default();
    let value = serde_json::json!({
        "name": spec.name,
        "magic": spec.magic.to_lower_hex_string(),
        "default_port": spec.default_port,
        "rpc_port": spec.rpc_port,
        "genesis_timestamp": spec.genesis_timestamp,
        "genesis_output_script": spec.genesis_output_script.as_bytes().to_lower_hex_string(),
        "genesis_time": spec.genesis_time,
        "genesis_bits": format!("{:08x}", spec.genesis_bits),
        "genesis_reward": spec.genesis_reward,
        "halving_interval": spec.halving_interval,
        "target_spacing": spec.target_spacing,
        "target_timespan": spec.target_timespan,
        "pow_limit": spec.pow_limit.to_big_endian().to_lower_hex_string(),
        "allow_min_difficulty_blocks": spec.allow_min_difficulty_blocks,
        "no_retargeting": spec.no_retargeting,
        "ct_enabled": spec.ct_enabled,
        "bech32_hrp": spec.bech32_hrp,
        "pubkey_address_prefix": spec.pubkey_address_prefix,
        "script_address_prefix": spec.script_address_prefix,
        "seeds": spec.seeds,
    });
    serde_json::to_string_pretty(&value).expect("a JSON value always serializes")
}

/// Checks the invariants `ChainParams::custom` and the difficulty code rely on,
/// so a bad file is reported instead of panicking at startup.
fn validate(spec: &CustomChainSpec) -> Result<(), ChainSpecError> {
    let valid_name = !spec.name.is_empty()
        && spec
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid_name {
        return Err(field_err(
            "name",
            "use only ASCII letters, digits, '-' and '_'",
        ));
    }
    let target = decode_compact(spec.genesis_bits)
        .map_err(|_| field_err("genesis_bits", "not a valid compact target"))?;
    if target > spec.pow_limit {
        return Err(field_err("genesis_bits", "target is above pow_limit"));
    }
    if spec.target_spacing <= 0 {
        return Err(field_err("target_spacing", "must be positive"));
    }
    if spec.target_timespan < spec.target_spacing {
        return Err(field_err(
            "target_timespan",
            "must be at least target_spacing",
        ));
    }
    if spec.halving_interval == 0 {
        return Err(field_err("halving_interval", "must be positive"));
    }
    if !(0..=btc_consensus::MAX_MONEY).contains(&spec.genesis_reward) {
        return Err(field_err("genesis_reward", "outside the money range"));
    }
    Ok(())
}

fn field_err(field: &'static str, reason: &str) -> ChainSpecError {
    ChainSpecError::Field {
        field,
        reason: reason.to_owned(),
    }
}

fn field_bytes(field: &'static str, hex: &str) -> Result<Vec<u8>, ChainSpecError> {
    Vec::<u8>::from_hex(hex).map_err(|err| field_err(field, &format!("invalid hex: {err}")))
}

fn field_u256(field: &'static str, hex: &str) -> Result<U256, ChainSpecError> {
    let bytes = field_bytes(field, hex)?;
    if bytes.len() != 32 {
        return Err(field_err(field, "expected 64 hex digits"));
    }
    Ok(U256::from_big_endian(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::Hash;
    use btc_consensus::ChainParams;

    const REGTEST_LIMIT: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn example_round_trips_to_default() {
        let parsed = parse_chain_spec(&example_spec_json()).unwrap();
        assert_eq!(parsed, CustomChainSpec::default());
    }

    #[test]
    fn missing_fields_keep_defaults() {
        let spec = parse_chain_spec(r#"{"name": "mycoin", "rpc_port": 9999}"#).unwrap();
        let default = CustomChainSpec::default();
        assert_eq!(spec.name, "mycoin");
        assert_eq!(spec.rpc_port, 9999);
        assert_eq!(spec.magic, default.magic);
        assert_eq!(spec.genesis_bits, default.genesis_bits);
        assert_eq!(spec.pow_limit, default.pow_limit);
    }

    #[test]
    fn parses_hex_and_numeric_fields() {
        let spec = parse_chain_spec(&format!(
            r#"{{"magic": "f9beb4d9", "genesis_bits": "207fffff", "pow_limit": "{REGTEST_LIMIT}",
                "genesis_output_script": "6a", "pubkey_address_prefix": 30}}"#
        ))
        .unwrap();
        assert_eq!(spec.magic, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(spec.genesis_bits, 0x207f_ffff);
        assert_eq!(spec.pow_limit, ChainParams::regtest().pow_limit);
        assert_eq!(spec.genesis_output_script.as_bytes(), &[0x6a]);
        assert_eq!(spec.pubkey_address_prefix, 30);

        let numeric = parse_chain_spec(&format!(
            r#"{{"genesis_bits": 545259519, "pow_limit": "{REGTEST_LIMIT}"}}"#
        ))
        .unwrap();
        assert_eq!(numeric.genesis_bits, 0x207f_ffff);
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        assert!(matches!(
            parse_chain_spec(r#"{"nmae": "typo"}"#),
            Err(ChainSpecError::Json(_))
        ));
        assert!(matches!(
            parse_chain_spec(r#"{"magic": "f9beb4"}"#),
            Err(ChainSpecError::Field { field: "magic", .. })
        ));
        assert!(matches!(
            parse_chain_spec(r#"{"pow_limit": "00ff"}"#),
            Err(ChainSpecError::Field {
                field: "pow_limit",
                ..
            })
        ));
        assert!(matches!(
            parse_chain_spec(r#"{"name": "bad/name"}"#),
            Err(ChainSpecError::Field { field: "name", .. })
        ));
        assert!(matches!(
            parse_chain_spec(&format!(
                r#"{{"genesis_bits": "1f00ffff", "pow_limit": "{}"}}"#,
                "00".repeat(32)
            )),
            Err(ChainSpecError::Field {
                field: "genesis_bits",
                ..
            })
        ));
        assert!(matches!(
            parse_chain_spec(r#"{"target_spacing": 0}"#),
            Err(ChainSpecError::Field {
                field: "target_spacing",
                ..
            })
        ));
    }

    #[test]
    fn parses_seed_list() {
        let spec = parse_chain_spec(r#"{"seeds": ["seed.example.org", "10.1.2.3:18555"]}"#).unwrap();
        assert_eq!(spec.seeds, vec!["seed.example.org", "10.1.2.3:18555"]);
        assert!(matches!(
            parse_chain_spec(r#"{"seeds": [""]}"#),
            Err(ChainSpecError::Field { field: "seeds", .. })
        ));
        assert!(matches!(
            parse_chain_spec(r#"{"seeds": ["bad host"]}"#),
            Err(ChainSpecError::Field { field: "seeds", .. })
        ));
    }

    #[test]
    fn shipped_presets_are_hard_and_valid() {
        // Parse-only: mining bitcoin-level genesis would take hours, so these
        // tests validate the files without calling ChainParams::custom.
        let hard = parse_chain_spec(include_str!("../../../chains/anoncoin.json")).unwrap();
        assert_eq!(hard.name, "AnonCoin");
        assert_eq!(hard.bech32_hrp, "an");
        assert_eq!(hard.genesis_bits, 0x1e00_ffff);
        assert_eq!(hard.pow_limit, decode_compact(0x1e00_ffff).unwrap());
        assert_eq!(hard.target_spacing, 600);
        assert_eq!(hard.target_timespan / hard.target_spacing, 2016);
        assert!(!hard.allow_min_difficulty_blocks);

        let level =
            parse_chain_spec(include_str!("../../../chains/satoshibtc.json")).unwrap();
        assert_eq!(level.genesis_bits, 0x1d00_ffff);
        assert_eq!(level.pow_limit, decode_compact(0x1d00_ffff).unwrap());
        assert_eq!(level.target_spacing, 600);
        assert!(!level.allow_min_difficulty_blocks);

        // The default spec matches the hard preset; both are strictly
        // easier than bitcoin-level.
        let default = CustomChainSpec::default();
        assert_eq!(default.genesis_bits, hard.genesis_bits);
        assert!(default.pow_limit > level.pow_limit);
    }

    #[test]
    fn custom_params_mine_a_valid_genesis() {
        let spec = parse_chain_spec(&format!(
            r#"{{"name": "easycoin", "genesis_bits": "207fffff", "pow_limit": "{REGTEST_LIMIT}"}}"#
        ))
        .unwrap();
        let (params, block) = ChainParams::custom(&spec);

        assert_eq!(params.data_dir, "easycoin");
        assert_eq!(params.genesis_hash, block.block_hash());
        let target = decode_compact(block.header.bits).unwrap();
        let hash = U256::from_little_endian(&block.block_hash().to_byte_array());
        assert!(hash <= target);
    }
}
