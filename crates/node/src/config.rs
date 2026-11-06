//! Startup configuration. Port of the chain/datadir/port argument handling in src/init.cpp and src/common/args.cpp.
//!
//! Arguments use Bitcoin Core's syntax: `-name=value` for values and `-name`
//! for boolean flags. Core also accepts `--name`, which is accepted here too.

use std::env;
use std::path::PathBuf;

use btc_consensus::{ChainParams, ChainType};
use thiserror::Error;

/// Resolved startup configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    /// Selected network (`-chain=`).
    pub chain: ChainType,
    /// Network-specific data directory: the base `-datadir` (or the platform
    /// default) plus the chain subdirectory (`testnet3`, `regtest`), matching
    /// `ArgsManager::GetDataDirNet()`.
    pub datadir: PathBuf,
    /// Peer-to-peer port (`-port=`), defaulting to the chain's `nDefaultPort`.
    pub p2p_port: u16,
    /// JSON-RPC port (`-rpcport=`), defaulting to the chain's RPC port.
    pub rpc_port: u16,
    /// Accept inbound connections (`-listen=0|1`, default on).
    pub listen: bool,
    /// Run in the background (`-daemon`, default off).
    pub daemon: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("unknown option: {0}")]
    UnknownOption(String),
    #[error("unexpected argument: {0} (options must start with '-')")]
    UnexpectedArgument(String),
    #[error("option -{name} requires a value (use -{name}=<value>)")]
    MissingValue { name: &'static str },
    #[error("invalid value for -{name}: {value:?}")]
    InvalidValue { name: &'static str, value: String },
    #[error("unsupported chain {0:?} (expected main, test or regtest)")]
    UnsupportedChain(String),
    #[error("cannot determine a default data directory (APPDATA and HOME are unset); pass -datadir=<dir>")]
    NoDefaultDatadir,
}

/// Parse command-line arguments (without the program name) into a [`NodeConfig`].
///
/// Options may appear in any order. Repeated options take the last value.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<NodeConfig, ConfigError> {
    let mut chain: Option<ChainType> = None;
    let mut datadir: Option<PathBuf> = None;
    let mut p2p_port: Option<u16> = None;
    let mut rpc_port: Option<u16> = None;
    let mut listen = true;
    let mut daemon = false;

    for arg in args {
        let body = match arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) {
            Some(body) => body,
            None => return Err(ConfigError::UnexpectedArgument(arg.to_string())),
        };
        let (name, value) = match body.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (body, None),
        };

        match name {
            "chain" => {
                let value = required("chain", value)?;
                chain = Some(
                    ChainType::for_chain_name(value)
                        .ok_or_else(|| ConfigError::UnsupportedChain(value.to_string()))?,
                );
            }
            "datadir" => datadir = Some(PathBuf::from(required("datadir", value)?)),
            "port" => p2p_port = Some(parse_port("port", value)?),
            "rpcport" => rpc_port = Some(parse_port("rpcport", value)?),
            "listen" => listen = parse_bool("listen", value)?,
            "daemon" => daemon = parse_bool("daemon", value)?,
            _ => return Err(ConfigError::UnknownOption(arg.to_string())),
        }
    }

    // Defaults depend on the chain, and -chain may come after -port, so
    // resolve them only once every argument has been read.
    let chain = chain.unwrap_or(ChainType::Main);
    let params = ChainParams::for_chain(chain);
    let base = match datadir {
        Some(dir) => dir,
        None => default_datadir()?,
    };
    // Mainnet has an empty data_dir subdirectory, so its path is used as-is.
    let datadir = if params.data_dir.is_empty() {
        base
    } else {
        base.join(&params.data_dir)
    };

    Ok(NodeConfig {
        chain,
        datadir,
        p2p_port: p2p_port.unwrap_or(params.default_port),
        rpc_port: rpc_port.unwrap_or(params.rpc_port),
        listen,
        daemon,
    })
}

/// Base data directory used when `-datadir` is absent.
///
/// Windows: `%APPDATA%\Bitcoin-rust`. Elsewhere, or when APPDATA is unset:
/// `~/.bitcoin-rust`, using HOME or USERPROFILE for the home directory.
fn default_datadir() -> Result<PathBuf, ConfigError> {
    if cfg!(windows) {
        if let Some(appdata) = env::var_os("APPDATA") {
            return Ok(PathBuf::from(appdata).join("Bitcoin-rust"));
        }
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .ok_or(ConfigError::NoDefaultDatadir)?;
    Ok(PathBuf::from(home).join(".bitcoin-rust"))
}

/// Require a non-empty value for an option that takes one.
fn required<'a>(name: &'static str, value: Option<&'a str>) -> Result<&'a str, ConfigError> {
    match value {
        Some("") => Err(ConfigError::InvalidValue {
            name,
            value: String::new(),
        }),
        Some(value) => Ok(value),
        None => Err(ConfigError::MissingValue { name }),
    }
}

/// Parse a TCP port. Port 0 is rejected because the node must advertise a
/// fixed port to peers.
fn parse_port(name: &'static str, value: Option<&str>) -> Result<u16, ConfigError> {
    let value = required(name, value)?;
    match value.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(ConfigError::InvalidValue {
            name,
            value: value.to_string(),
        }),
    }
}

/// Parse a boolean flag. A bare `-name` means true, as in Core. Only `0` and
/// `1` are accepted as explicit values; Core would treat any nonzero integer
/// as true, but that hides typos.
fn parse_bool(name: &'static str, value: Option<&str>) -> Result<bool, ConfigError> {
    match value {
        None | Some("1") => Ok(true),
        Some("0") => Ok(false),
        Some(other) => Err(ConfigError::InvalidValue {
            name,
            value: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_datadir() -> PathBuf {
        env::temp_dir().join("btc-node-test")
    }

    /// Parse with an explicit `-datadir` so tests do not depend on the
    /// environment, followed by `extra`.
    fn parse(extra: &[&str]) -> Result<NodeConfig, ConfigError> {
        let mut args = vec![format!("-datadir={}", test_datadir().display())];
        args.extend(extra.iter().map(|s| s.to_string()));
        parse_args(args)
    }

    #[test]
    fn defaults_are_mainnet() {
        let config = parse(&[]).unwrap();
        assert_eq!(config.chain, ChainType::Main);
        // Mainnet has no chain subdirectory.
        assert_eq!(config.datadir, test_datadir());
        assert_eq!((config.p2p_port, config.rpc_port), (8333, 8332));
        assert!(config.listen);
        assert!(!config.daemon);
    }

    #[test]
    fn chain_test_uses_testnet_subdir_and_ports() {
        let config = parse(&["-chain=test"]).unwrap();
        assert_eq!(config.chain, ChainType::Testnet);
        assert_eq!(config.datadir, test_datadir().join("testnet3"));
        assert_eq!((config.p2p_port, config.rpc_port), (18333, 18332));

        let regtest = parse(&["-chain=regtest"]).unwrap();
        assert_eq!(regtest.datadir, test_datadir().join("regtest"));
        assert_eq!((regtest.p2p_port, regtest.rpc_port), (18444, 18443));
    }

    #[test]
    fn port_listen_and_daemon_overrides() {
        // -chain comes after -port to check that the chain default does not
        // overwrite an explicit port.
        let config = parse(&[
            "-port=19000",
            "-rpcport=19001",
            "-chain=regtest",
            "-listen=0",
            "-daemon",
        ])
        .unwrap();
        assert_eq!((config.p2p_port, config.rpc_port), (19000, 19001));
        assert!(!config.listen);
        assert!(config.daemon);

        // The double-dash form and an explicit -daemon=0 are also accepted.
        let config = parse(&["--port=20000", "-daemon=0", "-listen=1"]).unwrap();
        assert_eq!(config.p2p_port, 20000);
        assert!(!config.daemon);
        assert!(config.listen);
    }

    #[test]
    fn rejects_unknown_and_invalid_options() {
        assert_eq!(
            parse(&["--help"]),
            Err(ConfigError::UnknownOption("--help".to_string()))
        );
        assert_eq!(
            parse(&["-nosuchoption=1"]),
            Err(ConfigError::UnknownOption("-nosuchoption=1".to_string()))
        );
        assert_eq!(
            parse(&["positional"]),
            Err(ConfigError::UnexpectedArgument("positional".to_string()))
        );
        assert!(matches!(
            parse(&["-chain=signet"]),
            Err(ConfigError::UnsupportedChain(_))
        ));
        assert!(matches!(
            parse(&["-port=0"]),
            Err(ConfigError::InvalidValue { name: "port", .. })
        ));
        assert!(matches!(
            parse(&["-listen=2"]),
            Err(ConfigError::InvalidValue { name: "listen", .. })
        ));
        assert!(matches!(
            parse(&["-rpcport"]),
            Err(ConfigError::MissingValue { name: "rpcport" })
        ));
    }
}
