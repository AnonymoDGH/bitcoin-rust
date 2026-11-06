//! Startup configuration. Port of the chain/datadir/port argument handling in src/init.cpp and src/common/args.cpp.
//!
//! Arguments use Bitcoin Core's syntax: `-name=value` for values and `-name`
//! for boolean flags. Core also accepts `--name`, which is accepted here too.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use btc_consensus::{ChainParams, ChainType, CustomChainSpec};
use thiserror::Error;

use crate::chainspec::load_chain_spec;

/// Core's default `-maxconnections`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 125;

/// Resolved startup configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeConfig {
    /// Selected network (`-chain=`). A custom coin (`-chainspec`) uses
    /// `Regtest`, the chain type `ChainParams::custom` produces.
    pub chain: ChainType,
    /// Network-specific data directory: the base `-datadir` (or the platform
    /// default) plus the chain subdirectory (`testnet3`, `regtest`, or the
    /// coin's name), matching `ArgsManager::GetDataDirNet()`.
    pub datadir: PathBuf,
    /// Peer-to-peer port (`-port=`), defaulting to the chain's `nDefaultPort`.
    pub p2p_port: u16,
    /// JSON-RPC port (`-rpcport=`), defaulting to the chain's RPC port.
    pub rpc_port: u16,
    /// Accept inbound connections (`-listen=0|1`, default on).
    pub listen: bool,
    /// Run in the background (`-daemon`, default off).
    pub daemon: bool,
    /// Custom coin loaded from `-chainspec=<path>`, replacing `chain`.
    pub custom_chain: Option<CustomChainSpec>,
    /// `-rpcuser`. Cookie authentication is used when unset.
    pub rpc_user: Option<String>,
    /// `-rpcpassword`, required with `-rpcuser`.
    pub rpc_password: Option<String>,
    /// Address the RPC server binds to (`-rpcbind=`, default 127.0.0.1).
    pub rpc_bind: IpAddr,
    /// Peers from `-connect=<ip:port>`, repeatable.
    pub connect: Vec<SocketAddr>,
    /// Peers from `-addnode=<ip:port>`, repeatable. Kept connected alongside automatic outbound peers.
    pub add_nodes: Vec<SocketAddr>,
    /// Peers from `-seednode=<ip:port>`, repeatable. Asked for addresses once, then disconnected.
    pub seed_nodes: Vec<SocketAddr>,
    /// Resolve the chain's DNS seeds while the address table is empty (`-dnsseed=0|1`, default on).
    pub dns_seed: bool,
    /// Address to advertise to peers (`-externalip=<ip>`), with the p2p port.
    pub external_ip: Option<IpAddr>,
    /// Connection limit (`-maxconnections=<n>`, default 125). Eight of these are outbound.
    pub max_connections: usize,
    /// Wallet file name inside the datadir (`-wallet=<name>`, default `wallet.json`).
    pub wallet: String,
    /// Run without a wallet (`-disablewallet`).
    pub disable_wallet: bool,
    /// Mine blocks in the background (`-gen`).
    pub generate: bool,
    /// Address or script hex that mined blocks pay to (`-genaddress=`).
    pub gen_address: Option<String>,
    /// Seconds between `-gen` blocks (`-blockinterval=`). Defaults to the
    /// chain's `target_spacing` (600 s).
    pub block_interval: Option<u64>,
    /// Print an example chain spec and exit (`-printchainspec`).
    pub print_chainspec: bool,
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
    #[error("cannot load -chainspec: {0}")]
    ChainSpec(String),
    #[error("-{first} cannot be combined with -{second}")]
    Conflict {
        first: &'static str,
        second: &'static str,
    },
    #[error("-{option} requires -{requires}")]
    Requires {
        option: &'static str,
        requires: &'static str,
    },
}

/// Parse command-line arguments (without the program name) into a [`NodeConfig`].
///
/// Options may appear in any order. Repeated options take the last value,
/// except `-connect`, which accumulates.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<NodeConfig, ConfigError> {
    let mut chain: Option<ChainType> = None;
    let mut datadir: Option<PathBuf> = None;
    let mut p2p_port: Option<u16> = None;
    let mut rpc_port: Option<u16> = None;
    let mut listen = true;
    let mut daemon = false;
    let mut chainspec: Option<PathBuf> = None;
    let mut rpc_user: Option<String> = None;
    let mut rpc_password: Option<String> = None;
    let mut rpc_bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut connect = Vec::new();
    let mut add_nodes = Vec::new();
    let mut seed_nodes = Vec::new();
    let mut dns_seed = true;
    let mut external_ip: Option<IpAddr> = None;
    let mut max_connections = DEFAULT_MAX_CONNECTIONS;
    let mut wallet = "wallet.json".to_owned();
    let mut disable_wallet = false;
    let mut generate = false;
    let mut gen_address: Option<String> = None;
    let mut block_interval: Option<u64> = None;
    let mut print_chainspec = false;

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
            "chainspec" => chainspec = Some(PathBuf::from(required("chainspec", value)?)),
            "rpcuser" => rpc_user = Some(required("rpcuser", value)?.to_owned()),
            "rpcpassword" => rpc_password = Some(required("rpcpassword", value)?.to_owned()),
            "rpcbind" => rpc_bind = parse_value("rpcbind", value)?,
            "connect" => connect.push(parse_value("connect", value)?),
            "addnode" => add_nodes.push(parse_value("addnode", value)?),
            "seednode" => seed_nodes.push(parse_value("seednode", value)?),
            "dnsseed" => dns_seed = parse_bool("dnsseed", value)?,
            "externalip" => external_ip = Some(parse_value("externalip", value)?),
            "maxconnections" => max_connections = parse_value("maxconnections", value)?,
            "wallet" => wallet = required("wallet", value)?.to_owned(),
            "disablewallet" => disable_wallet = parse_bool("disablewallet", value)?,
            "gen" => generate = parse_bool("gen", value)?,
            "genaddress" => gen_address = Some(required("genaddress", value)?.to_owned()),
            "blockinterval" => {
                let secs = parse_value::<u64>("blockinterval", value)?;
                if secs == 0 {
                    return Err(ConfigError::InvalidValue {
                        name: "blockinterval",
                        value: "0".to_owned(),
                    });
                }
                block_interval = Some(secs);
            }
            "printchainspec" => print_chainspec = parse_bool("printchainspec", value)?,
            _ => return Err(ConfigError::UnknownOption(arg.to_string())),
        }
    }

    if chainspec.is_some() && chain.is_some() {
        return Err(ConfigError::Conflict {
            first: "chainspec",
            second: "chain",
        });
    }
    match (&rpc_user, &rpc_password) {
        (Some(_), None) => {
            return Err(ConfigError::Requires {
                option: "rpcuser",
                requires: "rpcpassword",
            })
        }
        (None, Some(_)) => {
            return Err(ConfigError::Requires {
                option: "rpcpassword",
                requires: "rpcuser",
            })
        }
        _ => {}
    }
    if generate && gen_address.is_none() {
        return Err(ConfigError::Requires {
            option: "gen",
            requires: "genaddress",
        });
    }
    if gen_address.is_some() && !generate {
        return Err(ConfigError::Requires {
            option: "genaddress",
            requires: "gen",
        });
    }

    // Defaults depend on the chain, and -chain may come after -port, so
    // resolve them only once every argument has been read.
    let custom_chain = match chainspec {
        Some(path) => {
            Some(load_chain_spec(&path).map_err(|err| ConfigError::ChainSpec(err.to_string()))?)
        }
        None => None,
    };
    let chain = match custom_chain {
        Some(_) => ChainType::Regtest,
        None => chain.unwrap_or(ChainType::Main),
    };
    let (default_p2p_port, default_rpc_port, subdir) = match &custom_chain {
        Some(spec) => (spec.default_port, spec.rpc_port, spec.name.clone()),
        None => {
            let params = ChainParams::for_chain(chain);
            (params.default_port, params.rpc_port, params.data_dir)
        }
    };
    let base = match datadir {
        Some(dir) => dir,
        None => default_datadir()?,
    };
    // Mainnet has an empty subdirectory, so its path is used as-is.
    let datadir = if subdir.is_empty() {
        base
    } else {
        base.join(subdir)
    };

    Ok(NodeConfig {
        chain,
        datadir,
        p2p_port: p2p_port.unwrap_or(default_p2p_port),
        rpc_port: rpc_port.unwrap_or(default_rpc_port),
        listen,
        daemon,
        custom_chain,
        rpc_user,
        rpc_password,
        rpc_bind,
        connect,
        add_nodes,
        seed_nodes,
        dns_seed,
        external_ip,
        max_connections,
        wallet,
        disable_wallet,
        generate,
        gen_address,
        block_interval,
        print_chainspec,
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

/// Parse a required value with `FromStr`.
fn parse_value<T: FromStr>(name: &'static str, value: Option<&str>) -> Result<T, ConfigError> {
    let value = required(name, value)?;
    value.parse().map_err(|_| ConfigError::InvalidValue {
        name,
        value: value.to_string(),
    })
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

    #[test]
    fn rpc_and_connect_options() {
        let config = parse(&[]).unwrap();
        assert_eq!(config.rpc_user, None);
        assert_eq!(config.rpc_bind, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(config.connect.is_empty());

        let config = parse(&[
            "-rpcuser=alice",
            "-rpcpassword=secret",
            "-rpcbind=0.0.0.0",
            "-connect=10.0.0.1:8333",
            "-connect=10.0.0.2:8333",
        ])
        .unwrap();
        assert_eq!(config.rpc_user.as_deref(), Some("alice"));
        assert_eq!(config.rpc_password.as_deref(), Some("secret"));
        assert_eq!(config.rpc_bind, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            config.connect,
            vec![
                "10.0.0.1:8333".parse::<SocketAddr>().unwrap(),
                "10.0.0.2:8333".parse::<SocketAddr>().unwrap(),
            ]
        );

        assert!(matches!(
            parse(&["-connect=10.0.0.1"]),
            Err(ConfigError::InvalidValue {
                name: "connect",
                ..
            })
        ));
        assert!(matches!(
            parse(&["-rpcbind=not-an-ip"]),
            Err(ConfigError::InvalidValue {
                name: "rpcbind",
                ..
            })
        ));
    }

    #[test]
    fn mining_and_auth_pairs_are_required_together() {
        let config = parse(&["-gen", "-genaddress=51"]).unwrap();
        assert!(config.generate);
        assert_eq!(config.gen_address.as_deref(), Some("51"));
        assert_eq!(config.block_interval, None);

        assert_eq!(
            parse(&["-gen"]),
            Err(ConfigError::Requires {
                option: "gen",
                requires: "genaddress"
            })
        );
        assert_eq!(
            parse(&["-genaddress=51"]),
            Err(ConfigError::Requires {
                option: "genaddress",
                requires: "gen"
            })
        );
        assert_eq!(
            parse(&["-rpcuser=alice"]),
            Err(ConfigError::Requires {
                option: "rpcuser",
                requires: "rpcpassword"
            })
        );
        assert_eq!(
            parse(&["-rpcpassword=x"]),
            Err(ConfigError::Requires {
                option: "rpcpassword",
                requires: "rpcuser"
            })
        );
    }

    #[test]
    fn p2p_peer_flags() {
        let config = parse(&[]).unwrap();
        assert!(config.add_nodes.is_empty() && config.seed_nodes.is_empty());
        assert!(config.dns_seed);
        assert_eq!(config.external_ip, None);
        assert_eq!(config.max_connections, 125);

        let config = parse(&[
            "-seednode=10.0.0.1:8333",
            "-seednode=10.0.0.2:8333",
            "-addnode=10.0.0.3:8333",
            "-dnsseed=0",
            "-externalip=203.0.113.7",
            "-maxconnections=40",
        ])
        .unwrap();
        assert_eq!(config.seed_nodes.len(), 2);
        assert_eq!(config.add_nodes, vec!["10.0.0.3:8333".parse::<SocketAddr>().unwrap()]);
        assert!(!config.dns_seed);
        assert_eq!(config.external_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(config.max_connections, 40);

        assert!(parse(&["-maxconnections=0"]).unwrap().max_connections == 0);
        assert!(matches!(
            parse(&["-maxconnections=many"]),
            Err(ConfigError::InvalidValue { name: "maxconnections", .. })
        ));
        assert!(matches!(
            parse(&["-externalip=not-an-ip"]),
            Err(ConfigError::InvalidValue { name: "externalip", .. })
        ));
        assert!(matches!(
            parse(&["-dnsseed=2"]),
            Err(ConfigError::InvalidValue { name: "dnsseed", .. })
        ));
        assert!(matches!(
            parse(&["-seednode=10.0.0.1"]),
            Err(ConfigError::InvalidValue { name: "seednode", .. })
        ));
    }

    #[test]
    fn printchainspec_flag() {
        assert!(parse(&["-printchainspec"]).unwrap().print_chainspec);
        assert!(!parse(&[]).unwrap().print_chainspec);
    }

    #[test]
    fn block_interval_controls_automining_spacing() {
        let config = parse(&["-gen", "-genaddress=51", "-blockinterval=2"]).unwrap();
        assert_eq!(config.block_interval, Some(2));
        assert_eq!(
            parse(&["-blockinterval=0"]),
            Err(ConfigError::InvalidValue {
                name: "blockinterval",
                value: "0".to_owned()
            })
        );
    }

    #[test]
    fn chainspec_sets_datadir_subdir_and_ports() {
        let path = env::temp_dir().join(format!("btc-node-config-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"name": "mycoin", "default_port": 19777, "rpc_port": 19778}"#,
        )
        .unwrap();
        let chainspec_arg = format!("-chainspec={}", path.display());

        let config = parse(&[&chainspec_arg]).unwrap();
        let spec = config.custom_chain.as_ref().expect("custom chain loaded");
        assert_eq!(spec.name, "mycoin");
        assert_eq!(config.chain, ChainType::Regtest);
        assert_eq!(config.datadir, test_datadir().join("mycoin"));
        assert_eq!((config.p2p_port, config.rpc_port), (19777, 19778));

        let config = parse(&[&chainspec_arg, "-port=19000"]).unwrap();
        assert_eq!(config.p2p_port, 19000);

        assert_eq!(
            parse(&[&chainspec_arg, "-chain=regtest"]),
            Err(ConfigError::Conflict {
                first: "chainspec",
                second: "chain"
            })
        );
        assert!(matches!(
            parse(&["-chainspec=/nonexistent/btc-node-spec.json"]),
            Err(ConfigError::ChainSpec(_))
        ));
        std::fs::remove_file(path).unwrap();
    }
}
