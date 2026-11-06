// btc-node binary entry point.

use std::error::Error;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hex::FromHex;
use btc_consensus::{
    mainnet_genesis_block, regtest_genesis_block, testnet_genesis_block, ChainParams, ChainType,
};
use btc_node::chainspec::example_spec_json;
use btc_node::config::{parse_args, NodeConfig};
use btc_node::node::{Node, SharedNode};
use btc_node::p2p::{run_p2p, P2pConfig};
use btc_node::rpc_backend::NodeRpc;
use btc_primitives::{Block, ScriptBuf};
use btc_rpc::{serve_listener, write_cookie};
use btc_storage::{CoinsDb, DiskBlockStore};
use btc_wallet::address::{decode_address, Network as WalletNetwork};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::time::MissedTickBehavior;

/// Automatic full-relay outbound connections.
const MAX_OUTBOUND_PEERS: usize = 8;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(1);
        }
    };
    if config.print_chainspec {
        println!("{}", example_spec_json());
        return ExitCode::SUCCESS;
    }

    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

async fn run(config: NodeConfig) -> Result<(), Box<dyn Error>> {
    if config.daemon {
        eprintln!("warning: -daemon is parsed but not implemented yet; running in the foreground");
    }

    let mining_script = config
        .gen_address
        .as_deref()
        .map(|address| resolve_script(address, wallet_network(config.chain)))
        .transpose()?;

    let (params, genesis) = match &config.custom_chain {
        Some(spec) => {
            println!("mining genesis block for {}", spec.name);
            ChainParams::custom(spec)
        }
        None => (
            ChainParams::for_chain(config.chain),
            builtin_genesis(config.chain),
        ),
    };
    let chain_name = config
        .custom_chain
        .as_ref()
        .map_or(config.chain.as_str(), |spec| spec.name.as_str());

    std::fs::create_dir_all(&config.datadir)?;
    let coins = CoinsDb::open(config.datadir.join("chainstate"))?;
    let store = DiskBlockStore::open(config.datadir.join("blocks"), params.magic)?;
    let node: SharedNode = Node::new(params.clone(), genesis, Box::new(coins), Box::new(store))
    .map_err(|err| format!("genesis rejected: {}", err.reject_reason()))?
    .shared();

    let (user, password, auth_source) = match (&config.rpc_user, &config.rpc_password) {
        (Some(user), Some(password)) => (user.clone(), password.clone(), "-rpcuser".to_owned()),
        _ => {
            let (user, password) = write_cookie(&config.datadir)?;
            let source = format!("{}/.cookie", config.datadir.display());
            (user, password, source)
        }
    };
    let rpc_addr = SocketAddr::new(config.rpc_bind, config.rpc_port);
    let listener = TcpListener::bind(rpc_addr)
        .await
        .map_err(|err| format!("cannot bind RPC to {rpc_addr}: {err}"))?;
    let shutdown = Arc::new(Notify::new());
    let backend = Arc::new(NodeRpc::new(Arc::clone(&node), Arc::clone(&shutdown)));
    let mut rpc_task = tokio::spawn(serve_listener(listener, Some((user, password)), backend));

    println!("chain: {chain_name}");
    println!("datadir: {}", config.datadir.display());
    println!("p2p port: {}", config.p2p_port);
    println!("rpc port: {}", config.rpc_port);
    println!("rpc bind: {rpc_addr}");
    println!("rpc auth: {auth_source}");
    println!("listen: {}", config.listen);
    println!("daemon: {}", config.daemon);
    println!("genesis hash: {}", params.genesis_hash);

    let p2p_config = P2pConfig {
        listen: config
            .listen
            .then(|| SocketAddr::from(([0, 0, 0, 0], config.p2p_port))),
        connect: config.connect.clone(),
        max_outbound: MAX_OUTBOUND_PEERS.min(config.max_connections),
        max_inbound: config.max_connections.saturating_sub(MAX_OUTBOUND_PEERS),
        user_agent: format!("/btc-rust:{}/", env!("CARGO_PKG_VERSION")),
        add_nodes: config.add_nodes.clone(),
        seed_nodes: config.seed_nodes.clone(),
        dns_seed: config.dns_seed,
        advertise: config
            .external_ip
            .map(|ip| SocketAddr::new(ip, config.p2p_port)),
        datadir: Some(config.datadir.clone()),
        // A regtest network runs on one machine, so loopback peers are normal there.
        accept_local: config.chain == ChainType::Regtest,
        ..P2pConfig::default()
    };
    tokio::spawn(run_p2p(Arc::clone(&node), p2p_config, Arc::clone(&shutdown)));

    if let Some(script) = mining_script {
        let spacing = Duration::from_secs(params.target_spacing.max(1) as u64);
        println!("mining one block every {} s", spacing.as_secs());
        tokio::spawn(mine_forever(Arc::clone(&node), script, spacing));
    }

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            println!("shutdown requested (ctrl-c)");
        }
        _ = shutdown.notified() => println!("shutdown requested (rpc stop)"),
        served = &mut rpc_task => return Err(format!("RPC server stopped: {served:?}").into()),
    }
    // Let an in-flight `stop` reply reach the client before the runtime shuts down.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

async fn mine_forever(node: SharedNode, script: ScriptBuf, spacing: Duration) {
    let mut ticker = tokio::time::interval(spacing);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let node = Arc::clone(&node);
        let script = script.clone();
        let mined = tokio::task::spawn_blocking(move || {
            let mut node = node.lock().expect("node lock poisoned");
            node.generate(1, &script)
        })
        .await;
        match mined {
            Ok(Ok(hashes)) => {
                for hash in hashes {
                    println!("mined block {hash}");
                }
            }
            Ok(Err(err)) => eprintln!("mining failed: {}", err.reject_reason()),
            Err(err) => eprintln!("mining task failed: {err}"),
        }
    }
}

fn builtin_genesis(chain: ChainType) -> Block {
    match chain {
        ChainType::Main => mainnet_genesis_block(),
        ChainType::Testnet => testnet_genesis_block(),
        ChainType::Regtest => regtest_genesis_block(),
    }
}

fn wallet_network(chain: ChainType) -> WalletNetwork {
    match chain {
        ChainType::Main => WalletNetwork::Main,
        ChainType::Testnet => WalletNetwork::Test,
        ChainType::Regtest => WalletNetwork::Regtest,
    }
}

/// `-genaddress` takes an address for the chain, or raw script hex for coins
/// whose address prefixes are not known to the wallet code.
fn resolve_script(value: &str, network: WalletNetwork) -> Result<ScriptBuf, String> {
    if let Ok(script) = decode_address(network, value) {
        return Ok(script);
    }
    match Vec::<u8>::from_hex(value) {
        Ok(bytes) if !bytes.is_empty() => Ok(ScriptBuf::from_bytes(bytes)),
        _ => Err(format!(
            "-genaddress {value:?} is neither an address nor script hex"
        )),
    }
}
