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
use btc_wallet::Wallet;
use btc_node::p2p::{run_p2p, P2pConfig};
use btc_node::rpc_backend::NodeRpc;
use btc_primitives::{Block, ScriptBuf};
use btc_rpc::{serve_listener, write_cookie};
use btc_storage::{CoinsDb, DiskBlockStore};
use btc_wallet::address::{decode_address_with, AddressParams};
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
    let node = Node::new(params.clone(), genesis, Box::new(coins), Box::new(store))
    .map_err(|err| format!("genesis rejected: {}", err.reject_reason()))?;
    let mut node = node;
    if !config.disable_wallet {
        let path = config.datadir.join(&config.wallet);
        let wallet = if path.exists() { Wallet::open(&path) } else { Wallet::create(&path) }
            .map_err(|e| format!("wallet {}: {e}", path.display()))?;
        node.attach_wallet(wallet).map_err(|e| format!("wallet rescan: {e}"))?;
        println!("wallet: {}", path.display());
    }
    let node: SharedNode = node.shared();

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
    let p2p_task = tokio::spawn(run_p2p(Arc::clone(&node), p2p_config, Arc::clone(&shutdown)));

    let address_params = AddressParams {
        bech32_hrp: params.bech32_hrp.clone(),
        pubkey_prefix: params.pubkey_address_prefix,
        script_prefix: params.script_address_prefix,
    };
    let mining_script = config
        .gen_address
        .as_deref()
        .map(|address| resolve_script(address, &address_params))
        .transpose()?;
    if let Some(script) = mining_script {
        // A real miner hashes until it finds a block, then immediately builds a
        // fresh template. `-blockinterval` keeps the old throttled behaviour.
        let spacing = config.block_interval.map(Duration::from_secs);
        match spacing {
            Some(spacing) => println!("mining one block every {} s", spacing.as_secs()),
            None => println!("mining continuously (-gen without -blockinterval)"),
        }
        tokio::spawn(mine_forever(
            Arc::clone(&node),
            script,
            spacing,
            config.max_blocks,
        ));
    }

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            println!("shutdown requested (ctrl-c)");
        }
        _ = shutdown.notified() => println!("shutdown requested (rpc stop)"),
        served = &mut rpc_task => return Err(format!("RPC server stopped: {served:?}").into()),
    }
    // Stop the P2P layer so it writes peers.dat, then let an in-flight `stop` reply reach the client.
    shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(5), p2p_task).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

async fn mine_forever(
    node: SharedNode,
    script: ScriptBuf,
    spacing: Option<Duration>,
    max_blocks: Option<u32>,
) {
    let mut ticker = spacing.map(|spacing| {
        let mut ticker = tokio::time::interval(spacing);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker
    });
    if let Some(ticker) = ticker.as_mut() {
        // The first tick fires immediately; skip it so -blockinterval waits first.
        ticker.tick().await;
    }
    let mut mined_this_run: u32 = 0;
    loop {
        if let Some(ticker) = ticker.as_mut() {
            ticker.tick().await;
        }
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
                mined_this_run += 1;
            }
            Ok(Err(err)) => eprintln!("mining failed: {}", err.reject_reason()),
            Err(err) => eprintln!("mining task failed: {err}"),
        }
        if let Some(max) = max_blocks {
            if mined_this_run >= max {
                println!("-gen: reached -maxblocks {max}, mining stopped");
                return;
            }
        }
        if ticker.is_none() {
            // Continuous mode: let RPC, P2P and the shutdown signal run between blocks.
            tokio::task::yield_now().await;
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


/// `-genaddress` takes an address for the chain, or raw script hex for coins
/// whose address prefixes are not known to the wallet code.
fn resolve_script(value: &str, params: &AddressParams) -> Result<ScriptBuf, String> {
    if let Ok(script) = decode_address_with(params, value) {
        return Ok(script);
    }
    match Vec::<u8>::from_hex(value) {
        Ok(bytes) if !bytes.is_empty() => Ok(ScriptBuf::from_bytes(bytes)),
        _ => Err(format!(
            "-genaddress {value:?} is neither an address nor script hex"
        )),
    }
}
