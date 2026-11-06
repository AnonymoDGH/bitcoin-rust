// btc-node binary entry point.

use std::process::ExitCode;

use btc_consensus::ChainParams;
use btc_node::config::parse_args;

fn main() -> ExitCode {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(1);
        }
    };

    let params = ChainParams::for_chain(config.chain);
    println!("chain: {}", config.chain.as_str());
    println!("datadir: {}", config.datadir.display());
    println!("p2p port: {}", config.p2p_port);
    println!("rpc port: {}", config.rpc_port);
    println!("listen: {}", config.listen);
    println!("daemon: {}", config.daemon);
    println!("genesis hash: {}", params.genesis_hash);
    if config.daemon {
        eprintln!("warning: -daemon is parsed but not implemented yet; running in the foreground");
    }

    ExitCode::SUCCESS
}
