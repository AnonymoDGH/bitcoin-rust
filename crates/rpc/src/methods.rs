//! The RPC method table and handlers, backed by [`RpcBackend`].

use std::sync::OnceLock;
use std::time::Instant;

use bitcoin::consensus::encode::{deserialize, serialize_hex, Decodable};
use bitcoin::hex::FromHex;
use bitcoin::OutPoint;
use btc_primitives::{Block, BlockHash, Tx, Txid};
use btc_wallet::address::decode_address_with;
use serde_json::{json, Value};

use crate::backend::RpcBackend;
use crate::error::{
    RpcError, RpcResult, RPC_DESERIALIZATION_ERROR, RPC_INVALID_ADDRESS_OR_KEY,
    RPC_INVALID_PARAMETER, RPC_METHOD_NOT_FOUND, RPC_MISC_ERROR, RPC_VERIFY_REJECTED,
};
use crate::json::{amount, block_json, header_fields, script_json, tx_json, validate_address};
use crate::params::Args;
use crate::wallet;

/// A registered method: its name and `(parameter name, required)` in positional order.
pub(crate) struct Method {
    pub(crate) name: &'static str,
    pub(crate) params: &'static [(&'static str, bool)],
}

const METHODS: &[Method] = &[
    Method {
        name: "getblockcount",
        params: &[],
    },
    Method {
        name: "getbestblockhash",
        params: &[],
    },
    Method {
        name: "getblockhash",
        params: &[("height", true)],
    },
    Method {
        name: "getblock",
        params: &[("blockhash", true), ("verbosity", false)],
    },
    Method {
        name: "getblockheader",
        params: &[("blockhash", true), ("verbose", false)],
    },
    Method {
        name: "getblockchaininfo",
        params: &[],
    },
    Method {
        name: "getrawmempool",
        params: &[("verbose", false)],
    },
    Method {
        name: "getmempoolinfo",
        params: &[],
    },
    Method {
        name: "getrawtransaction",
        params: &[("txid", true), ("verbose", false), ("blockhash", false)],
    },
    Method {
        name: "sendrawtransaction",
        params: &[
            ("hexstring", true),
            ("maxfeerate", false),
            ("maxburnamount", false),
        ],
    },
    Method {
        name: "submitblock",
        params: &[("hexdata", true), ("dummy", false)],
    },
    Method {
        name: "generatetoaddress",
        params: &[("nblocks", true), ("address", true), ("maxtries", false)],
    },
    Method {
        name: "gettxout",
        params: &[("txid", true), ("n", true), ("include_mempool", false)],
    },
    Method {
        name: "validateaddress",
        params: &[("address", true)],
    },
    Method {
        name: "stop",
        params: &[],
    },
    Method {
        name: "help",
        params: &[("command", false)],
    },
    Method {
        name: "uptime",
        params: &[],
    },
];

/// Wallet methods, registered only when the backend has a wallet.
const WALLET_METHODS: &[Method] = &[
    Method {
        name: "getnewaddress",
        params: &[("label", false), ("address_type", false)],
    },
    Method {
        name: "getbalance",
        params: &[
            ("dummy", false),
            ("minconf", false),
            ("include_watchonly", false),
            ("avoid_reuse", false),
        ],
    },
    Method {
        name: "getbalances",
        params: &[],
    },
    Method {
        name: "listunspent",
        params: &[
            ("minconf", false),
            ("maxconf", false),
            ("addresses", false),
            ("include_unsafe", false),
            ("query_options", false),
        ],
    },
    Method {
        name: "sendtoaddress",
        params: &[
            ("address", true),
            ("amount", true),
            ("comment", false),
            ("comment_to", false),
            ("subtractfeefromamount", false),
            ("replaceable", false),
            ("conf_target", false),
            ("estimate_mode", false),
            ("avoid_reuse", false),
            ("fee_rate", false),
            ("verbose", false),
        ],
    },
    Method {
        name: "getwalletinfo",
        params: &[],
    },
    Method {
        name: "listtransactions",
        params: &[
            ("label", false),
            ("count", false),
            ("skip", false),
            ("include_watchonly", false),
        ],
    },
    Method {
        name: "dumpprivkey",
        params: &[("address", true)],
    },
    Method {
        name: "importprivkey",
        params: &[("privkey", true), ("label", false), ("rescan", false)],
    },
    Method {
        name: "encryptwallet",
        params: &[("passphrase", true)],
    },
    Method {
        name: "walletpassphrase",
        params: &[("passphrase", true), ("timeout", true)],
    },
    Method {
        name: "walletlock",
        params: &[],
    },
    Method {
        name: "getnewstealthaddress",
        params: &[],
    },
    Method {
        name: "liststealthutxos",
        params: &[("minconf", false), ("max_blocks", false)],
    },
];

/// Finds a method. Wallet methods are reported as missing when there is no wallet.
pub(crate) fn lookup(name: &str, wallet_enabled: bool) -> RpcResult<&'static Method> {
    if let Some(method) = METHODS.iter().find(|method| method.name == name) {
        return Ok(method);
    }
    match WALLET_METHODS.iter().find(|method| method.name == name) {
        Some(method) if wallet_enabled => Ok(method),
        Some(_) => Err(RpcError::new(
            RPC_METHOD_NOT_FOUND,
            "Method not found (wallet disabled)",
        )),
        None => Err(RpcError::new(RPC_METHOD_NOT_FOUND, "Method not found")),
    }
}

static START: OnceLock<Instant> = OnceLock::new();

/// Starts the uptime clock. Called when the server starts and on first use.
pub(crate) fn start_clock() {
    START.get_or_init(Instant::now);
}

/// Runs a registered method. Its name must come from [`lookup`].
pub(crate) fn call(backend: &dyn RpcBackend, method: &str, args: &Args) -> RpcResult<Value> {
    match method {
        "getblockcount" => Ok(json!(backend.get_block_count())),
        "getbestblockhash" => Ok(json!(backend.get_best_block_hash().to_string())),
        "getblockhash" => {
            let height = args.u32_req(0, "height")?;
            backend
                .get_block_hash(height)
                .map(|hash| json!(hash.to_string()))
                .ok_or_else(|| RpcError::new(RPC_INVALID_PARAMETER, "Block height out of range"))
        }
        "getblock" => {
            let hash: BlockHash = args.hash_req(0, "blockhash")?;
            let verbosity = args.u32(1)?.unwrap_or(1);
            if verbosity > 2 {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    format!("Invalid verbosity value {verbosity}"),
                ));
            }
            let (block, height, confirmations) =
                backend.get_block(&hash).ok_or_else(block_not_found)?;
            if verbosity == 0 {
                Ok(json!(serialize_hex(&block)))
            } else {
                Ok(block_json(
                    &block,
                    height,
                    confirmations,
                    &backend.address_params(),
                    verbosity == 2,
                ))
            }
        }
        "getblockheader" => {
            let hash: BlockHash = args.hash_req(0, "blockhash")?;
            let verbose = args.bool(1, true)?;
            let (header, height, confirmations) = backend
                .get_block_header(&hash)
                .ok_or_else(block_not_found)?;
            if verbose {
                Ok(Value::Object(header_fields(&header, height, confirmations)))
            } else {
                Ok(json!(serialize_hex(&header)))
            }
        }
        "getblockchaininfo" => {
            let info = backend.get_blockchain_info();
            Ok(json!({
                "chain": info.chain,
                "blocks": info.blocks,
                "headers": info.headers,
                "bestblockhash": info.bestblockhash.to_string(),
                "difficulty": info.difficulty,
                "mediantime": info.mediantime,
                "chainwork": info.chainwork,
            }))
        }
        "getrawmempool" => {
            if args.bool(0, false)? {
                return Err(RpcError::new(
                    RPC_MISC_ERROR,
                    "verbose mempool output is not supported",
                ));
            }
            let txids: Vec<String> = backend
                .get_raw_mempool()
                .iter()
                .map(ToString::to_string)
                .collect();
            Ok(json!(txids))
        }
        "getmempoolinfo" => {
            let info = backend.get_mempool_info();
            Ok(json!({ "size": info.size, "bytes": info.bytes }))
        }
        "getrawtransaction" => {
            let txid: Txid = args.hash_req(0, "txid")?;
            let verbose = args.bool(1, false)?;
            if args.is_set(2) {
                return Err(RpcError::new(
                    RPC_INVALID_PARAMETER,
                    "getrawtransaction with blockhash is not supported",
                ));
            }
            let tx = backend.get_raw_transaction(&txid).ok_or_else(|| {
                RpcError::new(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "No such mempool or blockchain transaction",
                )
            })?;
            if verbose {
                Ok(tx_json(&tx, &backend.address_params(), true))
            } else {
                Ok(json!(serialize_hex(&tx)))
            }
        }
        "sendrawtransaction" => {
            let tx: Tx = decode_hex(args.str_req(0, "hexstring")?, "TX")?;
            backend
                .send_raw_transaction(tx)
                .map(|txid| json!(txid.to_string()))
                .map_err(|reason| RpcError::new(RPC_VERIFY_REJECTED, reason))
        }
        "submitblock" => {
            let block: Block = decode_hex(args.str_req(0, "hexdata")?, "Block")?;
            match backend.submit_block(block) {
                Ok(()) => Ok(Value::Null),
                Err(reason) => Ok(json!(reason)),
            }
        }
        "generatetoaddress" => {
            let nblocks = args.u32_req(0, "nblocks")?;
            let address = args.str_req(1, "address")?;
            let script = decode_address_with(&backend.address_params(), address)
                .map_err(|_| RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address"))?;
            let hashes = backend
                .generate_to_script(nblocks, script)
                .map_err(|reason| RpcError::new(RPC_MISC_ERROR, reason))?;
            let hashes: Vec<String> = hashes.iter().map(ToString::to_string).collect();
            Ok(json!(hashes))
        }
        "gettxout" => {
            let txid: Txid = args.hash_req(0, "txid")?;
            let vout = args.u32_req(1, "n")?;
            let outpoint = OutPoint { txid, vout };
            let params = backend.address_params();
            match backend.get_tx_out(&outpoint) {
                None => Ok(Value::Null),
                Some((output, confirmations, coinbase)) => Ok(json!({
                    "bestblock": backend.get_best_block_hash().to_string(),
                    "confirmations": confirmations,
                    "value": amount(output.value),
                    "scriptPubKey": script_json(&output.script_pubkey, &params),
                    "coinbase": coinbase,
                })),
            }
        }
        "validateaddress" => Ok(validate_address(
            &backend.address_params(),
            args.str_req(0, "address")?,
        )),
        "stop" => {
            backend.stop();
            Ok(json!("Bitcoin Core stopping"))
        }
        "help" => match args.str(0)? {
            None => {
                let wallet_enabled = backend.wallet().is_some();
                let names: Vec<&str> = METHODS
                    .iter()
                    .chain(WALLET_METHODS.iter().filter(|_| wallet_enabled))
                    .map(|method| method.name)
                    .collect();
                Ok(json!(names.join("\n")))
            }
            Some(name) => lookup(name, backend.wallet().is_some())
                .map(|method| json!(usage(method)))
                .map_err(|_| {
                    RpcError::new(RPC_MISC_ERROR, format!("help: unknown command: {name}"))
                }),
        },
        "uptime" => Ok(json!(START.get_or_init(Instant::now).elapsed().as_secs())),
        _ => wallet::call(backend, method, args),
    }
}

fn usage(method: &Method) -> String {
    let params: Vec<String> = method
        .params
        .iter()
        .map(|&(name, required)| {
            if required {
                name.to_owned()
            } else {
                format!("( {name} )")
            }
        })
        .collect();
    std::iter::once(method.name.to_owned())
        .chain(params)
        .collect::<Vec<_>>()
        .join(" ")
}

fn block_not_found() -> RpcError {
    RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Block not found")
}

fn decode_hex<T: Decodable>(hex: &str, what: &str) -> RpcResult<T> {
    Vec::<u8>::from_hex(hex)
        .ok()
        .and_then(|bytes| deserialize(&bytes).ok())
        .ok_or_else(|| RpcError::new(RPC_DESERIALIZATION_ERROR, format!("{what} decode failed")))
}
