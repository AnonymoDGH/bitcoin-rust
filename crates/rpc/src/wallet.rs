//! Wallet RPCs (port of `src/wallet/rpc/*.cpp`), forwarded to [`WalletRpc`].

use bitcoin::PrivateKey;
use btc_primitives::ScriptBuf;
use btc_wallet::address::{decode_address_with, AddressParams};
use serde_json::{json, Map, Value};

use crate::backend::{RpcBackend, WalletInfo, WalletRpc, WalletTx};
use crate::error::{
    RpcError, RpcResult, RPC_INVALID_ADDRESS_OR_KEY, RPC_INVALID_PARAMETER, RPC_METHOD_DEPRECATED,
    RPC_METHOD_NOT_FOUND, RPC_MISC_ERROR, RPC_TYPE_ERROR, RPC_WALLET_ERROR,
    RPC_WALLET_INSUFFICIENT_FUNDS, RPC_WALLET_PASSPHRASE_INCORRECT, RPC_WALLET_UNLOCK_NEEDED,
    RPC_WALLET_WRONG_ENC_STATE,
};
use crate::json::{address_of, amount, script_hex};
use crate::params::Args;

/// `walletversion` reported by `getwalletinfo`.
const WALLET_VERSION: u32 = 169_900;
const DEFAULT_MAX_CONF: u32 = 9_999_999;

/// Runs a wallet method. Unknown names are reported as missing.
pub(crate) fn call(backend: &dyn RpcBackend, method: &str, args: &Args) -> RpcResult<Value> {
    let Some(wallet) = backend.wallet() else {
        return Err(RpcError::new(
            RPC_METHOD_NOT_FOUND,
            "Method not found (wallet disabled)",
        ));
    };
    let params = backend.address_params();
    match method {
        "getnewaddress" => get_new_address(wallet, &params, args),
        "getbalance" => get_balance(wallet, args),
        "getbalances" => Ok(get_balances(wallet)),
        "listunspent" => list_unspent(wallet, &params, args),
        "sendtoaddress" => send_to_address(wallet, &params, args),
        "getwalletinfo" => Ok(wallet_info_json(&wallet.wallet_info())),
        "listtransactions" => list_transactions(wallet, &params, args),
        "dumpprivkey" => dump_privkey(wallet, &params, args),
        "importprivkey" => import_privkey(wallet, args),
        "encryptwallet" => encrypt_wallet(wallet, args),
        "walletpassphrase" => wallet_passphrase(wallet, args),
        "walletlock" => {
            wallet.wallet_lock().map_err(wallet_error)?;
            Ok(Value::Null)
        }
        "getnewstealthaddress" => Ok(json!(wallet.get_stealth_address().map_err(wallet_error)?)),
        "sendtostealthaddress" => {
            let address = args.str_req(0, "stealth_address")?;
            let sats = args.amount_req(1, "amount")?;
            if sats <= 0 {
                return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid amount for send"));
            }
            let fee_rate = args.scaled(2, 3)?;
            let txid = wallet
                .send_to_stealth(address.to_owned(), sats, fee_rate)
                .map_err(wallet_error)?;
            Ok(json!(txid.to_string()))
        }
        "shieldtoct" => {
            let sats = args.amount_req(0, "amount")?;
            if sats <= 0 {
                return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid amount for send"));
            }
            let fee = match args.scaled(1, 8)? {
                Some(sats) => sats,
                None => 10_000,
            };
            if fee < 0 {
                return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid fee for send"));
            }
            let txid = wallet
                .send_to_confidential(sats, fee)
                .map_err(wallet_error)?;
            Ok(json!(txid.to_string()))
        }
        "createpoolnote" => {
            let sats = args.amount_req(0, "amount")?;
            if sats <= 0 {
                return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid amount for send"));
            }
            let fee = match args.scaled(1, 8)? {
                Some(sats) => sats,
                None => 10_000,
            };
            if fee < 0 {
                return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid fee for send"));
            }
            let cmu = wallet
                .create_pool_note(sats, fee)
                .map_err(wallet_error)?;
            Ok(json!(cmu))
        }
        "spendnote" => {
            let commitment = args.str_req(0, "commitment")?;
            let sats = args.amount_req(1, "amount")?;
            if sats <= 0 {
                return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid amount for send"));
            }
            let txid = wallet
                .spend_note(commitment.to_owned(), sats)
                .map_err(wallet_error)?;
            Ok(json!(txid.to_string()))
        }
        "liststealthutxos" => {
            let minconf = args.u32(0)?.unwrap_or(0);
            let max_blocks = args.u32(1)?.unwrap_or(2000);
            let utxos = wallet.list_stealth_utxos(minconf, max_blocks);
            let rows = utxos
                .iter()
                .map(|u| {
                    json!({
                        "txid": u.outpoint.txid.to_string(),
                        "vout": u.outpoint.vout,
                        "address": encode(&params, &u.script_pubkey).unwrap_or_default(),
                        "amount": amount(u.amount),
                        "confirmations": u.confirmations,
                        "spendable": u.spendable,
                        "solvable": true,
                        "safe": true,
                        "scriptPubKey": script_hex(&u.script_pubkey),
                    })
                })
                .collect::<Vec<_>>();
            Ok(Value::Array(rows))
        }
        _ => Err(RpcError::new(RPC_METHOD_NOT_FOUND, "Method not found")),
    }
}

/// Maps a wallet failure to Core's wallet error code. The wallet reports only text.
fn wallet_error(message: String) -> RpcError {
    let lower = message.to_lowercase();
    let code = if lower.contains("locked") {
        RPC_WALLET_UNLOCK_NEEDED
    } else if lower.contains("encrypted") {
        RPC_WALLET_WRONG_ENC_STATE
    } else if lower.contains("passphrase") {
        RPC_WALLET_PASSPHRASE_INCORRECT
    } else if lower.contains("insufficient funds") {
        RPC_WALLET_INSUFFICIENT_FUNDS
    } else {
        RPC_WALLET_ERROR
    };
    RpcError::new(code, message)
}

fn encode(params: &AddressParams, script: &ScriptBuf) -> RpcResult<String> {
    address_of(params, script)
        .ok_or_else(|| RpcError::new(RPC_MISC_ERROR, "script has no address encoding"))
}

fn decode(params: &AddressParams, text: &str) -> RpcResult<ScriptBuf> {
    decode_address_with(params, text)
        .map_err(|_| RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address"))
}

fn get_new_address(
    wallet: &dyn WalletRpc,
    params: &AddressParams,
    args: &Args,
) -> RpcResult<Value> {
    args.str(0)?;
    let kind = args.str(1)?.unwrap_or("bech32");
    if !matches!(kind, "legacy" | "p2sh-segwit" | "bech32" | "bech32m") {
        return Err(RpcError::new(
            RPC_INVALID_ADDRESS_OR_KEY,
            format!("Unknown address type '{kind}'"),
        ));
    }
    let script = wallet.get_new_address(Some(kind)).map_err(wallet_error)?;
    Ok(json!(encode(params, &script)?))
}

fn get_balance(wallet: &dyn WalletRpc, args: &Args) -> RpcResult<Value> {
    if args.str(0)?.is_some_and(|dummy| dummy != "*") {
        return Err(RpcError::new(
            RPC_METHOD_DEPRECATED,
            "dummy first argument must be excluded or set to \"*\".",
        ));
    }
    let minconf = args.u32(1)?.unwrap_or(0);
    Ok(amount(wallet.get_balance(minconf)))
}

fn get_balances(wallet: &dyn WalletRpc) -> Value {
    let info = wallet.wallet_info();
    json!({
        "mine": {
            "trusted": amount(info.balance),
            "untrusted_pending": amount(info.unconfirmed_balance),
            "immature": amount(info.immature_balance),
        }
    })
}

fn list_unspent(wallet: &dyn WalletRpc, params: &AddressParams, args: &Args) -> RpcResult<Value> {
    let minconf = args.u32(0)?.unwrap_or(1);
    let maxconf = args.u32(1)?.unwrap_or(DEFAULT_MAX_CONF);
    if args.is_set(2) || args.is_set(4) {
        return Err(RpcError::new(
            RPC_INVALID_PARAMETER,
            "the addresses and query_options filters are not supported",
        ));
    }
    let rows = wallet
        .list_unspent(minconf, maxconf)
        .iter()
        .map(|utxo| {
            let mut row = Map::new();
            row.insert("txid".into(), json!(utxo.outpoint.txid.to_string()));
            row.insert("vout".into(), json!(utxo.outpoint.vout));
            if let Some(address) = address_of(params, &utxo.script_pubkey) {
                row.insert("address".into(), json!(address));
            }
            row.insert(
                "scriptPubKey".into(),
                json!(script_hex(&utxo.script_pubkey)),
            );
            row.insert("amount".into(), amount(utxo.amount));
            row.insert("confirmations".into(), json!(utxo.confirmations));
            row.insert("spendable".into(), json!(utxo.spendable));
            row.insert("solvable".into(), json!(true));
            row.insert("safe".into(), json!(true));
            Value::Object(row)
        })
        .collect();
    Ok(Value::Array(rows))
}

fn send_to_address(
    wallet: &dyn WalletRpc,
    params: &AddressParams,
    args: &Args,
) -> RpcResult<Value> {
    let script = decode(params, args.str_req(0, "address")?)?;
    let sats = args.amount_req(1, "amount")?;
    if sats <= 0 {
        return Err(RpcError::new(RPC_TYPE_ERROR, "Invalid amount for send"));
    }
    let subtract_fee = args.bool(4, false)?;
    // fee_rate is sat/vB in Core; the wallet takes sat/kvB.
    let fee_rate = args.scaled(9, 3)?;
    let txid = wallet
        .send_to(script, sats, fee_rate, subtract_fee)
        .map_err(wallet_error)?;
    Ok(json!(txid.to_string()))
}

fn wallet_info_json(info: &WalletInfo) -> Value {
    let mut m = Map::new();
    m.insert("walletname".into(), json!(info.name));
    m.insert("walletversion".into(), json!(WALLET_VERSION));
    m.insert("format".into(), json!("json"));
    m.insert("balance".into(), amount(info.balance));
    m.insert(
        "unconfirmed_balance".into(),
        amount(info.unconfirmed_balance),
    );
    m.insert("immature_balance".into(), amount(info.immature_balance));
    m.insert("txcount".into(), json!(info.tx_count));
    m.insert("keypoolsize".into(), json!(info.keypool_size));
    if info.encrypted {
        m.insert("unlocked_until".into(), json!(info.unlocked_until));
    }
    m.insert("private_keys_enabled".into(), json!(true));
    m.insert("descriptors".into(), json!(false));
    Value::Object(m)
}

fn list_transactions(
    wallet: &dyn WalletRpc,
    params: &AddressParams,
    args: &Args,
) -> RpcResult<Value> {
    // Wallet labels are not tracked, so every entry carries the empty label.
    let label = args.str(0)?.unwrap_or("*");
    let count = args.u32(1)?.unwrap_or(10) as usize;
    let skip = args.u32(2)?.unwrap_or(0) as usize;
    if !matches!(label, "*" | "") {
        return Ok(json!([]));
    }
    let rows = wallet
        .list_transactions(count, skip)
        .iter()
        .map(|tx| tx_row(params, tx))
        .collect();
    Ok(Value::Array(rows))
}

fn tx_row(params: &AddressParams, tx: &WalletTx) -> Value {
    let mut row = Map::new();
    if let Some(address) = tx
        .script_pubkey
        .as_ref()
        .and_then(|script| address_of(params, script))
    {
        row.insert("address".into(), json!(address));
    }
    row.insert("category".into(), json!(tx.category));
    row.insert("amount".into(), amount(tx.amount));
    if tx.category == "send" {
        if let Some(fee) = tx.fee {
            row.insert("fee".into(), amount(-fee.saturating_abs()));
        }
    }
    row.insert("confirmations".into(), json!(tx.confirmations));
    if let Some(hash) = tx.blockhash {
        row.insert("blockhash".into(), json!(hash.to_string()));
    }
    row.insert("txid".into(), json!(tx.txid.to_string()));
    row.insert("time".into(), json!(tx.time));
    Value::Object(row)
}

fn dump_privkey(wallet: &dyn WalletRpc, params: &AddressParams, args: &Args) -> RpcResult<Value> {
    let script = decode(params, args.str_req(0, "address")?)?;
    if !script.is_p2pkh() {
        return Err(RpcError::new(
            RPC_TYPE_ERROR,
            "Address does not refer to key",
        ));
    }
    let wif = wallet.dump_privkey(&script).map_err(wallet_error)?;
    Ok(json!(wif))
}

fn import_privkey(wallet: &dyn WalletRpc, args: &Args) -> RpcResult<Value> {
    let wif = args.str_req(0, "privkey")?;
    PrivateKey::from_wif(wif)
        .map_err(|_| RpcError::new(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding"))?;
    wallet.import_privkey(wif).map_err(wallet_error)?;
    Ok(Value::Null)
}

fn encrypt_wallet(wallet: &dyn WalletRpc, args: &Args) -> RpcResult<Value> {
    let passphrase = args.str_req(0, "passphrase")?;
    if passphrase.is_empty() {
        return Err(RpcError::new(
            RPC_INVALID_PARAMETER,
            "passphrase can not be empty",
        ));
    }
    wallet.encrypt_wallet(passphrase).map_err(wallet_error)?;
    Ok(json!(
        "wallet encrypted; back up the wallet file again (it now holds only encrypted keys)."
    ))
}

fn wallet_passphrase(wallet: &dyn WalletRpc, args: &Args) -> RpcResult<Value> {
    let passphrase = args.str_req(0, "passphrase")?;
    let timeout = args.u32_req(1, "timeout")?;
    wallet
        .wallet_passphrase(passphrase, u64::from(timeout))
        .map_err(wallet_error)?;
    Ok(Value::Null)
}
