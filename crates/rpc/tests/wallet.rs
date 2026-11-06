mod common;

use bitcoin::hashes::Hash;
use bitcoin::{Network, PrivateKey, PubkeyHash};
use btc_primitives::ScriptBuf;
use btc_rpc::dispatch;
use common::{p2wpkh_script, regtest_address, MockBackend, MockWallet};
use serde_json::{json, Value};

fn v1(backend: &MockBackend, method: &str, params: Value) -> Value {
    dispatch(
        backend,
        json!({ "method": method, "params": params, "id": 1 }),
    )
}

fn ok(reply: &Value) -> &Value {
    assert!(reply["error"].is_null(), "unexpected error: {reply}");
    &reply["result"]
}

fn code(reply: &Value) -> i64 {
    reply["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("expected an error: {reply}"))
}

fn message(reply: &Value) -> &str {
    reply["error"]["message"].as_str().unwrap_or("")
}

fn funded() -> MockBackend {
    MockBackend::new().with_wallet(MockWallet::new())
}

fn dest() -> String {
    regtest_address(&p2wpkh_script(0x90))
}

fn text(value: &Value) -> String {
    serde_json::to_string(value).unwrap()
}

#[test]
fn wallet_methods_are_not_found_without_a_wallet() {
    let backend = MockBackend::new();
    for method in [
        "getnewaddress",
        "getbalance",
        "getbalances",
        "listunspent",
        "sendtoaddress",
        "getwalletinfo",
        "listtransactions",
        "dumpprivkey",
        "importprivkey",
        "encryptwallet",
        "walletpassphrase",
        "walletlock",
    ] {
        let reply = v1(&backend, method, json!([]));
        assert_eq!(code(&reply), -32601, "{method}");
        assert_eq!(message(&reply), "Method not found (wallet disabled)");
    }
    let help = ok(&v1(&backend, "help", json!([])))
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!help.lines().any(|line| line == "getbalance"));
    assert!(help.lines().any(|line| line == "validateaddress"));
    assert_eq!(code(&v1(&backend, "help", json!(["getbalance"]))), -1);
}

#[test]
fn help_lists_and_describes_wallet_methods_when_enabled() {
    let backend = funded();
    let help = ok(&v1(&backend, "help", json!([])))
        .as_str()
        .unwrap()
        .to_owned();
    for name in ["getbalance", "sendtoaddress", "walletlock"] {
        assert!(help.lines().any(|line| line == name), "{name}");
    }
    let usage = ok(&v1(&backend, "help", json!(["sendtoaddress"])))
        .as_str()
        .unwrap()
        .to_owned();
    assert!(usage.starts_with("sendtoaddress address amount"), "{usage}");
}

#[test]
fn getnewaddress_honours_the_address_type() {
    let backend = funded();
    let address = |kind: &str| {
        ok(&v1(&backend, "getnewaddress", json!(["", kind])))
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert!(address("bech32").starts_with("bcrt1q"));
    assert!(address("bech32m").starts_with("bcrt1p"));
    assert!(address("legacy").starts_with(['m', 'n']));
    assert!(address("p2sh-segwit").starts_with('2'));
    let bech32 = ok(&v1(&backend, "getnewaddress", json!([])))
        .as_str()
        .unwrap()
        .to_owned();
    assert!(bech32.starts_with("bcrt1q"));
    assert_eq!(
        code(&v1(&backend, "getnewaddress", json!(["", "fancy"]))),
        -5
    );
}

#[test]
fn getbalance_and_getbalances_split_confirmed_and_pending() {
    let backend = funded();
    assert_eq!(ok(&v1(&backend, "getbalance", json!([]))), 1.5);
    assert_eq!(ok(&v1(&backend, "getbalance", json!(["*", 1]))), 1.0);
    assert_eq!(ok(&v1(&backend, "getbalance", json!(["*", 7]))), 0.0);
    assert_eq!(code(&v1(&backend, "getbalance", json!(["x"]))), -32);
    assert_eq!(code(&v1(&backend, "getbalance", json!(["*", -1]))), -8);

    let balances = ok(&v1(&backend, "getbalances", json!([]))).clone();
    assert_eq!(balances["mine"]["trusted"], 1.0);
    assert_eq!(balances["mine"]["untrusted_pending"], 0.5);
    assert_eq!(balances["mine"]["immature"], 0.0);
    assert!(text(&balances).contains("\"immature\":0.00000000"));
}

#[test]
fn listunspent_filters_by_confirmations_and_renders_rows() {
    let backend = funded();
    let confirmed = ok(&v1(&backend, "listunspent", json!([])))
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(confirmed.len(), 1);
    let row = &confirmed[0];
    assert_eq!(row["amount"], 1.0);
    assert_eq!(row["confirmations"], 6);
    assert_eq!(row["spendable"], true);
    assert_eq!(row["solvable"], true);
    assert_eq!(row["safe"], true);
    assert_eq!(row["vout"], 0);
    assert_eq!(row["address"], regtest_address(&p2wpkh_script(0xa1)));
    assert_eq!(row["scriptPubKey"], format!("0014{}", "a1".repeat(20)));

    let all = ok(&v1(&backend, "listunspent", json!([0])))
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(all.len(), 2);
    assert_eq!(
        code(&v1(
            &backend,
            "listunspent",
            json!([0, 9_999_999, [dest()]])
        )),
        -8
    );
}

#[test]
fn sendtoaddress_spends_funds_and_lists_the_send() {
    let backend = funded();
    let txid = ok(&v1(&backend, "sendtoaddress", json!([dest(), 0.25])))
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(txid.len(), 64);

    let list = ok(&v1(&backend, "listtransactions", json!(["*", 1])))
        .as_array()
        .unwrap()
        .clone();
    let send = &list[0];
    assert_eq!(send["category"], "send");
    assert_eq!(send["txid"], txid);
    assert_eq!(send["amount"], -0.25);
    assert_eq!(send["fee"], -0.000002);
    assert!(text(send).contains("\"amount\":-0.25000000"));

    assert_eq!(ok(&v1(&backend, "getbalance", json!(["*", 1]))), 0.0);
    assert_eq!(ok(&v1(&backend, "getbalance", json!([]))), 1.249998);
}

#[test]
fn sendtoaddress_fee_rate_is_sat_per_vbyte() {
    let backend = funded();
    let params = json!([dest(), 0.1, null, null, null, null, null, null, null, 2.5]);
    ok(&v1(&backend, "sendtoaddress", params));
    let last = ok(&v1(&backend, "listtransactions", json!([])))
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(last["fee"], -0.000005);
}

#[test]
fn sendtoaddress_validates_amount_and_address() {
    let backend = funded();
    let amount = |value: Value| code(&v1(&backend, "sendtoaddress", json!([dest(), value])));
    assert_eq!(amount(json!(0)), -3);
    assert_eq!(amount(json!(-1)), -3);
    assert_eq!(amount(json!(true)), -3);
    assert_eq!(amount(json!("0.000000001")), -3);
    assert_eq!(amount(json!("1e-8")), -3);
    assert_eq!(amount(json!(21_000_001)), -3);
    assert_eq!(amount(json!(10)), -6);
    assert_eq!(
        message(&v1(&backend, "sendtoaddress", json!([dest(), 0]))),
        "Invalid amount for send"
    );
    assert!(ok(&v1(&backend, "sendtoaddress", json!([dest(), "0.5"]))).is_string());
    assert_eq!(code(&v1(&backend, "sendtoaddress", json!(["nope", 1]))), -5);
    let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    assert_eq!(
        code(&v1(&backend, "sendtoaddress", json!([mainnet, 1]))),
        -5
    );
    assert_eq!(code(&v1(&backend, "sendtoaddress", json!([dest()]))), -8);
}

#[test]
fn listtransactions_returns_newest_last_with_count_and_skip() {
    let backend = funded();
    let all = ok(&v1(&backend, "listtransactions", json!([])))
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0]["amount"], 1.0);
    assert_eq!(all[0]["category"], "receive");
    assert!(all[0].get("fee").is_none());
    assert_eq!(all[0]["blockhash"].as_str().unwrap().len(), 64);

    let page = ok(&v1(&backend, "listtransactions", json!(["*", 2, 1])))
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0]["txid"], all[0]["txid"]);
    assert_eq!(page[1]["txid"], all[1]["txid"]);
    assert_eq!(
        code(&v1(&backend, "listtransactions", json!(["*", -1]))),
        -8
    );
    assert_eq!(
        ok(&v1(&backend, "listtransactions", json!(["other"]))),
        &json!([])
    );
}

#[test]
fn getwalletinfo_reports_fields_and_unlock_state_only_when_encrypted() {
    let backend = funded();
    let info = ok(&v1(&backend, "getwalletinfo", json!([]))).clone();
    assert_eq!(info["walletversion"], 169_900);
    assert_eq!(info["format"], "json");
    assert_eq!(info["balance"], 1.0);
    assert_eq!(info["unconfirmed_balance"], 0.5);
    assert_eq!(info["immature_balance"], 0.0);
    assert_eq!(info["txcount"], 3);
    assert_eq!(info["private_keys_enabled"], true);
    assert_eq!(info["descriptors"], false);
    assert!(info.get("unlocked_until").is_none());
}

#[test]
fn dumpprivkey_and_importprivkey_check_their_inputs() {
    let backend = funded();
    let legacy = ok(&v1(&backend, "getnewaddress", json!(["", "legacy"])))
        .as_str()
        .unwrap()
        .to_owned();
    let wif = ok(&v1(&backend, "dumpprivkey", json!([legacy])))
        .as_str()
        .unwrap()
        .to_owned();
    assert!(wif.starts_with("cMockKey"));

    let bech32 = ok(&v1(&backend, "getnewaddress", json!([])))
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(code(&v1(&backend, "dumpprivkey", json!([bech32]))), -3);
    assert_eq!(code(&v1(&backend, "dumpprivkey", json!(["nope"]))), -5);
    let unknown = regtest_address(&ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(
        [0x77; 20],
    )));
    let reply = v1(&backend, "dumpprivkey", json!([unknown]));
    assert_eq!(code(&reply), -4);
    assert!(message(&reply).contains("not known"));

    let secret = PrivateKey::from_slice(&[7u8; 32], Network::Regtest)
        .unwrap()
        .to_wif();
    assert!(ok(&v1(&backend, "importprivkey", json!([secret]))).is_null());
    assert_eq!(
        code(&v1(&backend, "importprivkey", json!(["not-a-wif"]))),
        -5
    );
}

#[test]
fn encryption_and_passphrase_flow_uses_core_error_codes() {
    let backend = funded();
    assert_eq!(code(&v1(&backend, "walletlock", json!([]))), -15);
    assert_eq!(
        code(&v1(&backend, "walletpassphrase", json!(["pw", 60]))),
        -15
    );
    assert_eq!(code(&v1(&backend, "encryptwallet", json!([""]))), -8);

    let encrypted = ok(&v1(&backend, "encryptwallet", json!(["hunter2"])))
        .as_str()
        .unwrap()
        .to_owned();
    assert!(encrypted.starts_with("wallet encrypted;"));
    assert_eq!(
        code(&v1(&backend, "encryptwallet", json!(["hunter2"]))),
        -15
    );

    let legacy = ok(&v1(&backend, "getnewaddress", json!(["", "legacy"])))
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        code(&v1(&backend, "sendtoaddress", json!([dest(), 0.1]))),
        -13
    );
    assert_eq!(code(&v1(&backend, "dumpprivkey", json!([legacy]))), -13);
    let info = ok(&v1(&backend, "getwalletinfo", json!([]))).clone();
    assert_eq!(info["unlocked_until"], 0);

    assert_eq!(
        code(&v1(&backend, "walletpassphrase", json!(["wrong", 60]))),
        -14
    );
    assert!(ok(&v1(&backend, "walletpassphrase", json!(["hunter2", 60]))).is_null());
    let info = ok(&v1(&backend, "getwalletinfo", json!([]))).clone();
    assert!(info["unlocked_until"].as_u64().unwrap() > 0);
    assert!(ok(&v1(&backend, "sendtoaddress", json!([dest(), 0.1]))).is_string());

    assert!(ok(&v1(&backend, "walletlock", json!([]))).is_null());
    assert_eq!(
        code(&v1(&backend, "sendtoaddress", json!([dest(), 0.1]))),
        -13
    );
}
