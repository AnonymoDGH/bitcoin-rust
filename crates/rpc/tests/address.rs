mod common;

use bitcoin::hashes::Hash;
use bitcoin::{PubkeyHash, ScriptHash};
use btc_primitives::{OutPoint, ScriptBuf, TxOut, Txid};
use btc_rpc::dispatch;
use btc_wallet::address::{encode_address, encode_address_with, Network};
use common::{cx_params, p2wpkh_script, regtest_address, MockBackend};
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

#[test]
fn validateaddress_describes_witness_v0_keyhash() {
    let backend = MockBackend::new();
    let address = regtest_address(&p2wpkh_script(0x33));
    let reply = ok(&v1(&backend, "validateaddress", json!([address]))).clone();
    assert_eq!(reply["isvalid"], true);
    assert_eq!(reply["address"], address);
    assert_eq!(reply["scriptPubKey"], format!("0014{}", "33".repeat(20)));
    assert_eq!(reply["isscript"], false);
    assert_eq!(reply["iswitness"], true);
    assert_eq!(reply["witness_version"], 0);
    assert_eq!(reply["witness_program"], "33".repeat(20));
}

#[test]
fn validateaddress_describes_legacy_and_script_hash_addresses() {
    let backend = MockBackend::new();
    let p2pkh = regtest_address(&ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(
        [0x22; 20],
    )));
    let reply = ok(&v1(&backend, "validateaddress", json!([p2pkh]))).clone();
    assert_eq!(reply["isscript"], false);
    assert_eq!(reply["iswitness"], false);
    assert!(reply.get("witness_version").is_none());

    let p2sh = regtest_address(&ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(
        [0x11; 20],
    )));
    let reply = ok(&v1(&backend, "validateaddress", json!([p2sh]))).clone();
    assert_eq!(reply["isscript"], true);
    assert_eq!(reply["iswitness"], false);
}

#[test]
fn validateaddress_describes_taproot() {
    let backend = MockBackend::new();
    let mut bytes = vec![0x51, 0x20];
    bytes.extend([0x44; 32]);
    let taproot = regtest_address(&ScriptBuf::from_bytes(bytes));
    let reply = ok(&v1(&backend, "validateaddress", json!([taproot]))).clone();
    assert_eq!(reply["isscript"], true);
    assert_eq!(reply["iswitness"], true);
    assert_eq!(reply["witness_version"], 1);
    assert_eq!(reply["witness_program"], "44".repeat(32));
}

#[test]
fn validateaddress_reports_invalid_addresses_with_only_isvalid() {
    let backend = MockBackend::new();
    for bogus in ["bogus", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"] {
        let reply = ok(&v1(&backend, "validateaddress", json!([bogus]))).clone();
        assert_eq!(reply, json!({ "isvalid": false }), "{bogus}");
    }
}

#[test]
fn custom_chain_params_drive_every_address_encoding() {
    let backend = MockBackend::new().with_address_params(cx_params());
    let script = p2wpkh_script(0x66);
    let address = encode_address_with(&cx_params(), &script).unwrap();
    assert!(address.starts_with("cx1q"), "{address}");

    let hashes = ok(&v1(&backend, "generatetoaddress", json!([1, address])))
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        code(&v1(
            &backend,
            "generatetoaddress",
            json!([1, regtest_address(&script)])
        )),
        -5
    );

    let block = ok(&v1(&backend, "getblock", json!([hashes[0], 2]))).clone();
    assert_eq!(
        block["tx"][0]["vout"][0]["scriptPubKey"]["address"],
        address
    );

    let valid = ok(&v1(&backend, "validateaddress", json!([address]))).clone();
    assert_eq!(valid["isvalid"], true);
    assert_eq!(valid["address"], address);
    let other = ok(&v1(
        &backend,
        "validateaddress",
        json!([regtest_address(&script)]),
    ))
    .clone();
    assert_eq!(other, json!({ "isvalid": false }));
}

#[test]
fn amounts_serialize_with_exactly_eight_decimals() {
    let backend = MockBackend::new();
    let coinbase_txid = backend.with(|c| c.blocks[2].txdata[0].txid().to_string());
    let reply = v1(&backend, "gettxout", json!([coinbase_txid, 0]));
    let text = serde_json::to_string(&reply).unwrap();
    assert!(text.contains("\"value\":50.00000000"), "{text}");
    assert_eq!(ok(&reply)["value"], 50.0);

    let dust = OutPoint {
        txid: Txid::all_zeros(),
        vout: 0,
    };
    backend.with(|c| {
        c.utxos
            .push((dust, TxOut::new(1, p2wpkh_script(0x01)), 1, false))
    });
    let reply = v1(&backend, "gettxout", json!([dust.txid.to_string(), 0]));
    let text = serde_json::to_string(&reply).unwrap();
    assert!(text.contains("\"value\":0.00000001"), "{text}");
}

#[test]
fn mainnet_and_regtest_addresses_encode_with_the_node_network() {
    let script = p2wpkh_script(0x01);
    assert!(encode_address(Network::Main, &script)
        .unwrap()
        .starts_with("bc1q"));
    assert!(encode_address(Network::Regtest, &script)
        .unwrap()
        .starts_with("bcrt1q"));
}
