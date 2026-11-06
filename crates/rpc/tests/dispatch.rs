mod common;

use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hex::FromHex;
use bitcoin::OutPoint;
use btc_primitives::{Block, BlockHeader, Tx, Txid};
use btc_rpc::dispatch;
use common::{coinbase, make_block, p2wpkh_script, regtest_address, spend, MockBackend};
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

fn hash_at(backend: &MockBackend, height: usize) -> String {
    backend.with(|c| c.blocks[height].block_hash().to_string())
}

fn txid_of_block(backend: &MockBackend, height: usize, index: usize) -> String {
    backend.with(|c| c.blocks[height].txdata[index].txid().to_string())
}

#[test]
fn getblockcount_and_bestblockhash_report_tip() {
    let backend = MockBackend::new();
    assert_eq!(ok(&v1(&backend, "getblockcount", json!([]))), 2);
    assert_eq!(
        ok(&v1(&backend, "getbestblockhash", json!([]))),
        &hash_at(&backend, 2)
    );
    let reply = v1(&backend, "getblockcount", json!([]));
    assert_eq!(reply["id"], 1);
}

#[test]
fn getblockhash_maps_height_and_checks_range() {
    let backend = MockBackend::new();
    assert_eq!(
        ok(&v1(&backend, "getblockhash", json!([1]))),
        &hash_at(&backend, 1)
    );
    assert_eq!(code(&v1(&backend, "getblockhash", json!([3]))), -8);
    assert_eq!(code(&v1(&backend, "getblockhash", json!([-1]))), -8);
    assert_eq!(code(&v1(&backend, "getblockhash", json!(["1"]))), -3);
}

#[test]
fn getblock_verbosity_zero_returns_serialized_block() {
    let backend = MockBackend::new();
    let hex = ok(&v1(&backend, "getblock", json!([hash_at(&backend, 1), 0])))
        .as_str()
        .unwrap()
        .to_owned();
    let block: Block = deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap();
    assert_eq!(block.block_hash().to_string(), hash_at(&backend, 1));
    assert_eq!(block.txdata.len(), 1);
}

#[test]
fn getblock_verbosity_one_is_the_default_and_lists_txids() {
    let backend = MockBackend::new();
    let hash = hash_at(&backend, 2);
    let default = ok(&v1(&backend, "getblock", json!([hash.clone()]))).clone();
    let explicit = ok(&v1(&backend, "getblock", json!([hash.clone(), 1]))).clone();
    assert_eq!(default, explicit);

    assert_eq!(explicit["hash"], hash);
    assert_eq!(explicit["height"], 2);
    assert_eq!(explicit["confirmations"], 1);
    assert_eq!(explicit["nTx"], 2);
    assert_eq!(explicit["tx"][0], txid_of_block(&backend, 2, 0));
    assert_eq!(explicit["tx"][1], txid_of_block(&backend, 2, 1));
    assert_eq!(explicit["previousblockhash"], hash_at(&backend, 1));
    assert_eq!(explicit["versionHex"], "20000000");
    assert_eq!(explicit["bits"], "207fffff");
    assert!(explicit["size"].as_u64().unwrap() > 80);
    assert!(explicit["weight"].as_u64().unwrap() >= explicit["strippedsize"].as_u64().unwrap() * 3);
}

#[test]
fn getblock_verbosity_two_decodes_transactions() {
    let backend = MockBackend::new();
    let block = ok(&v1(&backend, "getblock", json!([hash_at(&backend, 2), 2]))).clone();
    let coinbase_tx = &block["tx"][0];
    assert_eq!(coinbase_tx["txid"], txid_of_block(&backend, 2, 0));
    assert!(coinbase_tx["vin"][0]["coinbase"].is_string());
    assert_eq!(coinbase_tx["vout"][0]["value"], 50.0);
    assert_eq!(coinbase_tx["vout"][0]["n"], 0);
    assert_eq!(
        coinbase_tx["vout"][0]["scriptPubKey"]["type"],
        "witness_v0_keyhash"
    );
    assert_eq!(
        coinbase_tx["vout"][0]["scriptPubKey"]["address"],
        regtest_address(&p2wpkh_script(0x33))
    );

    let spending_tx = &block["tx"][1];
    let prev = backend.with(|c| c.blocks[1].txdata[0].txid().to_string());
    assert_eq!(spending_tx["vin"][0]["txid"], prev);
    assert_eq!(spending_tx["vin"][0]["vout"], 0);
    assert_eq!(spending_tx["vout"][0]["value"], 49.0);
    assert!(spending_tx["vin"][0].get("coinbase").is_none());
    assert!(spending_tx.get("hex").is_none());
}

#[test]
fn getblock_errors_for_missing_block_bad_hash_and_bad_verbosity() {
    let backend = MockBackend::new();
    let unknown = "11".repeat(32);
    assert_eq!(code(&v1(&backend, "getblock", json!([unknown]))), -5);
    assert_eq!(code(&v1(&backend, "getblock", json!(["zz"]))), -8);
    assert_eq!(
        code(&v1(&backend, "getblock", json!([hash_at(&backend, 0), 3]))),
        -8
    );
    assert_eq!(code(&v1(&backend, "getblock", json!([]))), -8);
}

#[test]
fn getblock_reports_negative_confirmations_for_stale_blocks() {
    let backend = MockBackend::new();
    let stale = make_block(
        backend.with(|c| c.blocks[0].block_hash()),
        1_500,
        vec![coinbase(p2wpkh_script(0x77), 50_0000_0000, 9)],
    );
    let stale_hash = stale.block_hash().to_string();
    backend.with(|c| c.stale.push((stale, 1)));
    let reply = ok(&v1(&backend, "getblock", json!([stale_hash]))).clone();
    assert_eq!(reply["confirmations"], -1);
    assert_eq!(reply["height"], 1);
}

#[test]
fn getblockheader_verbose_and_hex_forms() {
    let backend = MockBackend::new();
    let hash = hash_at(&backend, 1);
    let verbose = ok(&v1(&backend, "getblockheader", json!([hash.clone()]))).clone();
    assert_eq!(verbose["hash"], hash);
    assert_eq!(verbose["height"], 1);
    assert_eq!(verbose["confirmations"], 2);
    assert_eq!(verbose["time"], 1001);
    assert_eq!(verbose["previousblockhash"], hash_at(&backend, 0));
    let difficulty = verbose["difficulty"].as_f64().unwrap();
    assert!((difficulty - 4.656_542_373_906_925e-10).abs() < 1e-18);

    let hex = ok(&v1(&backend, "getblockheader", json!([hash, false])))
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(hex.len(), 160);
    let header: BlockHeader = deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap();
    assert_eq!(header.time, 1001);

    assert_eq!(
        code(&v1(&backend, "getblockheader", json!(["22".repeat(32)]))),
        -5
    );
}

#[test]
fn getblockchaininfo_reports_chain_state() {
    let backend = MockBackend::new();
    let info = ok(&v1(&backend, "getblockchaininfo", json!([]))).clone();
    assert_eq!(info["chain"], "regtest");
    assert_eq!(info["blocks"], 2);
    assert_eq!(info["headers"], 2);
    assert_eq!(info["bestblockhash"], hash_at(&backend, 2));
    assert_eq!(info["mediantime"], 1002);
    assert_eq!(info["chainwork"].as_str().unwrap().len(), 64);
    assert!(info["difficulty"].is_number());
}

#[test]
fn getrawmempool_lists_txids_and_rejects_verbose() {
    let backend = MockBackend::new();
    let pool = ok(&v1(&backend, "getrawmempool", json!([]))).clone();
    let txid = backend.with(|c| c.mempool[0].txid().to_string());
    assert_eq!(pool, json!([txid]));
    assert_eq!(ok(&v1(&backend, "getrawmempool", json!([false]))), &pool);
    assert_eq!(code(&v1(&backend, "getrawmempool", json!([true]))), -1);
}

#[test]
fn getmempoolinfo_reports_size_and_bytes() {
    let backend = MockBackend::new();
    let info = ok(&v1(&backend, "getmempoolinfo", json!([]))).clone();
    assert_eq!(info["size"], 1);
    assert!(info["bytes"].as_u64().unwrap() > 0);
}

#[test]
fn getrawtransaction_hex_verbose_and_missing() {
    let backend = MockBackend::new();
    let txid = txid_of_block(&backend, 2, 0);
    let hex = ok(&v1(&backend, "getrawtransaction", json!([txid.clone()])))
        .as_str()
        .unwrap()
        .to_owned();
    let tx: Tx = deserialize(&Vec::<u8>::from_hex(&hex).unwrap()).unwrap();
    assert_eq!(tx.txid().to_string(), txid);

    let verbose = ok(&v1(
        &backend,
        "getrawtransaction",
        json!([txid.clone(), true]),
    ))
    .clone();
    assert_eq!(verbose["txid"], txid);
    assert_eq!(verbose["hex"], hex);
    assert_eq!(verbose["vout"][0]["value"], 50.0);

    assert_eq!(
        code(&v1(&backend, "getrawtransaction", json!(["33".repeat(32)]))),
        -5
    );
    assert_eq!(
        code(&v1(
            &backend,
            "getrawtransaction",
            json!([txid, false, "44".repeat(32)])
        )),
        -8
    );
}

#[test]
fn sendrawtransaction_accepts_valid_and_reports_rejections() {
    let backend = MockBackend::new();
    let prevout = OutPoint {
        txid: txid_of_block(&backend, 2, 0).parse::<Txid>().unwrap(),
        vout: 0,
    };
    let tx = spend(prevout, 49_0000_0000, p2wpkh_script(0x88));
    let hex = serialize_hex(&tx);
    let before = backend.with(|c| c.mempool.len());

    let txid = ok(&v1(&backend, "sendrawtransaction", json!([hex.clone()]))).clone();
    assert_eq!(txid, tx.txid().to_string());
    assert_eq!(backend.with(|c| c.mempool.len()), before + 1);

    assert_eq!(
        code(&v1(&backend, "sendrawtransaction", json!(["zz"]))),
        -22
    );
    assert_eq!(
        code(&v1(&backend, "sendrawtransaction", json!(["00"]))),
        -22
    );

    backend.with(|c| c.reject_tx = Some("bad-txns-inputs-missingorspent".into()));
    let reply = v1(&backend, "sendrawtransaction", json!([hex]));
    assert_eq!(code(&reply), -26);
    assert_eq!(reply["error"]["message"], "bad-txns-inputs-missingorspent");
}

#[test]
fn submitblock_returns_null_or_rejection_reason() {
    let backend = MockBackend::new();
    let block = make_block(
        backend.with(|c| c.blocks[2].block_hash()),
        1_010,
        vec![coinbase(p2wpkh_script(0x99), 50_0000_0000, 3)],
    );
    let hex = serialize_hex(&block);
    assert!(ok(&v1(&backend, "submitblock", json!([hex.clone()]))).is_null());
    assert_eq!(backend.with(|c| c.blocks.len()), 4);

    backend.with(|c| c.reject_block = Some("duplicate".into()));
    assert_eq!(ok(&v1(&backend, "submitblock", json!([hex]))), "duplicate");

    assert_eq!(code(&v1(&backend, "submitblock", json!(["zz"]))), -22);
}

#[test]
fn generatetoaddress_mines_to_the_decoded_script() {
    let backend = MockBackend::new();
    let address = regtest_address(&p2wpkh_script(0x66));
    let hashes = ok(&v1(&backend, "generatetoaddress", json!([2, address]))).clone();
    assert_eq!(hashes.as_array().unwrap().len(), 2);
    assert_eq!(backend.with(|c| c.blocks.len()), 5);
    assert_eq!(hashes[1], hash_at(&backend, 4));

    let reply = v1(&backend, "generatetoaddress", json!([1, "not-an-address"]));
    assert_eq!(code(&reply), -5);
    assert_eq!(reply["error"]["message"], "Error: Invalid address");

    let mainnet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    assert_eq!(
        code(&v1(&backend, "generatetoaddress", json!([1, mainnet]))),
        -5
    );
}

#[test]
fn gettxout_returns_unspent_output_or_null() {
    let backend = MockBackend::new();
    let txid = txid_of_block(&backend, 2, 0);
    let out = ok(&v1(&backend, "gettxout", json!([txid.clone(), 0]))).clone();
    assert_eq!(out["bestblock"], hash_at(&backend, 2));
    assert_eq!(out["confirmations"], 1);
    assert_eq!(out["value"], 50.0);
    assert_eq!(out["coinbase"], true);
    assert_eq!(out["scriptPubKey"]["type"], "witness_v0_keyhash");

    assert!(ok(&v1(&backend, "gettxout", json!([txid, 5]))).is_null());
    assert_eq!(
        code(&v1(
            &backend,
            "gettxout",
            json!([txid_of_block(&backend, 2, 0)])
        )),
        -8
    );
}

#[test]
fn stop_sets_the_backend_flag() {
    let backend = MockBackend::new();
    assert_eq!(
        ok(&v1(&backend, "stop", json!([]))),
        "Bitcoin Core stopping"
    );
    assert!(backend.with(|c| c.stopped));
}

#[test]
fn help_lists_methods_and_describes_one() {
    let backend = MockBackend::new();
    let list = ok(&v1(&backend, "help", json!([])))
        .as_str()
        .unwrap()
        .to_owned();
    assert!(list.lines().any(|line| line == "getblock"));
    assert!(list.lines().any(|line| line == "uptime"));
    assert_eq!(
        ok(&v1(&backend, "help", json!(["getblock"]))),
        "getblock blockhash ( verbosity )"
    );
    assert_eq!(code(&v1(&backend, "help", json!(["nope"]))), -1);
}

#[test]
fn uptime_returns_a_number_of_seconds() {
    let backend = MockBackend::new();
    assert!(ok(&v1(&backend, "uptime", json!([]))).as_u64().is_some());
}

#[test]
fn unknown_method_is_method_not_found() {
    let backend = MockBackend::new();
    let reply = v1(&backend, "nosuchmethod", json!([]));
    assert_eq!(code(&reply), -32601);
    assert_eq!(reply["error"]["message"], "Method not found");
    assert!(reply["result"].is_null());
}

#[test]
fn named_parameters_are_mapped_to_positions() {
    let backend = MockBackend::new();
    assert_eq!(
        ok(&v1(&backend, "getblockhash", json!({ "height": 1 }))),
        &hash_at(&backend, 1)
    );
    let raw = ok(&v1(
        &backend,
        "getblock",
        json!({ "blockhash": hash_at(&backend, 0), "verbosity": 0 }),
    ))
    .clone();
    assert!(raw.is_string());
    let optional_null = ok(&v1(
        &backend,
        "getblock",
        json!({ "blockhash": hash_at(&backend, 0), "verbosity": null }),
    ))
    .clone();
    assert_eq!(optional_null["height"], 0);

    assert_eq!(
        code(&v1(
            &backend,
            "getblockhash",
            json!({ "height": 1, "bogus": 2 })
        )),
        -8
    );
    assert_eq!(code(&v1(&backend, "getblockhash", json!({}))), -8);
}

#[test]
fn version_2_replies_carry_jsonrpc_and_echo_id() {
    let backend = MockBackend::new();
    let reply = dispatch(
        &backend,
        json!({ "jsonrpc": "2.0", "id": "abc", "method": "getblockcount", "params": [] }),
    );
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], "abc");
    assert_eq!(reply["result"], 2);
    assert!(reply.get("error").is_none());

    let failed = dispatch(
        &backend,
        json!({ "jsonrpc": "2.0", "id": 7, "method": "nosuchmethod" }),
    );
    assert_eq!(failed["jsonrpc"], "2.0");
    assert_eq!(failed["id"], 7);
    assert_eq!(failed["error"]["code"], -32601);
    assert!(failed.get("result").is_none());
}

#[test]
fn version_1_replies_carry_result_and_error_keys() {
    let backend = MockBackend::new();
    let ok_reply = dispatch(&backend, json!({ "id": 3, "method": "getblockcount" }));
    assert_eq!(ok_reply["result"], 2);
    assert!(ok_reply["error"].is_null());
    assert_eq!(ok_reply["id"], 3);
    assert!(ok_reply.get("jsonrpc").is_none());

    let err_reply = dispatch(
        &backend,
        json!({ "id": 4, "method": "getblockhash", "params": [99] }),
    );
    assert!(err_reply["result"].is_null());
    assert_eq!(err_reply["error"]["code"], -8);
    assert_eq!(err_reply["id"], 4);
}

#[test]
fn notification_gets_no_reply() {
    let backend = MockBackend::new();
    let reply = dispatch(
        &backend,
        json!({ "jsonrpc": "2.0", "method": "getblockcount" }),
    );
    assert!(reply.is_null());
}

#[test]
fn batch_replies_in_order_and_skips_notifications() {
    let backend = MockBackend::new();
    let reply = dispatch(
        &backend,
        json!([
            { "method": "getblockcount", "id": 1 },
            { "jsonrpc": "2.0", "method": "getblockcount" },
            { "method": "getblockhash", "params": [99], "id": 3 },
        ]),
    );
    let items = reply.as_array().expect("batch reply is an array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["result"], 2);
    assert_eq!(items[0]["id"], 1);
    assert_eq!(items[1]["error"]["code"], -8);
    assert_eq!(items[1]["id"], 3);
}

#[test]
fn batch_of_only_notifications_and_empty_batch() {
    let backend = MockBackend::new();
    assert!(dispatch(
        &backend,
        json!([{ "jsonrpc": "2.0", "method": "getblockcount" }])
    )
    .is_null());
    assert_eq!(dispatch(&backend, json!([])), json!([]));
}

#[test]
fn batch_element_that_is_not_an_object_is_an_invalid_request() {
    let backend = MockBackend::new();
    let reply = dispatch(
        &backend,
        json!([42, { "method": "getblockcount", "id": 5 }]),
    );
    let items = reply.as_array().unwrap();
    assert_eq!(items[0]["error"]["code"], -32600);
    assert!(items[0].get("id").is_none());
    assert_eq!(items[1]["result"], 2);
    assert_eq!(items[1]["id"], 5);
}

#[test]
fn malformed_envelopes_are_rejected() {
    let backend = MockBackend::new();
    assert_eq!(code(&dispatch(&backend, json!(42))), -32700);
    assert_eq!(
        code(&dispatch(
            &backend,
            json!({ "method": "getblockcount", "jsonrpc": "3.0" })
        )),
        -32600
    );
    assert_eq!(
        code(&dispatch(
            &backend,
            json!({ "method": "getblockcount", "jsonrpc": 2 })
        )),
        -32600
    );
    assert_eq!(code(&dispatch(&backend, json!({ "id": 1 }))), -32600);
    assert_eq!(code(&dispatch(&backend, json!({ "method": 5 }))), -32600);
    assert_eq!(
        code(&dispatch(
            &backend,
            json!({ "method": "getblockcount", "params": "x" })
        )),
        -32600
    );
}

#[test]
fn argument_count_and_types_are_checked() {
    let backend = MockBackend::new();
    assert_eq!(code(&v1(&backend, "getblockcount", json!([1, 2]))), -8);
    assert_eq!(code(&v1(&backend, "getblockhash", json!([]))), -8);
    assert_eq!(code(&v1(&backend, "getblock", json!([42]))), -3);
    assert_eq!(code(&v1(&backend, "getblockhash", json!([1.5]))), -3);
}
