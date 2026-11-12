//! Stealth receive/spend flows between in-process nodes: the payer's blocks
//! are relayed to the recipient, like peers on a network.

use super::*;
use btc_chain::chainstate::MemBlockStore;
use btc_consensus::regtest_genesis_block;
use btc_validation::coins::CoinsViewMemory;
use serde_json::{json, Value};
use std::path::PathBuf;

const PASS: &str = "correct horse";

struct Peer {
    rpc: NodeRpc,
    wallet_path: PathBuf,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.wallet_path);
    }
}

fn peer(name: &str, with_wallet: bool) -> Peer {
    let mut node = Node::new(
        ChainParams::regtest(),
        regtest_genesis_block(),
        Box::new(CoinsViewMemory::new()),
        Box::<MemBlockStore>::default(),
    )
    .unwrap();
    let wallet_path =
        std::env::temp_dir().join(format!("btc-stealth-flow-{name}-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&wallet_path);
    if with_wallet {
        node.attach_wallet(Wallet::create(&wallet_path).unwrap()).unwrap();
    }
    Peer { rpc: NodeRpc::new(node.shared(), Arc::new(Notify::new())), wallet_path }
}

fn call(p: &Peer, method: &str, params: Value) -> Value {
    btc_rpc::dispatch(
        &p.rpc,
        json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}),
    )
}

fn ok(p: &Peer, method: &str, params: Value) -> Value {
    let reply = call(p, method, params);
    assert!(reply["error"].is_null(), "{method} failed: {reply}");
    reply["result"].clone()
}

fn miner(byte: u8) -> String {
    use bitcoin::WPubkeyHash;
    use bitcoin_hashes::Hash as _;
    let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([byte; 20]));
    btc_wallet::address::encode_address(btc_wallet::address::Network::Regtest, &script).unwrap()
}

fn mine(p: &Peer, n: u32, addr: &str) {
    let hashes = ok(p, "generatetoaddress", json!([n, addr]));
    assert_eq!(hashes.as_array().unwrap().len(), n as usize);
}

/// Delivers `from`'s active-chain blocks at `heights` to `to`, in order.
fn relay(from: &Peer, to: &Peer, heights: std::ops::RangeInclusive<u32>) {
    for h in heights {
        let block = from.rpc.with_node(|n| {
            let hash = n.chainstate.block_hash_at(h).expect("height on active chain");
            n.chainstate.get_block(&hash).expect("block stored")
        });
        to.rpc.with_node(|n| n.submit_block(&block)).expect("peer accepts block");
    }
}

fn balance(p: &Peer) -> f64 {
    ok(p, "getbalance", json!(["*", 1])).as_f64().unwrap()
}

fn unspent_amounts(p: &Peer) -> Vec<f64> {
    let rows = ok(p, "listunspent", json!([1]));
    let mut v: Vec<f64> =
        rows.as_array().unwrap().iter().map(|r| r["amount"].as_f64().unwrap()).collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v
}

fn stealth_rows(p: &Peer) -> Vec<Value> {
    ok(p, "liststealthutxos", json!([])).as_array().unwrap().clone()
}

fn pending(p: &Peer) -> usize {
    p.rpc.with_node(|n| n.wallet.as_ref().unwrap().pending_stealth_count())
}

fn reopen_wallet(p: &Peer) {
    p.rpc.with_node(|n| {
        drop(n.wallet.take());
        n.attach_wallet(Wallet::open(&p.wallet_path).unwrap()).unwrap();
    });
}

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

/// Funded payer `a` (101 blocks of coinbases) and recipient `b` on the same chain.
fn funded_pair(tag: &str) -> (Peer, Peer) {
    let a = peer(&format!("{tag}-a"), true);
    let b = peer(&format!("{tag}-b"), true);
    let a_addr = ok(&a, "getnewaddress", json!([])).as_str().unwrap().to_owned();
    mine(&a, 101, &a_addr);
    relay(&a, &b, 1..=101);
    (a, b)
}

#[test]
fn recipient_receives_and_spends_stealth_payment() {
    let (a, b) = funded_pair("flow");
    let stealth = ok(&b, "getnewstealthaddress", json!([]));

    ok(&a, "sendtostealthaddress", json!([stealth.as_str().unwrap(), 1.0]));
    mine(&a, 1, &miner(7));
    relay(&a, &b, 102..=102);

    // B sees the payment as an ordinary coin, consistently everywhere.
    assert!(approx(balance(&b), 1.0), "getbalance: {}", balance(&b));
    assert_eq!(unspent_amounts(&b), vec![1.0], "listunspent");
    let rows = stealth_rows(&b);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["spendable"], true);
    assert!(approx(rows[0]["amount"].as_f64().unwrap(), 1.0));
    assert!(stealth_rows(&a).is_empty(), "payer does not claim the payment");

    // The imported key survives a wallet reopen.
    reopen_wallet(&b);
    assert!(approx(balance(&b), 1.0));

    // B spends it with sendtoaddress back to A.
    let a_dest = ok(&a, "getnewaddress", json!([])).as_str().unwrap().to_owned();
    ok(&b, "sendtoaddress", json!([a_dest, 0.4]));
    mine(&b, 1, &miner(8));
    relay(&b, &a, 103..=103);

    let b_left = balance(&b);
    assert!(b_left < 0.6 && b_left > 0.599, "B keeps change minus fee: {b_left}");
    assert!(stealth_rows(&b).is_empty(), "spent stealth coin is gone");
    assert!(unspent_amounts(&a).iter().any(|x| approx(*x, 0.4)), "A received 0.4");
}

#[test]
fn unconfirmed_stealth_payment_is_listed_but_not_spendable() {
    let (a, b) = funded_pair("mempool");
    let stealth = ok(&b, "getnewstealthaddress", json!([]));
    ok(&a, "sendtostealthaddress", json!([stealth.as_str().unwrap(), 1.0]));
    // Hand the unconfirmed transaction to B's mempool.
    let tx = a.rpc.with_node(|n| n.mempool.sorted_by_fee_rate()[0].tx.clone());
    b.rpc.with_node(|n| n.submit_tx(tx)).unwrap();
    let rows = ok(&b, "liststealthutxos", json!([0]));
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["confirmations"], 0);
    assert_eq!(rows[0]["spendable"], false, "foreign unconfirmed coins are not trusted");
    assert!(approx(balance(&b), 0.0));
}

#[test]
fn locked_wallet_credits_stealth_payment_after_unlock() {
    let (a, b) = funded_pair("locked");
    let stealth = ok(&b, "getnewstealthaddress", json!([]));
    ok(&b, "encryptwallet", json!([PASS]));

    ok(&a, "sendtostealthaddress", json!([stealth.as_str().unwrap(), 1.0]));
    mine(&a, 1, &miner(7));
    relay(&a, &b, 102..=102);

    // Detected only as a queued payment: nothing spendable yet.
    assert_eq!(pending(&b), 1);
    assert!(approx(balance(&b), 0.0));
    assert!(stealth_rows(&b).is_empty());

    // The queue survives a restart (reopen the locked wallet file).
    reopen_wallet(&b);
    assert_eq!(pending(&b), 1);

    let a_dest = ok(&a, "getnewaddress", json!([])).as_str().unwrap().to_owned();
    let locked = call(&b, "sendtoaddress", json!([a_dest, 0.4]));
    assert!(!locked["error"].is_null(), "locked wallet cannot spend");

    ok(&b, "walletpassphrase", json!([PASS, 600]));
    assert_eq!(pending(&b), 0);
    assert!(approx(balance(&b), 1.0), "credited on unlock: {}", balance(&b));
    let rows = stealth_rows(&b);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["spendable"], true);

    ok(&b, "sendtoaddress", json!([a_dest, 0.4]));
    mine(&b, 1, &miner(8));
    relay(&b, &a, 103..=103);
    let b_left = balance(&b);
    assert!(b_left < 0.6 && b_left > 0.599, "{b_left}");
    assert!(stealth_rows(&b).is_empty(), "spent coin is gone");
}

#[test]
fn stealth_payment_while_unlocked_then_wallet_locks() {
    let (a, b) = funded_pair("relock");
    let stealth = ok(&b, "getnewstealthaddress", json!([]));
    ok(&b, "encryptwallet", json!([PASS]));
    ok(&b, "walletpassphrase", json!([PASS, 600]));

    ok(&a, "sendtostealthaddress", json!([stealth.as_str().unwrap(), 1.0]));
    mine(&a, 1, &miner(7));
    relay(&a, &b, 102..=102);
    assert_eq!(pending(&b), 0, "scanned immediately while unlocked");
    assert!(approx(balance(&b), 1.0));

    ok(&b, "walletlock", json!([]));
    let rows = stealth_rows(&b);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["spendable"], false, "cannot sign while locked");
}

#[test]
fn reorg_removes_then_restores_stealth_coin() {
    let (a, b) = funded_pair("reorg");
    let c = peer("reorg-c", false);
    relay(&a, &c, 1..=101);
    let stealth = ok(&b, "getnewstealthaddress", json!([]));

    ok(&a, "sendtostealthaddress", json!([stealth.as_str().unwrap(), 1.0]));
    mine(&a, 1, &miner(7)); // height 102 carries the payment
    relay(&a, &b, 102..=102);
    assert!(approx(balance(&b), 1.0));

    // A heavier competing chain without the payment displaces it.
    mine(&c, 2, &miner(9));
    relay(&c, &b, 102..=103);
    assert_eq!(b.rpc.with_node(|n| n.chainstate.height()), 103);
    assert!(approx(balance(&b), 0.0), "coin dropped with its block: {}", balance(&b));
    assert!(stealth_rows(&b).is_empty());
    assert!(unspent_amounts(&b).is_empty());

    // The original branch overtakes again: the payment is re-found.
    mine(&a, 2, &miner(7));
    relay(&a, &b, 103..=104);
    assert_eq!(b.rpc.with_node(|n| n.chainstate.height()), 104);
    assert!(approx(balance(&b), 1.0), "re-added after reorg: {}", balance(&b));
    assert_eq!(stealth_rows(&b).len(), 1);
    assert_eq!(unspent_amounts(&b), vec![1.0]);

    // ...and still spendable.
    let a_dest = ok(&a, "getnewaddress", json!([])).as_str().unwrap().to_owned();
    ok(&b, "sendtoaddress", json!([a_dest, 0.4]));
}

#[test]
fn invalidate_block_notifies_wallet() {
    let (a, b) = funded_pair("inval");
    let stealth = ok(&b, "getnewstealthaddress", json!([]));
    ok(&a, "sendtostealthaddress", json!([stealth.as_str().unwrap(), 1.0]));
    mine(&a, 1, &miner(7));
    relay(&a, &b, 102..=102);
    assert!(approx(balance(&b), 1.0));
    let tip = b.rpc.with_node(|n| n.chainstate.tip_hash());
    b.rpc.with_node(|n| n.invalidate_block(&tip)).unwrap();
    assert!(approx(balance(&b), 0.0));
}

#[test]
fn wallet_without_stealth_scan_flag_rescans_chain_on_attach() {
    // A wallet written before stealth payments were imported (flag absent)
    // finds payments already buried in blocks it had "seen".
    let (a, b) = funded_pair("rescan");
    let stealth = ok(&b, "getnewstealthaddress", json!([]));
    ok(&a, "sendtostealthaddress", json!([stealth.as_str().unwrap(), 1.0]));
    mine(&a, 1, &miner(7));
    // Detach B's wallet before it sees the block; then claim it already
    // processed height 102 and strip the flag, as an old wallet file would.
    b.rpc.with_node(|n| drop(n.wallet.take()));
    relay(&a, &b, 102..=102);
    let mut file: Value = serde_json::from_slice(&std::fs::read(&b.wallet_path).unwrap()).unwrap();
    let tip = b.rpc.with_node(|n| n.chainstate.tip_hash());
    file["best_block"] = json!({"hash": tip.to_string(), "height": 102});
    file.as_object_mut().unwrap().remove("stealth_scanned");
    std::fs::write(&b.wallet_path, serde_json::to_vec(&file).unwrap()).unwrap();
    b.rpc.with_node(|n| n.attach_wallet(Wallet::open(&b.wallet_path).unwrap()).unwrap());
    assert!(approx(balance(&b), 1.0));
    assert_eq!(stealth_rows(&b).len(), 1);
}
