//! [`RpcBackend`] over the shared node. Each call holds the node lock for its
//! duration, so RPC handlers run on blocking threads and never see a half-applied
//! chain change.

use std::sync::Arc;

use bitcoin::hex::DisplayHex;
use bitcoin::Network;
use btc_chain::chainstate::Chainstate;
use btc_chain::mempool_accept::MempoolReject;
use btc_chain::IndexId;
use btc_consensus::{ChainParams, ChainType};
use btc_primitives::{Block, BlockHash, BlockHeader, OutPoint, ScriptBuf, Tx, TxOut, Txid};
use btc_rpc::{BlockchainInfo, MempoolInfo, RpcBackend, WalletInfo, WalletRpc, WalletTx, WalletUtxo};
use btc_wallet::{Category, ScriptKind, Wallet, WalletError};
use crate::node::wallet_error_message;
use btc_wallet::address::AddressParams;
use tokio::sync::Notify;

use crate::node::{Node, SharedNode};

pub struct NodeRpc {
    node: SharedNode,
    /// Notified by the `stop` RPC; the daemon waits on it.
    shutdown: Arc<Notify>,
}

impl NodeRpc {
    pub fn new(node: SharedNode, shutdown: Arc<Notify>) -> Self {
        Self { node, shutdown }
    }

    fn with_node<T>(&self, f: impl FnOnce(&mut Node) -> T) -> T {
        let mut node = self.node.lock().expect("node lock poisoned");
        f(&mut node)
    }
}

impl RpcBackend for NodeRpc {
    fn get_block_count(&self) -> u32 {
        self.with_node(|n| n.chainstate.height())
    }

    fn get_best_block_hash(&self) -> BlockHash {
        self.with_node(|n| n.chainstate.tip_hash())
    }

    fn get_block_hash(&self, height: u32) -> Option<BlockHash> {
        self.with_node(|n| n.chainstate.block_hash_at(height))
    }

    fn get_block(&self, hash: &BlockHash) -> Option<(Block, u32, i64)> {
        self.with_node(|n| {
            let cs = &n.chainstate;
            let id = cs.tree.lookup(hash)?;
            let block = cs.get_block(hash)?;
            Some((block, cs.tree.get(id).height, confirmations(cs, id)))
        })
    }

    fn get_block_header(&self, hash: &BlockHash) -> Option<(BlockHeader, u32, i64)> {
        self.with_node(|n| {
            let cs = &n.chainstate;
            let id = cs.tree.lookup(hash)?;
            let entry = cs.tree.get(id);
            Some((entry.header, entry.height, confirmations(cs, id)))
        })
    }

    fn get_blockchain_info(&self) -> BlockchainInfo {
        self.with_node(|n| {
            let cs = &n.chainstate;
            let tip = cs.tree.get(cs.tip());
            BlockchainInfo {
                chain: chain_name(&n.params).to_owned(),
                blocks: cs.height(),
                headers: cs.tree.get(cs.best_header()).height,
                bestblockhash: cs.tip_hash(),
                difficulty: difficulty(tip.header.bits),
                mediantime: cs.median_time_past_tip(),
                chainwork: tip.chain_work.to_big_endian().to_lower_hex_string(),
            }
        })
    }

    fn get_raw_mempool(&self) -> Vec<Txid> {
        self.with_node(|n| {
            n.mempool
                .sorted_by_fee_rate()
                .iter()
                .map(|entry| entry.tx.txid())
                .collect()
        })
    }

    fn get_mempool_info(&self) -> MempoolInfo {
        self.with_node(|n| {
            let entries = n.mempool.sorted_by_fee_rate();
            MempoolInfo {
                size: entries.len() as u64,
                bytes: entries
                    .iter()
                    .map(|entry| entry.tx.total_size() as u64)
                    .sum(),
            }
        })
    }

    fn get_raw_transaction(&self, txid: &Txid) -> Option<Tx> {
        self.with_node(|n| {
            if let Some(entry) = n.mempool.get(txid) {
                return Some(entry.tx.clone());
            }
            let cs = &n.chainstate;
            (0..=cs.height()).rev().find_map(|height| {
                let block = cs.get_block(&cs.block_hash_at(height)?)?;
                block.txdata.into_iter().find(|tx| tx.txid() == *txid)
            })
        })
    }

    fn send_raw_transaction(&self, tx: Tx) -> Result<Txid, String> {
        self.with_node(|n| n.submit_tx(tx).map_err(reject_reason))
    }

    fn submit_block(&self, block: Block) -> Result<(), String> {
        self.with_node(|n| match n.submit_block(&block) {
            Ok(true) => Ok(()),
            Ok(false) => Err("duplicate".to_owned()),
            Err(err) => Err(err.reject_reason().to_owned()),
        })
    }

    fn generate_to_script(&self, n: u32, script: ScriptBuf) -> Result<Vec<BlockHash>, String> {
        self.with_node(|node| {
            node.generate(n, &script)
                .map_err(|err| err.reject_reason().to_owned())
        })
    }

    fn get_tx_out(&self, outpoint: &OutPoint) -> Option<(TxOut, u32, bool)> {
        self.with_node(|n| {
            if n.mempool.spender_of(outpoint).is_some() {
                return None;
            }
            let cs = &n.chainstate;
            let coin = cs.coins_view().get_coin(outpoint)?;
            let confirmations = cs.height().saturating_sub(coin.height) + 1;
            Some((coin.txout, confirmations, coin.is_coinbase))
        })
    }

    fn network(&self) -> Network {
        self.with_node(|n| match n.params.chain_type {
            ChainType::Main => Network::Bitcoin,
            ChainType::Testnet => Network::Testnet,
            ChainType::Regtest => Network::Regtest,
        })
    }

    fn address_params(&self) -> AddressParams {
        self.with_node(|n| AddressParams {
            bech32_hrp: n.params.bech32_hrp.clone(),
            pubkey_prefix: n.params.pubkey_address_prefix,
            script_prefix: n.params.script_address_prefix,
        })
    }

    fn wallet(&self) -> Option<&dyn WalletRpc> {
        if self.with_node(|n| n.wallet.is_some()) {
            Some(self)
        } else {
            None
        }
    }

    fn stop(&self) {
        self.shutdown.notify_one();
    }
}

/// `-chain=` name as Core reports it. Custom coins are named by their data
/// directory, which `ChainParams::custom` sets to the coin's name.
fn chain_name(params: &ChainParams) -> &str {
    match params.chain_type {
        ChainType::Main => "main",
        ChainType::Testnet => "test",
        ChainType::Regtest if params.data_dir.is_empty() => "regtest",
        ChainType::Regtest => &params.data_dir,
    }
}

/// Blocks on top of `id` including itself, or -1 when it is not in the active chain.
fn confirmations(cs: &Chainstate, id: IndexId) -> i64 {
    if cs.chain.contains(&cs.tree, id) {
        i64::from(cs.height() - cs.tree.get(id).height) + 1
    } else {
        -1
    }
}

/// `GetDifficulty()` from `rpc/blockchain.cpp`: difficulty relative to the
/// `0x1d00ffff` target.
fn difficulty(bits: u32) -> f64 {
    let mut shift = (bits >> 24) & 0xff;
    let mut diff = f64::from(0x0000_ffffu32) / f64::from(bits & 0x00ff_ffff);
    while shift < 29 {
        diff *= 256.0;
        shift += 1;
    }
    while shift > 29 {
        diff /= 256.0;
        shift -= 1;
    }
    diff
}

fn reject_reason(reject: MempoolReject) -> String {
    match reject {
        MempoolReject::Consensus(reason) | MempoolReject::Policy(reason) => reason,
        MempoolReject::MissingInputs => "missing-inputs".to_owned(),
        MempoolReject::AlreadyKnown => "txn-already-in-mempool".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::WPubkeyHash;
    use bitcoin_hashes::Hash as _;
    use btc_chain::chainstate::MemBlockStore;
    use btc_consensus::regtest_genesis_block;
    use btc_primitives::{TxIn, TxOut as PrimTxOut};
    use btc_validation::coins::CoinsViewMemory;
    use btc_wallet::address::{encode_address, Network as WalletNetwork};
    use serde_json::{json, Value};
    use std::time::Duration;

    fn regtest_backend() -> (NodeRpc, Arc<Notify>) {
        let node = Node::new(
            ChainParams::regtest(),
            regtest_genesis_block(),
            Box::new(CoinsViewMemory::new()),
            Box::<MemBlockStore>::default(),
        )
        .unwrap();
        let shutdown = Arc::new(Notify::new());
        (NodeRpc::new(node.shared(), Arc::clone(&shutdown)), shutdown)
    }

    fn call(backend: &NodeRpc, method: &str, params: Value) -> Value {
        btc_rpc::dispatch(
            backend,
            json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}),
        )
    }

    fn result(reply: &Value) -> &Value {
        assert!(reply["error"].is_null(), "unexpected error: {reply}");
        &reply["result"]
    }

    fn miner_address() -> String {
        let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7u8; 20]));
        encode_address(WalletNetwork::Regtest, &script).unwrap()
    }

    #[test]
    fn generate_and_query_regtest_chain() {
        let (rpc, _) = regtest_backend();
        let hashes: Vec<String> = serde_json::from_value(
            result(&call(
                &rpc,
                "generatetoaddress",
                json!([3, miner_address()]),
            ))
            .clone(),
        )
        .unwrap();
        assert_eq!(hashes.len(), 3);

        assert_eq!(result(&call(&rpc, "getblockcount", json!([]))), 3);
        assert_eq!(
            result(&call(&rpc, "getbestblockhash", json!([]))),
            hashes[2].as_str()
        );
        assert_eq!(
            result(&call(&rpc, "getblockhash", json!([1]))),
            hashes[0].as_str()
        );

        let block = result(&call(&rpc, "getblock", json!([hashes[0], 1]))).clone();
        assert_eq!(block["height"], 1);
        assert_eq!(block["confirmations"], 3);
        assert_eq!(block["tx"].as_array().unwrap().len(), 1);

        let stale = call(&rpc, "getblock", json!(["00".repeat(32), 1]));
        assert!(!stale["error"].is_null());

        let info = result(&call(&rpc, "getblockchaininfo", json!([]))).clone();
        assert_eq!(info["chain"], "regtest");
        assert_eq!(info["blocks"], 3);
        assert_eq!(info["headers"], 3);
        assert_eq!(info["bestblockhash"], hashes[2].as_str());
        assert_eq!(info["chainwork"].as_str().unwrap().len(), 64);
        let difficulty = info["difficulty"].as_f64().unwrap();
        assert!(
            (difficulty - 4.656_542_373_906_925e-10).abs() < 1e-18,
            "{difficulty}"
        );
    }

    #[test]
    fn stealth_address_rpc_is_deterministic_and_scans_empty() {
        let mut node = Node::new(
            ChainParams::regtest(),
            regtest_genesis_block(),
            Box::new(CoinsViewMemory::new()),
            Box::<MemBlockStore>::default(),
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("btc-node-wallet-stealth-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let wallet = Wallet::create(&dir).unwrap();
        node.attach_wallet(wallet).unwrap();
        let shutdown = Arc::new(Notify::new());
        let rpc = NodeRpc::new(node.shared(), shutdown);

        let first = result(&call(&rpc, "getnewstealthaddress", json!([]))).clone();
        let hex = first.as_str().unwrap();
        assert_eq!(hex.len(), 132, "66 bytes as hex");
        let second = result(&call(&rpc, "getnewstealthaddress", json!([]))).clone();
        assert_eq!(first, second, "reusable invitation address");
        let utxos = result(&call(&rpc, "liststealthutxos", json!([]))).clone();
        assert_eq!(utxos, json!([]), "no stealth payments yet");

        std::fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn stealth_payment_is_found_by_recipient_scan() {
        let mut node = Node::new(
            ChainParams::regtest(),
            regtest_genesis_block(),
            Box::new(CoinsViewMemory::new()),
            Box::<MemBlockStore>::default(),
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("btc-node-wallet-stealth-pay-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let wallet = Wallet::create(&dir).unwrap();
        node.attach_wallet(wallet).unwrap();
        let shutdown = Arc::new(Notify::new());
        let rpc = NodeRpc::new(node.shared(), shutdown);

        // Fund the wallet with mature coinbase outputs.
        let funded = result(&call(&rpc, "getnewaddress", json!([]))).clone();
        let funded_addr = funded.as_str().unwrap().to_owned();
        let hashes: Vec<String> = serde_json::from_value(
            result(&call(&rpc, "generatetoaddress", json!([101, funded_addr])))
                .clone(),
        )
        .unwrap();
        assert_eq!(hashes.len(), 101);

        // Pay 1 coin to our own stealth address (exercises sender side).
        let stealth_addr = result(&call(&rpc, "getnewstealthaddress", json!([]))).clone();
        let reply = call(
            &rpc,
            "sendtostealthaddress",
            json!([stealth_addr.as_str().unwrap(), 1.0]),
        );
        let txid = result(&reply);
        assert!(!txid.as_str().unwrap().is_empty());

        // Mine the stealth transaction into a block and rescan.
        let mempool = result(&call(&rpc, "getrawmempool", json!([]))).clone();
        assert!(!mempool.as_array().unwrap().is_empty());
        let mined: Vec<String> = serde_json::from_value(
            result(&call(
                &rpc,
                "generatetoaddress",
                json!([1, result(&call(&rpc, "getnewaddress", json!([]))).as_str().unwrap()]),
            ))
            .clone(),
        )
        .unwrap();
        assert_eq!(mined.len(), 1);

        let utxos = result(&call(&rpc, "liststealthutxos", json!([]))).clone();
        let arr = utxos.as_array().unwrap();
        assert_eq!(arr.len(), 1, "recipient scan finds the stealth payment: {arr:?}");
        assert!((arr[0]["amount"].as_f64().unwrap() - 1.0).abs() < 1e-9);
        assert!(arr[0]["confirmations"].as_u64().unwrap() >= 1);

        std::fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn gettxout_and_raw_transaction_for_block_one_coinbase() {
        let (rpc, _) = regtest_backend();
        let hashes: Vec<String> = serde_json::from_value(
            result(&call(
                &rpc,
                "generatetoaddress",
                json!([3, miner_address()]),
            ))
            .clone(),
        )
        .unwrap();
        let block = result(&call(&rpc, "getblock", json!([hashes[0], 1]))).clone();
        let coinbase = block["tx"][0].as_str().unwrap();

        let out = result(&call(&rpc, "gettxout", json!([coinbase, 0]))).clone();
        assert_eq!(out["confirmations"], 3);
        assert_eq!(out["coinbase"], true);
        assert_eq!(out["value"], 50.0);

        assert!(result(&call(&rpc, "gettxout", json!([coinbase, 1]))).is_null());

        let raw = result(&call(&rpc, "getrawtransaction", json!([coinbase]))).clone();
        assert!(raw.as_str().unwrap().len() > 100);
    }

    #[test]
    fn rejects_garbage_and_orphan_transactions() {
        let (rpc, _) = regtest_backend();
        assert!(!call(&rpc, "sendrawtransaction", json!(["zz"]))["error"].is_null());
        assert!(!call(&rpc, "sendrawtransaction", json!(["0100"]))["error"].is_null());

        let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([7u8; 20]));
        let orphan = Tx::new(
            2,
            vec![TxIn::new(OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            })],
            vec![PrimTxOut::new(1_000, script)],
            0,
        );
        let reply = call(&rpc, "sendrawtransaction", json!([serialize_hex(&orphan)]));
        assert_eq!(reply["error"]["message"], "missing-inputs", "{reply}");
    }

    #[tokio::test]
    async fn stop_notifies_the_daemon() {
        let (rpc, shutdown) = regtest_backend();
        assert_eq!(
            result(&call(&rpc, "stop", json!([]))),
            "Bitcoin Core stopping"
        );
        tokio::time::timeout(Duration::from_millis(500), shutdown.notified())
            .await
            .expect("stop should notify the shutdown handle");
    }
}

impl NodeRpc {
    fn with_wallet<T>(&self, f: impl FnOnce(&mut Wallet, u32) -> T) -> Option<T> {
        self.with_node(|n| {
            let tip = n.chainstate.height();
            n.wallet.as_mut().map(|w| f(w, tip))
        })
    }
}

fn unix_now() -> u64 {
    crate::node::now_secs().max(0) as u64
}

impl WalletRpc for NodeRpc {
    fn get_new_address(&self, kind: Option<&str>) -> Result<ScriptBuf, String> {
        let kind = match kind.unwrap_or("bech32") {
            "legacy" => ScriptKind::P2pkh,
            "p2sh-segwit" => ScriptKind::P2shP2wpkh,
            "bech32" => ScriptKind::P2wpkh,
            "bech32m" => ScriptKind::P2tr,
            other => return Err(format!("Unknown address type '{other}'")),
        };
        self.with_wallet(|w, _| w.new_script(kind).map_err(wallet_error_message))
            .unwrap_or_else(|| Err("wallet disabled".into()))
    }

    fn get_balance(&self, minconf: u32) -> i64 {
        self.with_wallet(|w, tip| w.balance(tip, minconf)).unwrap_or(0)
    }

    fn list_unspent(&self, minconf: u32, maxconf: u32) -> Vec<WalletUtxo> {
        self.with_wallet(|w, tip| {
            let locked = w.is_locked(unix_now());
            w.list_unspent(tip, minconf, maxconf)
                .into_iter()
                .map(|(outpoint, txout, confirmations)| WalletUtxo {
                    outpoint,
                    script_pubkey: txout.script_pubkey,
                    amount: txout.value,
                    confirmations,
                    spendable: !locked || !w.is_encrypted(),
                })
                .collect()
        })
        .unwrap_or_default()
    }

    fn send_to(&self, script: ScriptBuf, amount: i64, fee_rate: Option<i64>, subtract_fee: bool) -> Result<Txid, String> {
        self.with_node(|n| n.wallet_send(script, amount, fee_rate, subtract_fee))
    }

    fn send_to_stealth(&self, address_hex: String, amount: i64, fee_rate: Option<i64>) -> Result<Txid, String> {
        use bitcoin::hex::FromHex;
        let bytes = Vec::<u8>::from_hex(&address_hex)
            .map_err(|_| "Invalid stealth address: expected 66 bytes as hex".to_string())?;
        let address = btc_wallet::stealth::StealthAddress::from_bytes(&bytes)
            .map_err(|_| "Invalid stealth address: expected 66 bytes as hex".to_string())?;
        self.with_node(|n| n.wallet_send_stealth(address, amount, fee_rate))
    }

    fn send_to_confidential(&self, amount: i64, fee: i64) -> Result<Txid, String> {
        self.with_node(|n| {
            n.wallet_send_ct(amount.max(0) as u64, fee)
        })
    }

    fn dump_privkey(&self, script: &ScriptBuf) -> Result<String, String> {
        self.with_wallet(|w, _| w.dump_wif(script).map_err(wallet_error_message))
            .unwrap_or_else(|| Err("wallet disabled".into()))
    }

    fn import_privkey(&self, wif: &str) -> Result<(), String> {
        self.with_node(|n| {
            let w = n.wallet.as_mut().ok_or("wallet disabled")?;
            w.import_wif(wif).map_err(|e| match e {
                WalletError::Key(_) => "Invalid private key encoding".to_string(),
                other => wallet_error_message(other),
            })?;
            // Rescan the active chain so coins of the imported key show up.
            let cs = &n.chainstate;
            for height in 1..=cs.height() {
                if let Some(block) = cs.block_hash_at(height).and_then(|h| cs.get_block(&h)) {
                    w.block_connected(&block, height).map_err(wallet_error_message)?;
                }
            }
            Ok(())
        })
    }

    fn wallet_info(&self) -> WalletInfo {
        self.with_wallet(|w, tip| WalletInfo {
            name: "wallet".into(),
            balance: w.balance(tip, 1),
            unconfirmed_balance: w.unconfirmed_balance(),
            immature_balance: w.immature_balance(tip),
            tx_count: w.transactions().len(),
            keypool_size: 0,
            encrypted: w.is_encrypted(),
            unlocked_until: if w.is_encrypted() && !w.is_locked(unix_now()) { w.unlocked_until() } else { 0 },
        })
        .unwrap_or_default()
    }

    fn list_transactions(&self, count: usize, skip: usize) -> Vec<WalletTx> {
        self.with_wallet(|w, tip| {
            let all = w.transactions();
            let end = all.len().saturating_sub(skip);
            let start = end.saturating_sub(count);
            all[start..end]
                .iter()
                .map(|r| {
                    let confirmations = r.height.map_or(0, |h| i64::from(tip) - i64::from(h) + 1);
                    let category = match r.category {
                        Category::Send => "send",
                        Category::Receive => "receive",
                        Category::Generate if confirmations > 100 => "generate",
                        Category::Generate => "immature",
                    };
                    WalletTx {
                        txid: r.txid,
                        category: category.into(),
                        amount: r.amount,
                        fee: r.fee.map(|f| -f.abs()),
                        script_pubkey: None,
                        confirmations,
                        blockhash: r.block_hash,
                        time: r.time,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
    }

    fn encrypt_wallet(&self, passphrase: &str) -> Result<(), String> {
        self.with_wallet(|w, _| w.encrypt(passphrase).map_err(wallet_error_message))
            .unwrap_or_else(|| Err("wallet disabled".into()))
    }

    fn wallet_passphrase(&self, passphrase: &str, timeout_secs: u64) -> Result<(), String> {
        let until = unix_now() + timeout_secs.min(100_000_000);
        self.with_wallet(|w, _| w.unlock(passphrase, until).map_err(wallet_error_message))
            .unwrap_or_else(|| Err("wallet disabled".into()))
    }

    fn wallet_lock(&self) -> Result<(), String> {
        self.with_wallet(|w, _| w.lock().map_err(wallet_error_message))
            .unwrap_or_else(|| Err("wallet disabled".into()))
    }

    fn get_stealth_address(&self) -> Result<String, String> {
        self.with_wallet(|w, _| {
            w.stealth_address()
                .map(|a| a.to_bytes().to_lower_hex_string())
                .map_err(wallet_error_message)
        })
        .unwrap_or_else(|| Err("wallet disabled".into()))
    }

    fn list_stealth_utxos(&self, minconf: u32, max_blocks: u32) -> Vec<WalletUtxo> {
        use btc_wallet::stealth::{extract_hash160, parse_marker};
        self.with_node(|n| {
            let Some(wallet) = n.wallet.as_ref() else {
                return Vec::new();
            };
            let Ok(keys) = wallet.stealth_keys() else {
                return Vec::new();
            };
            let tip = n.chainstate.height();
            let mut found = Vec::new();

            let scan_tx = |tx: &Tx, height: Option<u32>, out: &mut Vec<WalletUtxo>| {
                // Markers announce the ephemeral key for this payment.
                let Some(ephemeral) = tx.vout.iter().find_map(|o| parse_marker(&o.script_pubkey))
                else {
                    return;
                };
                let confirmations = height.map_or(0, |h| tip - h + 1);
                if confirmations < minconf {
                    return;
                }
                for (vout, output) in tx.vout.iter().enumerate() {
                    let Some(candidate) = extract_hash160(&output.script_pubkey) else {
                        continue;
                    };
                    let matched = keys
                        .scan_output(&ephemeral, &candidate)
                        .ok()
                        .flatten();
                    if let Some(_secret) = matched {
                        out.push(WalletUtxo {
                            outpoint: OutPoint::new(tx.txid(), vout as u32),
                            script_pubkey: output.script_pubkey.clone(),
                            amount: output.value,
                            confirmations,
                            spendable: true,
                        });
                    }
                }
            };

            // Mempool first (0 confirmations), then blocks newest-last window.
            for entry in n.mempool.sorted_by_fee_rate() {
                let tx = entry.tx.clone();
                scan_tx(&tx, None, &mut found);
            }
            let start = tip.saturating_sub(max_blocks);
            for height in start..=tip {
                if let Some(block) = n
                    .chainstate
                    .block_hash_at(height)
                    .and_then(|h| n.chainstate.get_block(&h))
                {
                    for tx in &block.txdata {
                        scan_tx(tx, Some(height), &mut found);
                    }
                }
            }
            found
        })
    }
}
