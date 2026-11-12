//! Node core: chainstate + mempool + fee estimator behind one lock.
//! Port of the glue in `node/context.h` and `validationinterface`.
//!
//! CONTRACT: RPC and P2P layers use only these public items.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use btc_chain::chainstate::{BlockStore, ChainEvent, Chainstate};
use btc_chain::mempool_accept::{accept_to_mempool, update_mempool_for_events, MempoolReject};
use btc_chain::miner::generate_block;
use btc_chain::{IndexId, ValidationError};
use btc_consensus::ChainParams;
use btc_primitives::{Block, BlockHash, BlockHeader, ScriptBuf, Tx, Txid};
use btc_validation::coins::CoinsViewWrite;
use btc_validation::fees::FeeEstimator;
use btc_validation::mempool::Mempool;
use btc_wallet::{Wallet, WalletError};

/// Default `-maxmempool` expressed as an entry cap.
pub const DEFAULT_MEMPOOL_ENTRIES: usize = 50_000;

/// Core-style wallet error text (the RPC layer maps keywords to error codes).
pub fn wallet_error_message(e: WalletError) -> String {
    match e {
        WalletError::Locked => "Error: Please enter the wallet passphrase with walletpassphrase first (wallet locked).".into(),
        WalletError::WrongPassphrase => "Error: The wallet passphrase entered was incorrect.".into(),
        WalletError::InsufficientFunds { .. } => "Insufficient funds".into(),
        WalletError::AlreadyEncrypted => "Error: running with an encrypted wallet, but encryptwallet was called.".into(),
        WalletError::NotEncrypted => "Error: running with an unencrypted wallet, but walletpassphrase was called.".into(),
        other => format!("Error: {other}"),
    }
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub struct Node {
    pub params: ChainParams,
    pub chainstate: Chainstate,
    pub mempool: Mempool,
    pub fees: FeeEstimator,
    /// Hashes of blocks connected since the last `take_new_tips` (for relay).
    new_tips: Vec<BlockHash>,
    /// Txids accepted since the last `take_new_txs` (for relay).
    new_txs: Vec<Txid>,
    /// Loaded wallet (`-disablewallet` = None).
    pub wallet: Option<Wallet>,
    /// Groth16 proving key matching the chain's pinned verifying key, if
    /// the operator provided one (`snark_pk.bin` in the datadir). Without
    /// it the wallet builds plain (proof-free) note spends and cannot
    /// make shielded spends.
    pub snark_pk: Option<Arc<btc_chain::value_snark::SnarkProvingKey>>,
}

/// Fee rate used when the estimator has no data (`-fallbackfee`, sat/kvB).
pub const FALLBACK_FEE_RATE: i64 = 1_000;

pub type SharedNode = Arc<Mutex<Node>>;

impl Node {
    pub fn new(
        params: ChainParams,
        genesis: Block,
        coins: Box<dyn CoinsViewWrite + Send>,
        store: Box<dyn BlockStore>,
    ) -> Result<Self, ValidationError> {
        let chainstate = Chainstate::new(params.clone(), genesis, coins, store)?;
        Ok(Self {
            params,
            chainstate,
            mempool: Mempool::new(DEFAULT_MEMPOOL_ENTRIES),
            fees: FeeEstimator::new(),
            new_tips: Vec::new(),
            new_txs: Vec::new(),
            wallet: None,
            snark_pk: None,
        })
    }

    pub fn shared(self) -> SharedNode {
        Arc::new(Mutex::new(self))
    }

    fn after_chain_change(&mut self) {
        let events = self.chainstate.take_events();
        if events.is_empty() {
            return;
        }
        update_mempool_for_events(&self.chainstate, &mut self.mempool, &events);
        let mut reorged: Vec<&[Tx]> = Vec::new();
        for event in &events {
            match event {
                ChainEvent::BlockConnected { hash, height } => {
                    if let Some(block) = self.chainstate.get_block(hash) {
                        let txids: Vec<Txid> = block.txdata.iter().map(|t| t.txid()).collect();
                        self.fees.process_block(*height, &txids);
                        if let Some(w) = self.wallet.as_mut() {
                            let _ = w.block_connected(&block, *height);
                            let _ = w.set_best_block(*hash, *height);
                        }
                    }
                    self.new_tips.push(*hash);
                }
                ChainEvent::BlockDisconnected { hash, height, txs } => {
                    reorged.push(txs);
                    if let (Some(w), Some(block)) = (self.wallet.as_mut(), self.chainstate.get_block(hash)) {
                        let _ = w.block_disconnected(&block, *height);
                        let prev = block.header.prev_blockhash;
                        let _ = w.set_best_block(prev, height.saturating_sub(1));
                    }
                }
            }
        }
        // Transactions of disconnected blocks that went back to the mempool
        // are unconfirmed wallet transactions again (their coins were dropped
        // at disconnect). Lowest block first so parents precede children.
        if let Some(w) = self.wallet.as_mut() {
            for txs in reorged.into_iter().rev() {
                for tx in txs.iter().filter(|t| !t.is_coin_base()) {
                    if self.mempool.contains(&tx.txid()) {
                        let _ = w.tx_added_to_mempool(tx);
                    }
                }
            }
        }
    }

    /// Loads `wallet` and rescans blocks it has not seen (`AttachChain`).
    pub fn attach_wallet(&mut self, mut wallet: Wallet) -> Result<(), WalletError> {
        let cs = &self.chainstate;
        // A wallet that never scanned for stealth payments (written before
        // they were imported) rescans the whole chain once.
        let rescan_stealth = wallet.needs_stealth_rescan();
        let start = match wallet.best_block() {
            Some((hash, height)) if !rescan_stealth && cs.block_hash_at(height) == Some(hash) => height + 1,
            _ => 1,
        };
        for height in start..=cs.height() {
            let hash = cs.block_hash_at(height).expect("height within active chain");
            if let Some(block) = cs.get_block(&hash) {
                wallet.block_connected(&block, height)?;
            }
        }
        wallet.set_best_block(cs.tip_hash(), cs.height())?;
        if rescan_stealth {
            wallet.mark_stealth_scanned()?;
        }
        for entry in self.mempool.sorted_by_fee_rate() {
            wallet.tx_added_to_mempool(&entry.tx)?;
        }
        self.wallet = Some(wallet);
        Ok(())
    }

    /// Fee rate for wallet sends: smart estimate for 6 blocks, else fallback.
    pub fn wallet_fee_rate(&self) -> i64 {
        self.fees
            .estimate_smart_fee(6, false)
            .map(|(rate, _)| rate as i64)
            .unwrap_or(FALLBACK_FEE_RATE)
            .max(FALLBACK_FEE_RATE)
    }

    /// `sendtoaddress`: build, sign, accept to mempool, then commit to the wallet.
    pub fn wallet_send(
        &mut self,
        script: ScriptBuf,
        amount: i64,
        fee_rate: Option<i64>,
        subtract_fee: bool,
    ) -> Result<Txid, String> {
        let rate = fee_rate.unwrap_or_else(|| self.wallet_fee_rate());
        let tip = self.chainstate.height();
        let wallet = self.wallet.as_mut().ok_or("wallet disabled")?;
        let tx = wallet
            .create_transaction(tip, &[(script, amount)], rate, subtract_fee)
            .map_err(wallet_error_message)?;
        let txid = self.submit_tx(tx.clone()).map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(w) = self.wallet.as_mut() {
            w.commit_transaction(&tx).map_err(wallet_error_message)?;
        }
        Ok(txid)
    }

    /// `sendtostealthaddress`: builds a stealth payment with its marker
    /// output, accepts it to the mempool, then commits it to the wallet.
    pub fn wallet_send_stealth(
        &mut self,
        address: btc_wallet::stealth::StealthAddress,
        amount: i64,
        fee_rate: Option<i64>,
    ) -> Result<Txid, String> {
        let rate = fee_rate.unwrap_or_else(|| self.wallet_fee_rate());
        if amount <= 0 {
            return Err("Invalid amount for send".to_string());
        }
        let tip = self.chainstate.height();
        let wallet = self.wallet.as_mut().ok_or("wallet disabled")?;
        let tx = wallet
            .create_stealth_transaction(tip, address, amount, rate)
            .map_err(wallet_error_message)?;
        let txid = self
            .submit_tx(tx.clone())
            .map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(w) = self.wallet.as_mut() {
            w.commit_transaction(&tx).map_err(wallet_error_message)?;
        }
        Ok(txid)
    }

    /// `shieldtoct`: shield an amount of plaintext balance into a
    /// confidential output owned by this wallet.
    pub fn wallet_send_ct(&mut self, amount: u64, fee: i64) -> Result<Txid, String> {
        if amount == 0 {
            return Err("Invalid amount for send".to_string());
        }
        let tip = self.chainstate.height();
        let wallet = self.wallet.as_mut().ok_or("wallet disabled")?;
        let (tx, info, outpoint) = wallet
            .create_hybrid_ct(tip, amount, fee)
            .map_err(wallet_error_message)?;
        let txid = self.submit_tx(tx.clone()).map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(w) = self.wallet.as_mut() {
            w.commit_transaction(&tx).map_err(wallet_error_message)?;
            w.record_ct_coin(outpoint, tx.vout[0].script_pubkey.clone(), info)
                .map_err(wallet_error_message)?;
        }
        Ok(txid)
    }

    /// `sendct`: confidential payment of `amount` to a stealth address
    /// from the wallet's CT coins. The recipient's wallet recovers the
    /// hidden amount through its scan key; change returns to this
    /// wallet's own stealth address.
    pub fn wallet_send_ct_payment(
        &mut self,
        address: btc_wallet::stealth::StealthAddress,
        amount: u64,
        fee: i64,
    ) -> Result<Txid, String> {
        if amount == 0 {
            return Err("Invalid amount for send".to_string());
        }
        let tip = self.chainstate.height();
        let wallet = self.wallet.as_mut().ok_or("wallet disabled")?;
        let (tx, _own_outputs) = wallet
            .create_ct_payment(tip, &[(address, amount)], fee)
            .map_err(wallet_error_message)?;
        let txid = self
            .submit_tx(tx.clone())
            .map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(w) = self.wallet.as_mut() {
            // Adopts the change output (recovered by scanning).
            w.commit_transaction(&tx).map_err(wallet_error_message)?;
        }
        Ok(txid)
    }

    /// `createpoolnote`: shields plaintext into a pool note.
    pub fn wallet_create_pool_note(&mut self, amount: u64, fee: i64) -> Result<String, String> {
        if amount == 0 {
            return Err("Invalid amount for send".to_string());
        }
        let tip = self.chainstate.height();
        let wallet = self.wallet.as_mut().ok_or("wallet disabled")?;
        let (tx, info, outpoint) = wallet
            .create_pool_note(tip, amount, fee)
            .map_err(wallet_error_message)?;
        let cmu_hex = bitcoin::hex::DisplayHex::to_lower_hex_string(&btc_chain::notes::note_commitment(&btc_chain::notes::Note {
            spending_pub: {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let secret = info.secret;
                bitcoin::secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &bitcoin::secp256k1::SecretKey::from_slice(&secret)
                        .map_err(|_| "note secret invalid".to_string())?,
                )
                .serialize()
            },
            value: amount,
            rcm: info.rcm,
        }));
        let txid = self.submit_tx(tx.clone()).map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(w) = self.wallet.as_mut() {
            w.commit_transaction(&tx).map_err(wallet_error_message)?;
            w.record_note_coin(outpoint, tx.vout[0].script_pubkey.clone(), info)
                .map_err(wallet_error_message)?;
        }
        let _ = txid;
        Ok(cmu_hex)
    }

    /// `spendnote`: spends a shielded note by its commitment hex.
    pub fn wallet_spend_note(&mut self, cmu: [u8; 32], amount: i64) -> Result<Txid, String> {
        use btc_chain::notes::{note_commitment, Note};
        let snark_pk = self.snark_pk.clone();
        let wallet = self.wallet.as_mut().ok_or("wallet disabled")?;
        // Find the pool position + outpoint.
        let position = self
            .chainstate
            .pool_tree()
            .position_of(&cmu)
            .ok_or("note commitment unknown to the chain".to_string())?;
        let outpoint = self
            .chainstate
            .pool_note_outpoint(position)
            .ok_or("note outpoint not found".to_string())?;
        let Some(record) = wallet
            .coins_snapshot()
            .get(&outpoint)
            .and_then(|coin| coin.note.clone())
        else {
            return Err("note not held by this wallet".to_string());
        };
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let note = Note {
            spending_pub: bitcoin::secp256k1::PublicKey::from_secret_key(
                &secp,
                &bitcoin::secp256k1::SecretKey::from_slice(&record.secret)
                    .map_err(|_| "note secret invalid".to_string())?,
            )
            .serialize(),
            value: record.value,
            rcm: record.rcm,
        };
        debug_assert_eq!(note_commitment(&note), cmu);
        let anchor = self.chainstate.pool_root();
        let path = self.chainstate.pool_tree().path(position);
        let cap = self
            .chainstate
            .pool_funding()
            .get(&cmu)
            .copied()
            .ok_or("note commitment unknown to the chain".to_string())?;
        let recipient = wallet
            .new_script(btc_wallet::ScriptKind::P2wpkh)
            .map_err(wallet_error_message)?;
        let tx = wallet
            .create_note_spend(outpoint, note.clone(), &record.secret, anchor, position, path, recipient, amount, cap, snark_pk.as_deref())
            .map_err(wallet_error_message)?;
        let txid = self.submit_tx(tx.clone()).map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(w) = self.wallet.as_mut() {
            w.commit_transaction(&tx).map_err(wallet_error_message)?;
        }
        Ok(txid)
    }

    /// `shieldspendnote`: shielded spend — note -> new shielded note,
    /// only the public fee leaves the pool.
    pub fn wallet_spend_note_shielded(&mut self, cmu: [u8; 32], fee: i64) -> Result<Txid, String> {
        use btc_chain::notes::{note_commitment, Note};
        let snark_pk = self.snark_pk.clone().ok_or(
            "no SNARK proving key configured (shielded spends need snark_pk.bin matching the chain's snark_vk)",
        )?;
        let wallet = self.wallet.as_mut().ok_or("wallet disabled")?;
        let position = self
            .chainstate
            .pool_tree()
            .position_of(&cmu)
            .ok_or("note commitment unknown to the chain".to_string())?;
        let outpoint = self
            .chainstate
            .pool_note_outpoint(position)
            .ok_or("note outpoint not found".to_string())?;
        let Some(record) = wallet
            .coins_snapshot()
            .get(&outpoint)
            .and_then(|coin| coin.note.clone())
        else {
            return Err("note not held by this wallet".to_string());
        };
        let cap = self
            .chainstate
            .pool_funding()
            .get(&cmu)
            .copied()
            .ok_or("note commitment unknown to the chain".to_string())?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let note = Note {
            spending_pub: bitcoin::secp256k1::PublicKey::from_secret_key(
                &secp,
                &bitcoin::secp256k1::SecretKey::from_slice(&record.secret)
                    .map_err(|_| "note secret invalid".to_string())?,
            )
            .serialize(),
            value: record.value,
            rcm: record.rcm,
        };
        debug_assert_eq!(note_commitment(&note), cmu);
        let anchor = self.chainstate.pool_root();
        let path = self.chainstate.pool_tree().path(position);
        let (tx, new_info, new_outpoint) = wallet
            .create_note_spend_shielded(
                outpoint,
                note.clone(),
                &record.secret,
                anchor,
                position,
                path,
                cap,
                fee.max(0) as u64,
                &snark_pk,
            )
            .map_err(wallet_error_message)?;
        let txid = self.submit_tx(tx.clone()).map_err(|e| format!("transaction rejected: {e:?}"))?;
        if let Some(w) = self.wallet.as_mut() {
            w.commit_transaction(&tx).map_err(wallet_error_message)?;
            w.record_note_coin(new_outpoint, tx.vout[0].script_pubkey.clone(), new_info)
                .map_err(wallet_error_message)?;
        }
        Ok(txid)
    }

    /// `ProcessNewBlock` + mempool/fee updates. Ok(true) if new.
    pub fn submit_block(&mut self, block: &Block) -> Result<bool, ValidationError> {
        let result = self.chainstate.process_new_block(block, now_secs());
        self.after_chain_change();
        result
    }

    /// `invalidateblock`: marks `hash` failed and reorganises away from it,
    /// notifying the wallet of every disconnected and connected block.
    pub fn invalidate_block(&mut self, hash: &BlockHash) -> Result<(), ValidationError> {
        let result = self.chainstate.invalidate_block(hash);
        self.after_chain_change();
        result
    }

    pub fn submit_headers(&mut self, headers: &[BlockHeader]) -> Result<IndexId, ValidationError> {
        self.chainstate.process_new_block_headers(headers, now_secs())
    }

    /// `AcceptToMemoryPool` + fee tracking.
    pub fn submit_tx(&mut self, tx: Tx) -> Result<Txid, MempoolReject> {
        let wallet_copy = self.wallet.as_ref().map(|_| tx.clone());
        let txid = accept_to_mempool(&self.chainstate, &mut self.mempool, tx)?;
        if let (Some(w), Some(tx)) = (self.wallet.as_mut(), wallet_copy) {
            let _ = w.tx_added_to_mempool(&tx);
        }
        if let Some(entry) = self.mempool.get(&txid) {
            let rate = entry.fee as f64 * 1000.0 / entry.vsize as f64;
            self.fees.process_transaction(txid, self.chainstate.height(), rate);
        }
        self.new_txs.push(txid);
        Ok(txid)
    }

    /// Mine `n` blocks to `script` (regtest-style `generatetoaddress`).
    pub fn generate(&mut self, n: u32, script: &ScriptBuf) -> Result<Vec<BlockHash>, ValidationError> {
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let hash = generate_block(&mut self.chainstate, &self.mempool, script.clone(), now_secs())?;
            self.after_chain_change();
            out.push(hash);
        }
        Ok(out)
    }

    pub fn take_new_tips(&mut self) -> Vec<BlockHash> {
        std::mem::take(&mut self.new_tips)
    }

    pub fn take_new_txs(&mut self) -> Vec<Txid> {
        std::mem::take(&mut self.new_txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_chain::chainstate::MemBlockStore;
    use btc_validation::coins::CoinsViewMemory;

    #[test]
    fn generate_extends_regtest_chain() {
        let params = ChainParams::regtest();
        let genesis = btc_consensus::regtest_genesis_block();
        let mut node = Node::new(params, genesis, Box::new(CoinsViewMemory::new()), Box::<MemBlockStore>::default()).unwrap();
        let hashes = node.generate(5, &ScriptBuf::from_bytes(vec![0x51])).unwrap();
        assert_eq!(hashes.len(), 5);
        assert_eq!(node.chainstate.height(), 5);
        assert_eq!(node.take_new_tips(), hashes);
    }

    #[test]
    fn wallet_mines_sends_and_tracks_balance() {
        let dir = std::env::temp_dir().join(format!("btc-node-wallet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let params = ChainParams::regtest();
        let genesis = btc_consensus::regtest_genesis_block();
        let mut node = Node::new(params, genesis, Box::new(CoinsViewMemory::new()), Box::<MemBlockStore>::default()).unwrap();
        node.attach_wallet(Wallet::create(&dir.join("w.json")).unwrap()).unwrap();

        let mine = node.wallet.as_mut().unwrap().new_script(btc_wallet::ScriptKind::P2wpkh).unwrap();
        node.generate(101, &mine).unwrap();
        let w = node.wallet.as_ref().unwrap();
        assert_eq!(w.balance(101, 1), 50 * btc_consensus::COIN);
        assert_eq!(w.immature_balance(101), 100 * 50 * btc_consensus::COIN);

        let other = ScriptBuf::from_bytes(vec![0x00, 0x14].into_iter().chain([7u8; 20]).collect());
        let txid = node.wallet_send(other.clone(), 10 * btc_consensus::COIN, None, false).unwrap();
        assert!(node.mempool.contains(&txid));
        node.generate(1, &mine).unwrap();
        assert!(!node.mempool.contains(&txid));
        let w = node.wallet.as_ref().unwrap();
        let bal = w.balance(102, 1);
        // Two mature coinbases now, minus the 10 sent and the fee.
        assert!(bal < 90 * btc_consensus::COIN && bal > 89 * btc_consensus::COIN, "balance {bal}");

        // Reopen: wallet state persists and catches up.
        drop(node.wallet.take());
        node.attach_wallet(Wallet::open(&dir.join("w.json")).unwrap()).unwrap();
        assert_eq!(node.wallet.as_ref().unwrap().balance(102, 1), bal);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
