//! Persistent wallet. Port of the parts of src/wallet/wallet.cpp covered by this crate: key
//! bookkeeping, chain tracking (SyncTransaction and block (dis)connection), balances, spending
//! through `build_transaction`, and encryption (EncryptWallet, Unlock, Lock).
//!
//! State lives in one JSON file, rewritten atomically (temporary file, then rename) on every
//! change. Keys keep their output scripts and public keys even while the wallet is locked, so
//! `is_mine` works without the secrets.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{BlockHash, NetworkKind, OutPoint, PrivateKey, PublicKey, ScriptBuf, Txid};
use btc_primitives::{Block, Tx, TxOut};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::builder::{build_transaction, BuildError};
use crate::crypter::{
    decrypt_secret, encrypt_secret, Crypter, DEFAULT_DERIVE_ITERATIONS, KEY_SIZE, SALT_SIZE,
};
use crate::keys::{KeyError, KeyId, KeyStore, ScriptKind};

const FILE_VERSION: u32 = 1;
/// Core's COINBASE_MATURITY. A coinbase is spendable once its depth exceeds it.
const COINBASE_MATURITY: u32 = 100;
/// Passes of the fee-subtraction loop before the last transaction is accepted as is.
const FEE_SUBTRACTION_PASSES: usize = 4;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("wallet file I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("corrupt wallet file: {0}")]
    Corrupt(String),
    #[error("wallet is locked")]
    Locked,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("passphrase cannot be empty")]
    EmptyPassphrase,
    #[error("insufficient funds: need {required} sat, have {available} sat")]
    InsufficientFunds { required: i64, available: i64 },
    #[error("transaction construction failed: {0}")]
    Build(String),
    #[error("wallet is already encrypted")]
    AlreadyEncrypted,
    #[error("wallet is not encrypted")]
    NotEncrypted,
    #[error("script does not belong to this wallet")]
    NotMine,
    #[error("key cannot produce a {0:?} script")]
    NoScript(ScriptKind),
    #[error("input is already spent by wallet transaction {0}")]
    Conflict(Txid),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Stealth(#[from] crate::stealth::StealthError),
}

/// How a wallet transaction affects the wallet, as `listtransactions` categorizes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Send,
    Receive,
    Generate,
}

/// A transaction that credits or debits the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletTxRecord {
    pub txid: Txid,
    pub block_hash: Option<BlockHash>,
    pub height: Option<u32>,
    /// Header time of the confirming block; 0 while unconfirmed.
    pub time: i64,
    /// Wallet credit minus wallet debit, in satoshis.
    pub amount: i64,
    /// Inputs minus outputs, known only when every input is a wallet coin.
    pub fee: Option<i64>,
    pub category: Category,
}

/// An output the wallet can pay, with the spend that consumes it if any.
#[derive(Clone, Debug)]
struct Coin {
    txout: TxOut,
    height: Option<u32>,
    is_coinbase: bool,
    spent_by: Option<Txid>,
}

#[derive(Clone, Copy, Debug)]
struct Confirmation {
    height: Option<u32>,
    block_hash: Option<BlockHash>,
    time: i64,
}

#[derive(Clone)]
enum Secret {
    Plain(PrivateKey),
    /// `EncryptSecret` output: the 32-byte secret under the master key.
    Encrypted(Vec<u8>),
}

#[derive(Clone)]
struct KeyRecord {
    pubkey: PublicKey,
    compressed: bool,
    testnet: bool,
    scripts: Vec<(ScriptKind, ScriptBuf)>,
    secret: Secret,
}

/// `CMasterKey`: the random master key, encrypted under the passphrase-derived key.
#[derive(Clone)]
struct MasterKey {
    salt: [u8; SALT_SIZE],
    rounds: u32,
    encrypted: Vec<u8>,
    /// SHA256D of the master key, to reject a wrong passphrase before any key is decrypted.
    check: [u8; 32],
}

pub struct Wallet {
    path: PathBuf,
    /// Plaintext keys. Empty while an encrypted wallet is locked.
    keys: KeyStore,
    key_records: BTreeMap<KeyId, KeyRecord>,
    script_index: HashMap<ScriptBuf, (KeyId, ScriptKind)>,
    coins: BTreeMap<OutPoint, Coin>,
    txs: Vec<WalletTxRecord>,
    master: Option<MasterKey>,
    /// Decrypted master key while unlocked.
    master_key: Option<[u8; KEY_SIZE]>,
    unlocked_until: Option<u64>,
    best_block: Option<(BlockHash, u32)>,
}

impl Wallet {
    /// Creates an empty wallet file at `path`. Fails if the file already exists.
    pub fn create(path: &Path) -> Result<Wallet, WalletError> {
        if path.exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "wallet file exists").into());
        }
        let wallet = Wallet::empty(path.to_path_buf());
        wallet.save()?;
        Ok(wallet)
    }

    /// Loads the wallet stored at `path`. An encrypted wallet opens locked.
    pub fn open(path: &Path) -> Result<Wallet, WalletError> {
        let bytes = fs::read(path)?;
        let file: WalletFile =
            serde_json::from_slice(&bytes).map_err(|e| corrupt(format!("parse: {e}")))?;
        Wallet::from_file(path.to_path_buf(), file)
    }

    fn empty(path: PathBuf) -> Wallet {
        Wallet {
            path,
            keys: KeyStore::new(),
            key_records: BTreeMap::new(),
            script_index: HashMap::new(),
            coins: BTreeMap::new(),
            txs: Vec::new(),
            master: None,
            master_key: None,
            unlocked_until: None,
            best_block: None,
        }
    }

    // ----- keys and addresses -------------------------------------------------------------

    /// Derives a fresh key and returns the output script of `kind`.
    pub fn new_script(&mut self, kind: ScriptKind) -> Result<ScriptBuf, WalletError> {
        self.check_unlocked()?;
        let id = self.keys.generate()?;
        let key = *self.keys.private_key(&id).expect("generated key is stored");
        let id = self.add_key(key)?;
        self.save()?;
        self.script_of_kind(&id, kind)
    }

    /// Derives the wallet's reusable stealth invitation address.
    ///
    /// Deterministically derived from the first wallet key (spending and
    /// scan secrets are domain-separated hashes of the key secret), so no
    /// new secret material is stored and encrypted wallets keep the
    /// protection of the existing crypter. Creates a key if the wallet is
    /// empty, like `new_script`. Requires the wallet to be unlocked.
    pub fn stealth_address(&mut self) -> Result<crate::stealth::StealthAddress, WalletError> {
        self.check_unlocked()?;
        if self.keys.is_empty() {
            // Ensure at least one wallet key exists to derive from.
            self.new_script(ScriptKind::P2wpkh)?;
        }
        Ok(self.stealth_keys()?.address())
    }

    /// The stealth keypair behind `stealth_address`.
    pub fn stealth_keys(&self) -> Result<crate::stealth::StealthKeys, WalletError> {
        use bitcoin_hashes::{sha256, Hash as _};
        let id = self
            .keys
            .key_ids()
            .next()
            .ok_or(WalletError::Locked)?;
        let key = self.keys.private_key(id).ok_or(WalletError::Locked)?;
        let secret = key.inner.secret_bytes();
        let derive = |label: &[u8]| -> Result<[u8; 32], WalletError> {
            let mut buf = secret.to_vec();
            buf.extend_from_slice(label);
            let hash = sha256::Hash::hash(&buf);
            let mut out = [0u8; 32];
            out.copy_from_slice(hash.as_ref());
            Ok(out)
        };
        crate::stealth::StealthKeys::from_secrets(
            &derive(b"anoncoin-stealth-spending")?,
            &derive(b"anoncoin-stealth-scan")?,
        )
        .map_err(WalletError::Stealth)
    }

    /// Imports a WIF private key. Importing a known key changes nothing.
    pub fn import_wif(&mut self, wif: &str) -> Result<KeyId, WalletError> {
        self.check_unlocked()?;
        let key = PrivateKey::from_wif(wif).map_err(KeyError::InvalidWif)?;
        let id = self.add_key(key)?;
        self.save()?;
        Ok(id)
    }

    /// WIF of the key that owns `script`. Requires the wallet to be unlocked when encrypted.
    pub fn dump_wif(&self, script: &ScriptBuf) -> Result<String, WalletError> {
        let (id, _) = self.script_index.get(script).ok_or(WalletError::NotMine)?;
        if !self.is_unlocked_at(now_unix()) {
            return Err(WalletError::Locked);
        }
        self.keys.export_wif(id).ok_or(WalletError::Locked)
    }

    pub fn is_mine(&self, script: &ScriptBuf) -> bool {
        self.script_index.contains_key(script)
    }

    /// Adds `key` to the wallet and returns its id. The caller saves the file.
    fn add_key(&mut self, key: PrivateKey) -> Result<KeyId, WalletError> {
        let secp = Secp256k1::new();
        let pubkey = PublicKey::from_private_key(&secp, &key);
        let id = pubkey.pubkey_hash();
        if self.key_records.contains_key(&id) {
            return Ok(id);
        }
        let secret = if self.is_encrypted() {
            let master = self.master_key.ok_or(WalletError::Locked)?;
            Secret::Encrypted(encrypt_secret(
                &master,
                &key.inner.secret_bytes(),
                &pubkey.to_bytes(),
            ))
        } else {
            Secret::Plain(key)
        };
        let kid = self.keys.import_private_key(key);
        let scripts = self
            .keys
            .script_pubkeys(&kid)
            .expect("imported key is stored")
            .to_vec();
        for (kind, script) in &scripts {
            self.script_index.insert(script.clone(), (id, *kind));
        }
        self.key_records.insert(
            id,
            KeyRecord {
                pubkey,
                compressed: key.compressed,
                testnet: key.network == NetworkKind::Test,
                scripts,
                secret,
            },
        );
        Ok(id)
    }

    fn script_of_kind(&self, id: &KeyId, kind: ScriptKind) -> Result<ScriptBuf, WalletError> {
        self.key_records[id]
            .scripts
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, script)| script.clone())
            .ok_or(WalletError::NoScript(kind))
    }

    // ----- encryption ---------------------------------------------------------------------

    pub fn is_encrypted(&self) -> bool {
        self.master.is_some()
    }

    /// True unless the wallet is encrypted and not unlocked at time `now` (Unix seconds).
    /// Unix time an unlocked encrypted wallet relocks at (0 if locked).
    pub fn unlocked_until(&self) -> u64 {
        self.unlocked_until.unwrap_or(0)
    }

    pub fn is_locked(&self, now: u64) -> bool {
        !self.is_unlocked_at(now)
    }

    /// Encrypts every key under a new random master key, then locks the wallet.
    pub fn encrypt(&mut self, passphrase: &str) -> Result<(), WalletError> {
        if self.is_encrypted() {
            return Err(WalletError::AlreadyEncrypted);
        }
        if passphrase.is_empty() {
            return Err(WalletError::EmptyPassphrase);
        }
        let mut master = [0u8; KEY_SIZE];
        let mut salt = [0u8; SALT_SIZE];
        getrandom::getrandom(&mut master)
            .and_then(|()| getrandom::getrandom(&mut salt))
            .map_err(KeyError::Random)?;

        let crypter =
            Crypter::from_passphrase(passphrase.as_bytes(), &salt, DEFAULT_DERIVE_ITERATIONS)
                .map_err(|e| corrupt(e.to_string()))?;
        let encrypted = crypter.encrypt(&master);
        let check = sha256d::Hash::hash(&master).to_byte_array();

        for record in self.key_records.values_mut() {
            if let Secret::Plain(key) = record.secret {
                record.secret = Secret::Encrypted(encrypt_secret(
                    &master,
                    &key.inner.secret_bytes(),
                    &record.pubkey.to_bytes(),
                ));
            }
        }
        self.master = Some(MasterKey {
            salt,
            rounds: DEFAULT_DERIVE_ITERATIONS,
            encrypted,
            check,
        });
        self.lock_secrets();
        self.save()
    }

    /// Decrypts the master key and all secrets, and keeps them until `until_unix`.
    pub fn unlock(&mut self, passphrase: &str, until_unix: u64) -> Result<(), WalletError> {
        let master_rec = self.master.clone().ok_or(WalletError::NotEncrypted)?;
        let crypter =
            Crypter::from_passphrase(passphrase.as_bytes(), &master_rec.salt, master_rec.rounds)
                .map_err(|e| corrupt(e.to_string()))?;
        let plain = crypter
            .decrypt(&master_rec.encrypted)
            .map_err(|_| WalletError::WrongPassphrase)?;
        let master: [u8; KEY_SIZE] = plain.try_into().map_err(|_| WalletError::WrongPassphrase)?;
        if sha256d::Hash::hash(&master).to_byte_array() != master_rec.check {
            return Err(WalletError::WrongPassphrase);
        }

        let secp = Secp256k1::new();
        let mut keys = KeyStore::new();
        for rec in self.key_records.values() {
            let Secret::Encrypted(ciphertext) = &rec.secret else {
                return Err(corrupt("plaintext key in an encrypted wallet".into()));
            };
            let secret = decrypt_secret(&master, ciphertext, &rec.pubkey.to_bytes())
                .map_err(|e| corrupt(e.to_string()))?;
            let inner = SecretKey::from_slice(&secret).map_err(|e| corrupt(e.to_string()))?;
            let network = if rec.testnet {
                NetworkKind::Test
            } else {
                NetworkKind::Main
            };
            let mut key = PrivateKey::new(inner, network);
            key.compressed = rec.compressed;
            if PublicKey::from_private_key(&secp, &key) != rec.pubkey {
                return Err(corrupt("secret does not match its public key".into()));
            }
            keys.import_private_key(key);
        }

        self.keys = keys;
        self.master_key = Some(master);
        self.unlocked_until = Some(until_unix);
        Ok(())
    }

    /// Drops the decrypted master key and all plaintext keys.
    pub fn lock(&mut self) -> Result<(), WalletError> {
        if !self.is_encrypted() {
            return Err(WalletError::NotEncrypted);
        }
        self.lock_secrets();
        Ok(())
    }

    fn lock_secrets(&mut self) {
        self.master_key = None;
        self.keys = KeyStore::new();
        self.unlocked_until = None;
    }

    fn is_unlocked_at(&self, now: u64) -> bool {
        !self.is_encrypted()
            || (self.master_key.is_some() && self.unlocked_until.is_some_and(|until| now < until))
    }

    /// Fails with `Locked` when signing material is unavailable, forgetting it if it expired.
    fn check_unlocked(&mut self) -> Result<(), WalletError> {
        if self.is_unlocked_at(now_unix()) {
            return Ok(());
        }
        if self.is_encrypted() {
            self.lock_secrets();
        }
        Err(WalletError::Locked)
    }

    // ----- chain tracking -----------------------------------------------------------------

    /// Applies a connected block at `height`, crediting and debiting wallet outputs.
    pub fn block_connected(&mut self, block: &Block, height: u32) -> Result<(), WalletError> {
        let hash = block.block_hash();
        let conf = Confirmation {
            height: Some(height),
            block_hash: Some(hash),
            time: block.header.block_time(),
        };
        for tx in &block.txdata {
            self.apply_tx(tx, conf);
        }
        self.best_block = Some((hash, height));
        self.save()
    }

    /// Reverses `block_connected` for the block at `height`. Its transactions stay in the
    /// history as unconfirmed; coins they created are removed.
    pub fn block_disconnected(&mut self, block: &Block, height: u32) -> Result<(), WalletError> {
        for tx in &block.txdata {
            let txid = tx.txid();
            for input in &tx.vin {
                if let Some(coin) = self.coins.get_mut(&input.prevout) {
                    if coin.spent_by == Some(txid) {
                        coin.spent_by = None;
                    }
                }
            }
            self.coins.retain(|outpoint, _| outpoint.txid != txid);
            if let Some(rec) = self.txs.iter_mut().find(|t| t.txid == txid) {
                rec.height = None;
                rec.block_hash = None;
                rec.time = 0;
            }
        }
        self.best_block = height
            .checked_sub(1)
            .map(|prev| (block.header.prev_blockhash, prev));
        self.save()
    }

    /// Tracks a transaction accepted to the mempool (unconfirmed receives and pending spends).
    pub fn tx_added_to_mempool(&mut self, tx: &Tx) -> Result<(), WalletError> {
        if tx.is_coin_base() {
            return Ok(());
        }
        let txid = tx.txid();
        if self
            .txs
            .iter()
            .any(|t| t.txid == txid && t.height.is_some())
        {
            return Ok(());
        }
        self.apply_tx(
            tx,
            Confirmation {
                height: None,
                block_hash: None,
                time: 0,
            },
        );
        self.save()
    }

    /// Forgets an unconfirmed transaction that left the mempool, with its descendants.
    pub fn tx_removed_from_mempool(&mut self, txid: &Txid) -> Result<(), WalletError> {
        if self
            .txs
            .iter()
            .any(|t| t.txid == *txid && t.height.is_none())
        {
            self.evict_unconfirmed(*txid);
            self.save()?;
        }
        Ok(())
    }

    /// Records a transaction the wallet built and will broadcast. Its inputs become pending
    /// spends. Fails if one of its inputs is already spent by another wallet transaction.
    pub fn commit_transaction(&mut self, tx: &Tx) -> Result<(), WalletError> {
        let txid = tx.txid();
        for input in &tx.vin {
            if let Some(spender) = self.coins.get(&input.prevout).and_then(|c| c.spent_by) {
                if spender != txid {
                    return Err(WalletError::Conflict(spender));
                }
            }
        }
        self.tx_added_to_mempool(tx)
    }

    fn apply_tx(&mut self, tx: &Tx, conf: Confirmation) {
        let txid = tx.txid();
        let is_coinbase = tx.is_coin_base();

        let mut ours_in = 0usize;
        let mut input_value = 0i64;
        if !is_coinbase {
            for input in &tx.vin {
                let Some(spender) = self.coins.get(&input.prevout).map(|c| c.spent_by) else {
                    continue;
                };
                if let Some(other) = spender.filter(|other| *other != txid) {
                    self.evict_unconfirmed(other);
                }
                if let Some(coin) = self.coins.get_mut(&input.prevout) {
                    coin.spent_by = Some(txid);
                    input_value += coin.txout.value;
                    ours_in += 1;
                }
            }
        }

        let mut received = 0i64;
        for (n, out) in tx.vout.iter().enumerate() {
            if !self.script_index.contains_key(&out.script_pubkey) {
                continue;
            }
            received += out.value;
            let coin = self
                .coins
                .entry(OutPoint::new(txid, n as u32))
                .or_insert_with(|| Coin {
                    txout: out.clone(),
                    height: None,
                    is_coinbase,
                    spent_by: None,
                });
            coin.height = conf.height;
        }

        if ours_in == 0 && received == 0 {
            return;
        }
        let record = WalletTxRecord {
            txid,
            block_hash: conf.block_hash,
            height: conf.height,
            time: conf.time,
            amount: received - input_value,
            fee: (!is_coinbase && ours_in == tx.vin.len()).then(|| input_value - tx.value_out()),
            category: if is_coinbase {
                Category::Generate
            } else if ours_in > 0 {
                Category::Send
            } else {
                Category::Receive
            },
        };
        match self.txs.iter_mut().find(|t| t.txid == txid) {
            Some(slot) => *slot = record,
            None => self.txs.push(record),
        }
    }

    /// Removes an unconfirmed transaction, the coins it created, and any unconfirmed
    /// transactions that spend those coins. Its own spends become available again.
    fn evict_unconfirmed(&mut self, txid: Txid) {
        if self
            .txs
            .iter()
            .any(|t| t.txid == txid && t.height.is_some())
        {
            return;
        }
        let children: Vec<Txid> = self
            .coins
            .iter()
            .filter(|(outpoint, _)| outpoint.txid == txid)
            .filter_map(|(_, coin)| coin.spent_by)
            .collect();
        for child in children {
            self.evict_unconfirmed(child);
        }
        self.coins.retain(|outpoint, _| outpoint.txid != txid);
        for coin in self.coins.values_mut() {
            if coin.spent_by == Some(txid) {
                coin.spent_by = None;
            }
        }
        self.txs.retain(|t| t.txid != txid);
    }

    pub fn best_block(&self) -> Option<(BlockHash, u32)> {
        self.best_block
    }

    pub fn set_best_block(&mut self, hash: BlockHash, height: u32) -> Result<(), WalletError> {
        self.best_block = Some((hash, height));
        self.save()
    }

    pub fn transactions(&self) -> &[WalletTxRecord] {
        &self.txs
    }

    // ----- balances and coins -------------------------------------------------------------

    /// Confirmations of `coin` at chain tip `tip`. Zero while unconfirmed.
    fn depth(coin: &Coin, tip: u32) -> u32 {
        match coin.height {
            Some(h) if h <= tip => tip - h + 1,
            _ => 0,
        }
    }

    /// Core's rule: a coinbase is immature until its depth exceeds COINBASE_MATURITY.
    fn is_mature(coin: &Coin, tip: u32) -> bool {
        !coin.is_coinbase || Self::depth(coin, tip) > COINBASE_MATURITY
    }

    /// A transaction is trusted when every input is one of our coins (it is "from me").
    fn trusted(&self, txid: &Txid) -> bool {
        self.txs.iter().any(|t| t.txid == *txid && t.fee.is_some())
    }

    fn is_spendable(&self, outpoint: &OutPoint, coin: &Coin, tip: u32) -> bool {
        coin.spent_by.is_none()
            && Self::is_mature(coin, tip)
            && (Self::depth(coin, tip) > 0 || self.trusted(&outpoint.txid))
    }

    /// Mature unspent value with at least `minconf` confirmations. Unconfirmed value counts
    /// only at `minconf == 0` and only when it comes from our own transactions.
    pub fn balance(&self, tip: u32, minconf: u32) -> i64 {
        self.coins
            .iter()
            .filter(|(_, coin)| coin.spent_by.is_none() && Self::is_mature(coin, tip))
            .filter(|(outpoint, coin)| {
                let depth = Self::depth(coin, tip);
                if depth == 0 {
                    minconf == 0 && self.trusted(&outpoint.txid)
                } else {
                    depth >= minconf
                }
            })
            .map(|(_, coin)| coin.txout.value)
            .sum()
    }

    /// Value of coinbase outputs that are not yet mature.
    pub fn immature_balance(&self, tip: u32) -> i64 {
        self.coins
            .values()
            .filter(|c| c.spent_by.is_none() && c.is_coinbase && !Self::is_mature(c, tip))
            .map(|c| c.txout.value)
            .sum()
    }

    /// Value of unconfirmed outputs from our own transactions.
    pub fn unconfirmed_balance(&self) -> i64 {
        self.coins
            .iter()
            .filter(|(outpoint, c)| {
                c.spent_by.is_none()
                    && c.height.is_none()
                    && !c.is_coinbase
                    && self.trusted(&outpoint.txid)
            })
            .map(|(_, c)| c.txout.value)
            .sum()
    }

    /// Unspent mature outputs whose confirmation count lies in `minconf..=maxconf`.
    pub fn list_unspent(
        &self,
        tip: u32,
        minconf: u32,
        maxconf: u32,
    ) -> Vec<(OutPoint, TxOut, u32)> {
        self.coins
            .iter()
            .filter(|(_, c)| c.spent_by.is_none() && Self::is_mature(c, tip))
            .filter_map(|(outpoint, c)| {
                let depth = Self::depth(c, tip);
                (depth >= minconf && depth <= maxconf).then(|| (*outpoint, c.txout.clone(), depth))
            })
            .collect()
    }

    // ----- spending -----------------------------------------------------------------------

    /// Builds and signs a payment. Spendable coins are mature confirmed outputs and our own
    /// unconfirmed change. Change goes to a fresh P2WPKH script. With `subtract_fee_from_amount`
    /// the fee is taken from the recipients equally, and the first one pays any remainder.
    /// The result is not recorded; call `commit_transaction` to do that.
    pub fn create_transaction(
        &mut self,
        tip_height: u32,
        recipients: &[(ScriptBuf, i64)],
        fee_rate_sat_per_kvb: i64,
        subtract_fee_from_amount: bool,
    ) -> Result<Tx, WalletError> {
        self.check_unlocked()?;
        let utxos: Vec<(OutPoint, TxOut)> = self
            .coins
            .iter()
            .filter(|(op, coin)| self.is_spendable(op, coin, tip_height))
            .map(|(op, coin)| (*op, coin.txout.clone()))
            .collect();
        let change = self.new_script(ScriptKind::P2wpkh)?;

        let mut tx = self.build(&utxos, recipients, &change, fee_rate_sat_per_kvb)?;
        if subtract_fee_from_amount && !recipients.is_empty() {
            let n = recipients.len() as i64;
            for _ in 0..FEE_SUBTRACTION_PASSES {
                let fee = self.fee_of(&tx);
                let (share, remainder) = (fee / n, fee % n);
                let amounts: Vec<(ScriptBuf, i64)> = recipients
                    .iter()
                    .enumerate()
                    .map(|(i, (script, value))| {
                        let cut = share + if i == 0 { remainder } else { 0 };
                        (script.clone(), value - cut)
                    })
                    .collect();
                let next = self.build(&utxos, &amounts, &change, fee_rate_sat_per_kvb)?;
                let converged = self.fee_of(&next) == fee;
                tx = next;
                if converged {
                    break;
                }
            }
        }
        Ok(tx)
    }

    fn build(
        &self,
        utxos: &[(OutPoint, TxOut)],
        recipients: &[(ScriptBuf, i64)],
        change: &ScriptBuf,
        fee_rate: i64,
    ) -> Result<Tx, WalletError> {
        build_transaction(utxos, recipients, change.clone(), fee_rate, &self.keys).map_err(|e| {
            match e {
                BuildError::InsufficientFunds {
                    required,
                    available,
                } => WalletError::InsufficientFunds {
                    required,
                    available,
                },
                other => WalletError::Build(other.to_string()),
            }
        })
    }

    /// Fee paid by `tx`, from the values of its inputs (all of which must be wallet coins).
    fn fee_of(&self, tx: &Tx) -> i64 {
        let inputs: i64 = tx
            .vin
            .iter()
            .map(|input| self.coins.get(&input.prevout).map_or(0, |c| c.txout.value))
            .sum();
        inputs - tx.value_out()
    }

    // ----- persistence --------------------------------------------------------------------

    fn save(&self) -> Result<(), WalletError> {
        let json = serde_json::to_vec_pretty(&self.to_file())
            .map_err(|e| corrupt(format!("serialize: {e}")))?;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&json)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn to_file(&self) -> WalletFile {
        WalletFile {
            version: FILE_VERSION,
            keys: self
                .key_records
                .values()
                .map(|rec| KeyFile {
                    pubkey: rec.pubkey.to_bytes().to_lower_hex_string(),
                    compressed: rec.compressed,
                    testnet: rec.testnet,
                    scripts: rec
                        .scripts
                        .iter()
                        .map(|(kind, script)| ScriptFile {
                            kind: kind_name(*kind).to_string(),
                            script: script.as_bytes().to_lower_hex_string(),
                        })
                        .collect(),
                    secret: match &rec.secret {
                        Secret::Plain(key) => SecretFile::Wif(key.to_wif()),
                        Secret::Encrypted(bytes) => {
                            SecretFile::Encrypted(bytes.to_lower_hex_string())
                        }
                    },
                })
                .collect(),
            master: self.master.as_ref().map(|m| MasterFile {
                salt: m.salt.to_lower_hex_string(),
                rounds: m.rounds,
                encrypted_key: m.encrypted.to_lower_hex_string(),
                check: m.check.to_lower_hex_string(),
            }),
            coins: self
                .coins
                .iter()
                .map(|(outpoint, coin)| CoinFile {
                    txid: outpoint.txid.to_string(),
                    vout: outpoint.vout,
                    value: coin.txout.value,
                    script_pubkey: coin.txout.script_pubkey.as_bytes().to_lower_hex_string(),
                    height: coin.height,
                    is_coinbase: coin.is_coinbase,
                    spent_by: coin.spent_by.map(|t| t.to_string()),
                })
                .collect(),
            transactions: self
                .txs
                .iter()
                .map(|t| TxFile {
                    txid: t.txid.to_string(),
                    block_hash: t.block_hash.map(|h| h.to_string()),
                    height: t.height,
                    time: t.time,
                    amount: t.amount,
                    fee: t.fee,
                    category: category_name(t.category).to_string(),
                })
                .collect(),
            best_block: self.best_block.map(|(hash, height)| BestBlockFile {
                hash: hash.to_string(),
                height,
            }),
        }
    }

    fn from_file(path: PathBuf, file: WalletFile) -> Result<Wallet, WalletError> {
        if file.version != FILE_VERSION {
            return Err(corrupt(format!("unsupported version {}", file.version)));
        }
        let mut wallet = Wallet::empty(path);
        let encrypted = file.master.is_some();
        let secp = Secp256k1::new();

        for kf in file.keys {
            let pubkey = PublicKey::from_slice(&hex_bytes(&kf.pubkey)?)
                .map_err(|e| corrupt(format!("pubkey: {e}")))?;
            let id = pubkey.pubkey_hash();
            let mut scripts = Vec::with_capacity(kf.scripts.len());
            for sf in kf.scripts {
                scripts.push((
                    kind_from_name(&sf.kind)?,
                    ScriptBuf::from_bytes(hex_bytes(&sf.script)?),
                ));
            }
            let secret = match kf.secret {
                SecretFile::Wif(wif) => {
                    if encrypted {
                        return Err(corrupt("plaintext key in an encrypted wallet".into()));
                    }
                    let key =
                        PrivateKey::from_wif(&wif).map_err(|e| corrupt(format!("wif: {e}")))?;
                    if PublicKey::from_private_key(&secp, &key) != pubkey {
                        return Err(corrupt("WIF does not match its public key".into()));
                    }
                    wallet.keys.import_private_key(key);
                    Secret::Plain(key)
                }
                SecretFile::Encrypted(hex) => {
                    if !encrypted {
                        return Err(corrupt("encrypted key without a master key".into()));
                    }
                    Secret::Encrypted(hex_bytes(&hex)?)
                }
            };
            for (kind, script) in &scripts {
                wallet.script_index.insert(script.clone(), (id, *kind));
            }
            wallet.key_records.insert(
                id,
                KeyRecord {
                    pubkey,
                    compressed: kf.compressed,
                    testnet: kf.testnet,
                    scripts,
                    secret,
                },
            );
        }

        if let Some(mf) = file.master {
            wallet.master = Some(MasterKey {
                salt: fixed::<SALT_SIZE>(&hex_bytes(&mf.salt)?)?,
                rounds: mf.rounds,
                encrypted: hex_bytes(&mf.encrypted_key)?,
                check: fixed::<32>(&hex_bytes(&mf.check)?)?,
            });
        }

        for cf in file.coins {
            let outpoint = OutPoint::new(parse_txid(&cf.txid)?, cf.vout);
            let coin = Coin {
                txout: TxOut::new(
                    cf.value,
                    ScriptBuf::from_bytes(hex_bytes(&cf.script_pubkey)?),
                ),
                height: cf.height,
                is_coinbase: cf.is_coinbase,
                spent_by: cf.spent_by.as_deref().map(parse_txid).transpose()?,
            };
            wallet.coins.insert(outpoint, coin);
        }

        for tf in file.transactions {
            wallet.txs.push(WalletTxRecord {
                txid: parse_txid(&tf.txid)?,
                block_hash: tf
                    .block_hash
                    .as_deref()
                    .map(|h| {
                        BlockHash::from_str(h).map_err(|e| corrupt(format!("block hash: {e}")))
                    })
                    .transpose()?,
                height: tf.height,
                time: tf.time,
                amount: tf.amount,
                fee: tf.fee,
                category: category_from_name(&tf.category)?,
            });
        }

        wallet.best_block = match file.best_block {
            Some(bb) => Some((
                BlockHash::from_str(&bb.hash).map_err(|e| corrupt(format!("best block: {e}")))?,
                bb.height,
            )),
            None => None,
        };
        Ok(wallet)
    }
}

// ----- file format --------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    keys: Vec<KeyFile>,
    master: Option<MasterFile>,
    coins: Vec<CoinFile>,
    transactions: Vec<TxFile>,
    best_block: Option<BestBlockFile>,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    pubkey: String,
    compressed: bool,
    testnet: bool,
    scripts: Vec<ScriptFile>,
    secret: SecretFile,
}

#[derive(Serialize, Deserialize)]
struct ScriptFile {
    kind: String,
    script: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SecretFile {
    Wif(String),
    Encrypted(String),
}

#[derive(Serialize, Deserialize)]
struct MasterFile {
    salt: String,
    rounds: u32,
    encrypted_key: String,
    check: String,
}

#[derive(Serialize, Deserialize)]
struct CoinFile {
    txid: String,
    vout: u32,
    value: i64,
    script_pubkey: String,
    height: Option<u32>,
    is_coinbase: bool,
    spent_by: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TxFile {
    txid: String,
    block_hash: Option<String>,
    height: Option<u32>,
    time: i64,
    amount: i64,
    fee: Option<i64>,
    category: String,
}

#[derive(Serialize, Deserialize)]
struct BestBlockFile {
    hash: String,
    height: u32,
}

fn corrupt(msg: String) -> WalletError {
    WalletError::Corrupt(msg)
}

fn hex_bytes(s: &str) -> Result<Vec<u8>, WalletError> {
    Vec::<u8>::from_hex(s).map_err(|e| corrupt(format!("hex: {e}")))
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], WalletError> {
    bytes
        .try_into()
        .map_err(|_| corrupt(format!("expected {N} bytes, got {}", bytes.len())))
}

fn parse_txid(s: &str) -> Result<Txid, WalletError> {
    Txid::from_str(s).map_err(|e| corrupt(format!("txid: {e}")))
}

fn kind_name(kind: ScriptKind) -> &'static str {
    match kind {
        ScriptKind::P2pkh => "p2pkh",
        ScriptKind::P2wpkh => "p2wpkh",
        ScriptKind::P2shP2wpkh => "p2sh-p2wpkh",
        ScriptKind::P2tr => "p2tr",
    }
}

fn kind_from_name(name: &str) -> Result<ScriptKind, WalletError> {
    Ok(match name {
        "p2pkh" => ScriptKind::P2pkh,
        "p2wpkh" => ScriptKind::P2wpkh,
        "p2sh-p2wpkh" => ScriptKind::P2shP2wpkh,
        "p2tr" => ScriptKind::P2tr,
        other => return Err(corrupt(format!("unknown script kind {other}"))),
    })
}

fn category_name(category: Category) -> &'static str {
    match category {
        Category::Send => "send",
        Category::Receive => "receive",
        Category::Generate => "generate",
    }
}

fn category_from_name(name: &str) -> Result<Category, WalletError> {
    Ok(match name {
        "send" => Category::Send,
        "receive" => Category::Receive,
        "generate" => Category::Generate,
        other => return Err(corrupt(format!("unknown category {other}"))),
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{decode_address, Network};
    use bitcoin::hashes::Hash;
    use bitcoin::{TxMerkleNode, WPubkeyHash};
    use btc_primitives::{BlockHeader, TxIn};

    const COIN: i64 = 100_000_000;
    const SUBSIDY: i64 = 50 * COIN;
    const KEY_ONE_WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

    /// A wallet file in the temp directory, removed on drop.
    struct TestFile(PathBuf);

    impl TestFile {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("btc-wallet-{}-{name}.json", std::process::id()));
            let _ = fs::remove_file(&path);
            TestFile(path)
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let mut tmp = self.0.clone().into_os_string();
            tmp.push(".tmp");
            let _ = fs::remove_file(PathBuf::from(tmp));
        }
    }

    fn payee(n: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([n; 20]))
    }

    fn coinbase(height: u32, script: ScriptBuf) -> Tx {
        let mut input = TxIn::new(OutPoint::null());
        input.script_sig = ScriptBuf::from_bytes(vec![0x01, height as u8, (height >> 8) as u8]);
        Tx::new(2, vec![input], vec![TxOut::new(SUBSIDY, script)], 0)
    }

    fn make_block(height: u32, txs: Vec<Tx>) -> Block {
        let header = BlockHeader::new(
            1,
            BlockHash::from_byte_array([0x11; 32]),
            TxMerkleNode::all_zeros(),
            1_600_000_000 + height,
            0x207f_ffff,
            height,
        );
        Block::new(header, txs)
    }

    fn connect(wallet: &mut Wallet, height: u32, txs: Vec<Tx>) -> Block {
        let block = make_block(height, txs);
        wallet.block_connected(&block, height).unwrap();
        block
    }

    /// Connects blocks `from..=to`, each paying a foreign script.
    fn fill(wallet: &mut Wallet, from: u32, to: u32) {
        for height in from..=to {
            connect(wallet, height, vec![coinbase(height, payee(0x99))]);
        }
    }

    /// A wallet whose block 1 coinbase pays its first key; the chain is at height 101.
    fn funded(name: &str) -> (TestFile, Wallet, ScriptBuf) {
        let file = TestFile::new(name);
        let mut wallet = Wallet::create(&file.0).unwrap();
        let script = wallet.new_script(ScriptKind::P2wpkh).unwrap();
        connect(&mut wallet, 1, vec![coinbase(1, script.clone())]);
        fill(&mut wallet, 2, 101);
        (file, wallet, script)
    }

    fn record(wallet: &Wallet, txid: &Txid) -> WalletTxRecord {
        wallet
            .transactions()
            .iter()
            .find(|t| t.txid == *txid)
            .cloned()
            .expect("transaction is recorded")
    }

    #[test]
    fn create_reopen_keeps_keys_and_coins() {
        let file = TestFile::new("reopen");
        let mut wallet = Wallet::create(&file.0).unwrap();
        assert!(matches!(Wallet::create(&file.0), Err(WalletError::Io(_))));
        assert!(matches!(wallet.lock(), Err(WalletError::NotEncrypted)));

        let script = wallet.new_script(ScriptKind::P2wpkh).unwrap();
        let taproot = wallet.new_script(ScriptKind::P2tr).unwrap();
        connect(&mut wallet, 1, vec![coinbase(1, script.clone())]);
        fill(&mut wallet, 2, 101);
        let wif = wallet.dump_wif(&script).unwrap();
        let best = wallet.best_block();
        drop(wallet);

        let wallet = Wallet::open(&file.0).unwrap();
        assert!(wallet.is_mine(&script) && wallet.is_mine(&taproot));
        assert!(!wallet.is_encrypted() && !wallet.is_locked(now_unix()));
        assert_eq!(wallet.dump_wif(&script).unwrap(), wif);
        assert_eq!(wallet.balance(101, 1), SUBSIDY);
        assert_eq!(wallet.list_unspent(101, 1, u32::MAX).len(), 1);
        assert_eq!(wallet.best_block(), best);
        assert_eq!(wallet.transactions().len(), 1);
        assert_eq!(wallet.transactions()[0].category, Category::Generate);
    }

    #[test]
    fn stealth_address_is_deterministic_across_reopen() {
        let file = TestFile::new("stealth");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let first = wallet.stealth_address().unwrap();
        assert_eq!(wallet.stealth_address().unwrap(), first);
        drop(wallet);
        let wallet = Wallet::open(&file.0).unwrap();
        assert_eq!(wallet.stealth_keys().unwrap().address(), first);
    }

    #[test]
    fn imports_known_wif_and_rejects_garbage() {
        let file = TestFile::new("import");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let id = wallet.import_wif(KEY_ONE_WIF).unwrap();
        assert_eq!(wallet.import_wif(KEY_ONE_WIF).unwrap(), id);

        let p2wpkh =
            decode_address(Network::Main, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert!(wallet.is_mine(&p2wpkh));
        assert_eq!(wallet.dump_wif(&p2wpkh).unwrap(), KEY_ONE_WIF);
        assert!(matches!(
            wallet.import_wif("not a key"),
            Err(WalletError::Key(KeyError::InvalidWif(_)))
        ));
        assert!(!wallet.is_mine(&payee(0x01)));
        assert!(matches!(
            wallet.dump_wif(&payee(0x01)),
            Err(WalletError::NotMine)
        ));
    }

    #[test]
    fn coinbase_matures_after_100_blocks() {
        let file = TestFile::new("maturity");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let script = wallet.new_script(ScriptKind::P2wpkh).unwrap();
        connect(&mut wallet, 1, vec![coinbase(1, script.clone())]);
        assert_eq!(wallet.balance(1, 0), 0);
        assert_eq!(wallet.immature_balance(1), SUBSIDY);

        fill(&mut wallet, 2, 99);
        assert_eq!(wallet.balance(99, 0), 0);
        connect(&mut wallet, 100, vec![coinbase(100, payee(0x99))]);
        // Depth 100 is still immature, as in Core's GetTxBlocksToMaturity.
        assert_eq!(wallet.balance(100, 0), 0);
        assert!(wallet.list_unspent(100, 0, u32::MAX).is_empty());
        assert_eq!(wallet.immature_balance(100), SUBSIDY);

        connect(&mut wallet, 101, vec![coinbase(101, payee(0x99))]);
        assert_eq!(wallet.balance(101, 1), SUBSIDY);
        assert_eq!(wallet.balance(101, 102), 0);
        assert_eq!(wallet.immature_balance(101), 0);
        assert_eq!(wallet.list_unspent(101, 101, 101).len(), 1);
        assert!(wallet.list_unspent(101, 0, 100).is_empty());
        assert_eq!(wallet.best_block().map(|(_, h)| h), Some(101));
    }

    #[test]
    fn spend_commit_and_confirm_tracks_change() {
        let (_file, mut wallet, _) = funded("spend");
        let tx = wallet
            .create_transaction(101, &[(payee(0x44), COIN)], 1_000, false)
            .unwrap();
        assert_eq!(tx.vout.len(), 2);
        let change_vout = tx
            .vout
            .iter()
            .position(|out| wallet.is_mine(&out.script_pubkey))
            .unwrap();
        let change = tx.vout[change_vout].value;
        let fee = SUBSIDY - tx.value_out();
        assert!(fee > 0 && fee < 10_000);
        let txid = tx.txid();

        // Nothing is recorded until the transaction is committed.
        assert_eq!(wallet.balance(101, 1), SUBSIDY);
        assert!(wallet.transactions().iter().all(|t| t.txid != txid));

        wallet.commit_transaction(&tx).unwrap();
        assert_eq!(wallet.balance(101, 1), 0);
        assert_eq!(wallet.balance(101, 0), change);
        assert_eq!(wallet.unconfirmed_balance(), change);
        let rec = record(&wallet, &txid);
        assert_eq!(rec.category, Category::Send);
        assert_eq!(rec.fee, Some(fee));
        assert_eq!(rec.height, None);
        assert_eq!(rec.amount, -(COIN + fee));

        // A conflicting transaction (same input, different output) is refused.
        let mut alt = tx.clone();
        alt.vout[0].value -= 1;
        assert!(matches!(
            wallet.commit_transaction(&alt),
            Err(WalletError::Conflict(spender)) if spender == txid
        ));

        // Unconfirmed change is spendable; the original coin is not.
        let chained = wallet
            .create_transaction(101, &[(payee(0x55), COIN / 2)], 1_000, false)
            .unwrap();
        assert_eq!(chained.vin.len(), 1);
        assert_eq!(
            chained.vin[0].prevout,
            OutPoint::new(txid, change_vout as u32)
        );

        let block = connect(
            &mut wallet,
            102,
            vec![coinbase(102, payee(0x99)), tx.clone()],
        );
        assert_eq!(wallet.balance(102, 1), change);
        assert_eq!(wallet.unconfirmed_balance(), 0);
        let rec = record(&wallet, &txid);
        assert_eq!(rec.height, Some(102));
        assert_eq!(rec.block_hash, Some(block.block_hash()));
        assert_eq!(rec.time, block.header.block_time());
        let unspent = wallet.list_unspent(102, 1, u32::MAX);
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(txid, change_vout as u32));
        assert_eq!(unspent[0].2, 1);
    }

    #[test]
    fn disconnect_restores_coins_and_history() {
        let (_file, mut wallet, _) = funded("disconnect");
        let tx = wallet
            .create_transaction(101, &[(payee(0x44), COIN)], 1_000, false)
            .unwrap();
        let txid = tx.txid();
        let change = tx
            .vout
            .iter()
            .find(|o| wallet.is_mine(&o.script_pubkey))
            .unwrap()
            .value;
        wallet.commit_transaction(&tx).unwrap();
        let block = connect(
            &mut wallet,
            102,
            vec![coinbase(102, payee(0x99)), tx.clone()],
        );

        wallet.block_disconnected(&block, 102).unwrap();
        assert_eq!(wallet.balance(101, 1), SUBSIDY);
        assert_eq!(wallet.balance(101, 0), SUBSIDY);
        assert_eq!(record(&wallet, &txid).height, None);
        assert_eq!(
            wallet.best_block(),
            Some((block.header.prev_blockhash, 101))
        );

        // Returning the transaction to the mempool restores the unconfirmed change.
        wallet.tx_added_to_mempool(&tx).unwrap();
        assert_eq!(wallet.balance(101, 0), change);
        assert_eq!(wallet.balance(101, 1), 0);

        wallet.tx_removed_from_mempool(&txid).unwrap();
        assert_eq!(wallet.balance(101, 0), SUBSIDY);
        assert!(wallet.transactions().iter().all(|t| t.txid != txid));
    }

    #[test]
    fn subtract_fee_comes_out_of_recipient() {
        let (_file, mut wallet, _) = funded("subtract");
        let target = payee(0x66);
        let tx = wallet
            .create_transaction(101, &[(target.clone(), COIN)], 1_000, true)
            .unwrap();
        let recipient = tx
            .vout
            .iter()
            .find(|o| o.script_pubkey == target)
            .unwrap()
            .value;
        let fee = SUBSIDY - tx.value_out();
        assert!(fee > 0);
        assert_eq!(recipient, COIN - fee);
    }

    #[test]
    fn list_unspent_applies_confirmation_bounds() {
        let (_file, wallet, _) = funded("unspent");
        assert_eq!(wallet.list_unspent(101, 101, u32::MAX).len(), 1);
        assert!(wallet.list_unspent(101, 102, u32::MAX).is_empty());
        assert!(wallet.list_unspent(101, 0, 100).is_empty());
        assert_eq!(wallet.list_unspent(101, 0, 101)[0].2, 101);
    }

    #[test]
    fn encrypted_wallet_locks_and_signs_after_unlock() {
        let file = TestFile::new("encrypt");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let script = wallet.new_script(ScriptKind::P2wpkh).unwrap();
        let wif = wallet.dump_wif(&script).unwrap();
        connect(&mut wallet, 1, vec![coinbase(1, script.clone())]);
        fill(&mut wallet, 2, 100);

        assert!(matches!(
            wallet.encrypt(""),
            Err(WalletError::EmptyPassphrase)
        ));
        wallet.encrypt("correct horse").unwrap();
        let now = now_unix();
        assert!(wallet.is_encrypted() && wallet.is_locked(now));
        assert!(matches!(
            wallet.encrypt("again"),
            Err(WalletError::AlreadyEncrypted)
        ));
        assert!(matches!(wallet.dump_wif(&script), Err(WalletError::Locked)));
        assert!(matches!(
            wallet.new_script(ScriptKind::P2wpkh),
            Err(WalletError::Locked)
        ));
        assert!(!fs::read_to_string(&file.0).unwrap().contains(&wif));
        drop(wallet);

        let mut wallet = Wallet::open(&file.0).unwrap();
        assert!(wallet.is_encrypted() && wallet.is_locked(now));
        assert!(wallet.is_mine(&script));
        assert!(matches!(wallet.dump_wif(&script), Err(WalletError::Locked)));
        // Chain tracking does not need the secrets.
        connect(&mut wallet, 101, vec![coinbase(101, payee(0x99))]);
        assert_eq!(wallet.balance(101, 1), SUBSIDY);

        assert!(matches!(
            wallet.unlock("wrong passphrase", now + 3600),
            Err(WalletError::WrongPassphrase)
        ));
        assert!(wallet.is_locked(now));
        wallet.unlock("correct horse", now + 3600).unwrap();
        assert!(!wallet.is_locked(now));
        assert_eq!(wallet.dump_wif(&script).unwrap(), wif);

        let tx = wallet
            .create_transaction(101, &[(payee(0x44), COIN)], 1_000, false)
            .unwrap();
        assert!(tx.vin.iter().all(|input| !input.witness.is_empty()));
        wallet.commit_transaction(&tx).unwrap();

        // Once the unlock period ends the wallet is locked again.
        assert!(wallet.is_locked(now + 3601));
        wallet.lock().unwrap();
        assert!(matches!(
            wallet.create_transaction(101, &[(payee(0x45), COIN)], 1_000, false),
            Err(WalletError::Locked)
        ));
    }
}
