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
use btc_primitives::{Block, Tx, TxIn, TxOut};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::builder::{build_transaction, build_transaction_with_extras, BuildError};
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
pub struct Coin {
    pub txout: TxOut,
    pub height: Option<u32>,
    pub is_coinbase: bool,
    pub spent_by: Option<Txid>,
    /// Blinding of a confidential coin created by this wallet.
    pub ct: Option<CtCoinInfo>,
    /// Shielded note of a pool coin created by this wallet.
    pub note: Option<NoteCoinInfo>,
}

/// Wallet bookkeeping for a confidential coin: the blinding is required
/// to spend it (balance proof), and the one-time key secret to sign.
#[derive(Clone, Debug)]
pub struct CtCoinInfo {
    pub value: u64,
    pub blinding: [u8; 32],
    pub secret: [u8; 32],
    pub pubkey_hash: [u8; 20],
}

/// Wallet bookkeeping for a shielded pool note.
#[derive(Clone, Debug)]
pub struct NoteCoinInfo {
    pub value: u64,
    pub rcm: [u8; 32],
    pub secret: [u8; 32],
    pub pubkey_hash: [u8; 20],
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
    /// The first key ever added; anchors the stealth address derivation.
    first_key: Option<KeyId>,
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
            first_key: None,
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
        // Anchor to the first key ever added: generating later keys must
        // not change the invitation address.
        let id = self
            .first_key
            .or_else(|| self.keys.key_ids().next().copied())
            .ok_or(WalletError::Locked)?;
        let key = self.keys.private_key(&id).ok_or(WalletError::Locked)?;
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
    pub fn record_ct_coin(
        &mut self,
        outpoint: OutPoint,
        script: ScriptBuf,
        info: CtCoinInfo,
    ) -> Result<(), WalletError> {
        self.check_unlocked()?;
        let entry = self.coins.entry(outpoint).or_insert_with(|| Coin {
            txout: TxOut::new(0, script),
            height: None,
            is_coinbase: false,
            spent_by: None,
            ct: None,
            note: None,
        });
        entry.ct = Some(info);
        self.save()
    }

    /// Builds a hybrid shielding spend: a mature plaintext wallet coin is
    /// spent into a confidential output owned by a fresh wallet key.
    /// Returns the built+sign transaction and the blinding/key that spend
    /// it (record the latter with `record_ct_coin` after broadcast).
    pub fn create_hybrid_ct(
        &mut self,
        tip_height: u32,
        amount: u64,
        fee: i64,
    ) -> Result<(Tx, CtCoinInfo, OutPoint), WalletError> {
        self.check_unlocked()?;
        if amount == 0 {
            return Err(WalletError::Build("CT amount must be positive".into()));
        }
        let required = amount as i64 + fee;
        let mut candidates: Vec<(OutPoint, TxOut)> = self
            .coins
            .iter()
            .filter(|(op, coin)| {
                coin.ct.is_none()
                    && self.is_spendable(op, coin, tip_height)
                    // Hybrid inputs must be P2PKH: the ECDSA signature goes
                    // in scriptSig so the witness stays free for the CT
                    // balance proof trailer.
                    && matches!(
                        self.keys.is_mine(&coin.txout.script_pubkey),
                        Some((_, ScriptKind::P2pkh))
                    )
            })
            .map(|(op, coin)| (*op, coin.txout.clone()))
            .filter(|(_, txout)| txout.value >= required)
            .collect();
        candidates.sort_by_key(|(_, txout)| txout.value);
        let (spend_outpoint, spent) =
            candidates.into_iter().next().ok_or(WalletError::InsufficientFunds {
                required,
                available: self.balance(tip_height, 0),
            })?;

        // Fresh owner key for the CT output.
        let owner_script = self.new_script(ScriptKind::P2wpkh)?;
        let (owner_id, _) = self
            .script_index
            .get(&owner_script)
            .cloned()
            .ok_or(WalletError::NotMine)?;
        let owner_key = self
            .keys
            .private_key(&owner_id)
            .ok_or(WalletError::Locked)?;
        let owner_secret = owner_key.inner.secret_bytes();
        let pubkey_hash: [u8; 20] = bitcoin::PubkeyHash::from(owner_id.clone()).to_byte_array();
        let mut r_out = [0u8; 32];
        getrandom::getrandom(&mut r_out)
            .map_err(|_| WalletError::Build("ct output blinding failed".into()))?;
        let ct = btc_chain::confidential::create_commitment(amount, r_out)
            .map_err(|_| WalletError::Build("ct commitment failed".into()))?;
        let out_data = btc_chain::confidential::CtOutputData {
            commitment: ct.commitment,
            pubkey_hash,
            proof: ct.proof,
        };
        let ct_script = btc_chain::confidential::encode_ct_script(&out_data)
            .map_err(|_| WalletError::Build("ct script failed".into()))?;

        let mut r_in = [0u8; 32];
        getrandom::getrandom(&mut r_in)
            .map_err(|_| WalletError::Build("ct input blinding failed".into()))?;
        let ct_fee = spent.value - amount as i64;
        let mut vout = vec![TxOut::new(0, ct_script)];
        // Shielding marker: OP_RETURN PUSHDATA2(0x51 | r_in | balance).
        // The balance bytes are zero-filled first; `ct_context` zeroes
        // them too, so the proof computed over the placeholder still
        // verifies once the real proof is embedded.
        let marker = btc_chain::confidential::encode_shield_marker(&r_in, &[0u8; 73]);
        vout.push(TxOut::new(0, ScriptBuf::from_bytes(marker)));

        let input = TxIn::new(spend_outpoint);
        let mut tx = Tx::new(2, vec![input], vout, 0);
        let context = btc_chain::confidential::ct_context(&tx);
        let (proof, _) =
            btc_chain::confidential::create_balance_proof(&[r_in], &[r_out], 0, &context)
                .map_err(|_| WalletError::Build("ct balance failed".into()))?;
        let balance_bytes = btc_chain::confidential::with_fee(
            btc_chain::confidential::serialize_balance_proof(&proof),
            ct_fee as u64,
        );
        tx.vout[1] = TxOut::new(
            0,
            ScriptBuf::from_bytes(btc_chain::confidential::encode_shield_marker(
                &r_in,
                &balance_bytes,
            )),
        );
        // Sign the plaintext input (legacy P2PKH: signature in scriptSig,
        // witness stays empty so consensus lets the input through).
        crate::signer::sign_transaction(&mut tx, &[spent.clone()], &self.keys)
            .map_err(|e| WalletError::Build(e.to_string()))?;
        let info = CtCoinInfo {
            value: amount,
            blinding: r_out,
            secret: owner_secret,
            pubkey_hash,
        };
        let txid = tx.txid();
        Ok((tx, info, OutPoint::new(txid, 0)))
    }

    /// Builds a confidential spend of wallet-held CT coins: CT inputs are
    /// authorised by 16-key ring signatures, amounts stay hidden, and a
    /// balance proof ties inputs to outputs plus the public fee.
    /// Returns the transaction plus blinding records for its outputs.
    pub fn create_ct_spend(
        &mut self,
        tip_height: u32,
        amounts: &[u64],
        fee: i64,
    ) -> Result<(Tx, Vec<CtCoinInfo>, Vec<OutPoint>), WalletError> {
        use btc_chain::confidential::{
            create_balance_proof, create_commitment, ct_context, encode_ct_script,
            serialize_balance_proof, with_fee, CtOutputData,
        };
        use btc_chain::ringsig::sign_ring;
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        if amounts.is_empty() {
            return Err(WalletError::Build("CT spend needs at least one output".into()));
        }
        if amounts.iter().any(|a| *a == 0) {
            return Err(WalletError::Build("CT amount must be positive".into()));
        }
        if fee < 0 {
            return Err(WalletError::Build("CT fee must be non-negative".into()));
        }
        // Collect spendable CT coins, largest first.
        let total_out: u64 = amounts.iter().sum();
        let total_i64 = total_out as i64 + fee;
        let mut candidates: Vec<(OutPoint, CtCoinInfo, TxOut)> = self
            .coins
            .iter()
            .filter(|(op, coin)| {
                coin.ct.is_some() && self.is_spendable(op, coin, tip_height)
            })
            .map(|(op, coin)| (*op, coin.ct.clone().unwrap(), coin.txout.clone()))
            .collect();
        candidates.sort_by_key(|(_, info, _)| std::cmp::Reverse(info.value));
        let mut inputs_meta: Vec<(OutPoint, CtCoinInfo, TxOut)> = Vec::new();
        let mut in_value = 0u64;
        for (outpoint, info, txout) in candidates {
            if in_value >= total_out + fee.max(0) as u64 {
                break;
            }
            in_value += info.value;
            inputs_meta.push((outpoint, info, txout));
        }
        if inputs_meta.is_empty() || in_value < total_out + fee.max(0) as u64 {
            return Err(WalletError::InsufficientFunds {
                required: total_i64,
                available: self.balance(tip_height, 0),
            });
        }

        // Outputs: fresh owner keys, fresh blindings, one CT script each.
        let mut output_infos: Vec<CtCoinInfo> = Vec::with_capacity(amounts.len());
        let mut vout: Vec<TxOut> = Vec::with_capacity(amounts.len());
        for amount in amounts {
            let owner_script = self.new_script(ScriptKind::P2wpkh)?;
            let (owner_id, _) = self
                .script_index
                .get(&owner_script)
                .cloned()
                .ok_or(WalletError::NotMine)?;
            let owner_key = self
                .keys
                .private_key(&owner_id)
                .ok_or(WalletError::Locked)?;
            let owner_secret = owner_key.inner.secret_bytes();
            let pubkey_hash: [u8; 20] =
                bitcoin::PubkeyHash::from(owner_id.clone()).to_byte_array();
            let mut r_out = [0u8; 32];
            getrandom::getrandom(&mut r_out)
                .map_err(|_| WalletError::Build("ct output blinding failed".into()))?;
            let ct = create_commitment(*amount, r_out)
                .map_err(|_| WalletError::Build("ct commitment failed".into()))?;
            let data = CtOutputData {
                commitment: ct.commitment,
                pubkey_hash,
                proof: ct.proof,
            };
            vout.push(TxOut::new(0, encode_ct_script(&data)
                .map_err(|_| WalletError::Build("ct script failed".into()))?));
            output_infos.push(CtCoinInfo {
                value: *amount,
                blinding: r_out,
                secret: owner_secret,
                pubkey_hash,
            });
        }

        // Witness layout (see verify_ct_tx_block):
        //   input 0: [balance_proof(73 + fee prefix ignored here), ring_sig, ring_keys]
        //   input i>0: [ring_sig, ring_keys]
        // Here the balance proof is embedded in the first witness with the
        // public fee as the u64 prefix (73 = fee 8 + pub 33 + z 32).
        let secp = Secp256k1::new();
        let mut vin: Vec<TxIn> = Vec::with_capacity(inputs_meta.len());
        for (outpoint, _info, _txout) in &inputs_meta {
            vin.push(TxIn::new(*outpoint));
        }
        let mut tx = Tx::new(2, vin, vout, 0);
        let context = ct_context(&tx);
        let input_blindings: Vec<[u8; 32]> = inputs_meta.iter().map(|(_, info, _)| info.blinding).collect();
        let output_blindings: Vec<[u8; 32]> = output_infos.iter().map(|info| info.blinding).collect();
        let (proof, _) = create_balance_proof(&input_blindings, &output_blindings, fee.max(0) as u64, &context)
            .map_err(|_| WalletError::Build("ct balance failed".into()))?;
        let balance_bytes = with_fee(serialize_balance_proof(&proof), fee.max(0) as u64);
        for (i, (_outpoint, info, _txout)) in inputs_meta.iter().enumerate() {
            // Ring: own key plus 15 random decoys.
            let mut ring = Vec::with_capacity(16);
            let mut signer_pos = 0usize;
            for j in 0..16 {
                if j == 0 {
                    ring.push(
                        PublicKey::from_secret_key(
                            &secp,
                            &SecretKey::from_slice(&info.secret)
                                .map_err(|_| WalletError::Build("ct secret invalid".into()))?,
                        )
                        .serialize(),
                    );
                    signer_pos = 0;
                } else {
                    let mut decoy = [0u8; 32];
                    getrandom::getrandom(&mut decoy)
                        .map_err(|_| WalletError::Build("ct decoy failed".into()))?;
                    let decoy_sk = SecretKey::from_slice(&decoy)
                        .map_err(|_| WalletError::Build("ct decoy invalid".into()))?;
                    ring.push(PublicKey::from_secret_key(&secp, &decoy_sk).serialize());
                }
            }
            let sig = sign_ring(&context, &ring, signer_pos, &info.secret)
                .map_err(|_| WalletError::Build("ct ring sign failed".into()))?;
            let mut keys_bytes = Vec::with_capacity(16 * 33);
            for key in &ring {
                keys_bytes.extend_from_slice(key);
            }
            if i == 0 {
                tx.vin[i].witness = bitcoin::Witness::from_slice(&[
                    balance_bytes.clone(),
                    btc_chain::confidential::serialize_ring_sig(&sig),
                    keys_bytes,
                ]);
            } else {
                tx.vin[i].witness = bitcoin::Witness::from_slice(&[
                    btc_chain::confidential::serialize_ring_sig(&sig),
                    keys_bytes,
                ]);
            }
        }
        let outpoints: Vec<OutPoint> = (0..tx.vout.len() as u32)
            .map(|vout| OutPoint::new(tx.txid(), vout))
            .collect();
        Ok((tx, output_infos, outpoints))
    }

    /// Imports a WIF private key. Importing a known key changes nothing.
    pub fn record_note_coin(
        &mut self,
        outpoint: OutPoint,
        script: ScriptBuf,
        info: NoteCoinInfo,
    ) -> Result<(), WalletError> {
        self.check_unlocked()?;
        let entry = self.coins.entry(outpoint).or_insert_with(|| Coin {
            txout: TxOut::new(0, script),
            height: None,
            is_coinbase: false,
            spent_by: None,
            ct: None,
            note: None,
        });
        entry.note = Some(info);
        self.save()
    }

    /// Creates a pool note: spends a mature plaintext coin into a pool
    /// note output owned by a fresh wallet key. Returns the built+sign
    /// transaction and the note record to persist after broadcast.
    /// `tip_height` is the tip the note will be inserted at; the note
    /// output is vout 1 of the returned outpoint.
    pub fn create_pool_note(
        &mut self,
        tip_height: u32,
        value: u64,
        fee: i64,
    ) -> Result<(Tx, NoteCoinInfo, OutPoint), WalletError> {
        use btc_chain::notes::{encode_pool_note_committed, note_commitment, Note};
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        self.check_unlocked()?;
        if value == 0 {
            return Err(WalletError::Build("note amount must be positive".into()));
        }
        let required = value as i64 + fee;
        let mut candidates: Vec<(OutPoint, TxOut)> = self
            .coins
            .iter()
            .filter(|(op, coin)| {
                coin.ct.is_none()
                    && coin.note.is_none()
                    && self.is_spendable(op, coin, tip_height)
                    && matches!(
                        self.keys.is_mine(&coin.txout.script_pubkey),
                        Some((_, ScriptKind::P2pkh))
                    )
            })
            .map(|(op, coin)| (*op, coin.txout.clone()))
            .filter(|(_, txout)| txout.value >= required)
            .collect();
        candidates.sort_by_key(|(_, txout)| txout.value);
        let (spend_outpoint, spent) =
            candidates.into_iter().next().ok_or(WalletError::InsufficientFunds {
                required,
                available: self.balance(tip_height, 0),
            })?;

        let owner_script = self.new_script(ScriptKind::P2wpkh)?;
        let (owner_id, _) = self
            .script_index
            .get(&owner_script)
            .cloned()
            .ok_or(WalletError::NotMine)?;
        let owner_key = self
            .keys
            .private_key(&owner_id)
            .ok_or(WalletError::Locked)?;
        let owner_secret = owner_key.inner.secret_bytes();
        let secp = Secp256k1::new();
        let pubkey_bytes = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&owner_secret).map_err(|_| WalletError::Build("note key invalid".into()))?).serialize();
        let mut rcm = [0u8; 32];
        getrandom::getrandom(&mut rcm)
            .map_err(|_| WalletError::Build("note rcm failed".into()))?;
        let note = Note {
            spending_pub: pubkey_bytes,
            value,
            rcm,
        };
        // Value commitment published with the note: C = value*G + rcm*H.
        // The spend opening (value, rcm) re-checks it on chain.
        let value_commitment =
            btc_chain::confidential::commitment_point(value, rcm)
                .map_err(|_| WalletError::Build("note value commitment failed".into()))?;
        let pool_script = ScriptBuf::from_bytes(encode_pool_note_committed(
            &note_commitment(&note),
            &value_commitment,
        ));
        let mut vout = vec![TxOut::new(0, pool_script)];
        let change_value = spent.value - required;
        if change_value >= 546 {
            let change = self.new_script(ScriptKind::P2wpkh)?;
            vout.push(TxOut::new(change_value, change));
        }
        let input = TxIn::new(spend_outpoint);
        let mut tx = Tx::new(2, vec![input], vout, 0);
        crate::signer::sign_transaction(&mut tx, &[spent.clone()], &self.keys)
            .map_err(|e| WalletError::Build(e.to_string()))?;
        let info = NoteCoinInfo {
            value,
            rcm,
            secret: owner_secret,
            pubkey_hash: bitcoin::PubkeyHash::from(owner_id.clone()).to_byte_array(),
        };
        let txid = tx.txid();
        Ok((tx, info, OutPoint::new(txid, 0)))
    }

    /// Builds a note spend: spends the pool output at `prevout` with the
    /// note opening, anchor authorisation and membership path, to the
    /// given recipient script.
    pub fn create_note_spend(
        &mut self,
        prevout: OutPoint,
        note: btc_chain::notes::Note,
        secret: &[u8; 32],
        anchor: [u8; 32],
        index: u32,
        path: Vec<[u8; 32]>,
        recipient_script: ScriptBuf,
        amount: i64,
    ) -> Result<Tx, WalletError> {
        use btc_chain::notes::{
            authorize_spend, encode_note, encode_path, encode_spend_auth,
        };
        if note.value == 0 || amount <= 0 || amount as u64 > note.value {
            return Err(WalletError::Build("note spend amount out of range".into()));
        }
        let mut tx = Tx::new(2, vec![TxIn::new(prevout)], vec![TxOut::new(amount, recipient_script)], 0);
        let context = btc_chain::confidential::ct_context(&tx);
        let sig = authorize_spend(&note, secret, &anchor, &context)
            .map_err(|_| WalletError::Build("note authorize failed".into()))?;
        tx.vin[0].witness = bitcoin::Witness::from_slice(&[
            encode_note(&note),
            encode_spend_auth(&anchor, index, &sig),
            encode_path(&path),
        ]);
        Ok(tx)
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

    /// Export the internal view key (hex) for audit scans.
    pub fn export_view_key(&mut self) -> Result<String, WalletError> {
        self.check_unlocked()?;
        let keys = self.stealth_keys()?;
        Ok(keys
            .view_key()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>())
    }

    /// Notes created by this wallet: commitment, value, spent status.
    pub fn list_notes(&self) -> Vec<crate::shielded::NoteSummary> {
        let secp = Secp256k1::new();
        self.coins
            .values()
            .filter_map(|coin| {
                let info = coin.note.as_ref()?;
                let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &bitcoin::secp256k1::SecretKey::from_slice(&info.secret)
                        .map_err(|_| WalletError::Build("note secret invalid".into()))
                        .ok()?,
                )
                .serialize();
                let note = btc_chain::notes::Note {
                    spending_pub: pubkey,
                    value: info.value,
                    rcm: info.rcm,
                };
                Some(crate::shielded::NoteSummary {
                    commitment: btc_chain::notes::note_commitment(&note),
                    value: info.value,
                    spent: coin.spent_by.is_some(),
                })
            })
            .collect()
    }

    pub fn is_mine(&self, script: &ScriptBuf) -> bool {
        self.script_index.contains_key(script)
    }

    /// A cloned snapshot of coin bookkeeping records (for external callers
    /// that need to look up the note/CT info of an outpoint).
    pub fn coins_snapshot(&self) -> BTreeMap<OutPoint, Coin> {
        self.coins.clone()
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
        if self.first_key.is_none() {
            self.first_key = Some(id);
        }
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
            // Confidential outputs are adopted when their embedded
            // pubkey_hash belongs to one of our keys (the fresh key the
            // output was committed to). The amount is hidden: value stays
            // 0 in the ledger until the owner re-derives it locally.
            let ct_ours = btc_chain::confidential::decode_ct_script(
                out.script_pubkey.as_bytes(),
            )
            .map(|data| {
                self.keys
                    .key_ids()
                    .any(|id| id.to_byte_array() == data.pubkey_hash)
            })
            .unwrap_or(false);
            if !self.script_index.contains_key(&out.script_pubkey) && !ct_ours {
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
                    // Blinding is known only to the wallet that created the
                    // output (recorded via `record_ct_coin`); blindings of
                    // incoming CT outputs are not recoverable here.
                    ct: None,
                    note: None,
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

    /// Builds and signs a stealth payment: a fresh one-time output paid to
    /// `address`, plus an `OP_RETURN` marker publishing the ephemeral public
    /// key so the recipient can scan for it. Change goes to a fresh P2WPKH
    /// script. The result is not recorded; call `commit_transaction` to do that.
    pub fn create_stealth_transaction(
        &mut self,
        tip_height: u32,
        address: crate::stealth::StealthAddress,
        amount: i64,
        fee_rate_sat_per_kvb: i64,
    ) -> Result<Tx, WalletError> {
        self.check_unlocked()?;
        let ephemeral = crate::stealth::ephemeral_secret()?;
        let payment = address.payment(&ephemeral)?;
        let marker = crate::stealth::marker_script(&payment.ephemeral_pub);
        let utxos: Vec<(OutPoint, TxOut)> = self
            .coins
            .iter()
            .filter(|(op, coin)| self.is_spendable(op, coin, tip_height))
            .map(|(op, coin)| (*op, coin.txout.clone()))
            .collect();
        let change = self.new_script(ScriptKind::P2wpkh)?;
        build_transaction_with_extras(
            &utxos,
            &[(payment.script_pubkey.clone(), amount)],
            &[marker],
            change,
            fee_rate_sat_per_kvb,
            &self.keys,
        )
        .map_err(|e| match e {
            BuildError::InsufficientFunds { required, available } => {
                WalletError::InsufficientFunds { required, available }
            }
            other => WalletError::Build(other.to_string()),
        })
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
                    ct: coin.ct.as_ref().map(|info| CtFile {
                        value: info.value,
                        blinding: info.blinding.to_lower_hex_string(),
                        secret: info.secret.to_lower_hex_string(),
                        pubkey_hash: info.pubkey_hash.to_lower_hex_string(),
                    }),
                    note: coin.note.as_ref().map(|info| NoteFile {
                        value: info.value,
                        rcm: info.rcm.to_lower_hex_string(),
                        secret: info.secret.to_lower_hex_string(),
                        pubkey_hash: info.pubkey_hash.to_lower_hex_string(),
                    }),
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
            first_key: self
                .first_key
                .map(|id| id.to_byte_array().to_lower_hex_string()),
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

        wallet.first_key = match &file.first_key {
            Some(hex) => {
                let bytes = hex_bytes(hex)?;
                Some(
                    bitcoin::PubkeyHash::from_slice(&bytes)
                        .map_err(|e| corrupt(format!("first key: {e}")))?,
                )
            }
            None => wallet.keys.key_ids().next().copied(),
        };

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
            let ct = cf
                .ct
                .map(|entry| -> Result<CtCoinInfo, WalletError> {
                    Ok(CtCoinInfo {
                        value: entry.value,
                        blinding: fixed::<32>(&hex_bytes(&entry.blinding)?)?,
                        secret: fixed::<32>(&hex_bytes(&entry.secret)?)?,
                        pubkey_hash: fixed::<20>(&hex_bytes(&entry.pubkey_hash)?)?,
                    })
                })
                .transpose()?;
            let note = cf
                .note
                .map(|entry| -> Result<NoteCoinInfo, WalletError> {
                    Ok(NoteCoinInfo {
                        value: entry.value,
                        rcm: fixed::<32>(&hex_bytes(&entry.rcm)?)?,
                        secret: fixed::<32>(&hex_bytes(&entry.secret)?)?,
                        pubkey_hash: fixed::<20>(&hex_bytes(&entry.pubkey_hash)?)?,
                    })
                })
                .transpose()?;
            let coin = Coin {
                txout: TxOut::new(
                    cf.value,
                    ScriptBuf::from_bytes(hex_bytes(&cf.script_pubkey)?),
                ),
                height: cf.height,
                is_coinbase: cf.is_coinbase,
                spent_by: cf.spent_by.as_deref().map(parse_txid).transpose()?,
                ct,
                note,
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
    #[serde(default)]
    first_key: Option<String>,
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
    #[serde(default)]
    ct: Option<CtFile>,
    #[serde(default)]
    note: Option<NoteFile>,
}

#[derive(Serialize, Deserialize)]
struct NoteFile {
    value: u64,
    rcm: String,
    secret: String,
    pubkey_hash: String,
}

#[derive(Serialize, Deserialize)]
struct CtFile {
    value: u64,
    blinding: String,
    secret: String,
    pubkey_hash: String,
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
    fn hybrid_ct_creation_is_chain_verifiable() {        let file = TestFile::new("ct-hybrid");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let script = wallet.new_script(ScriptKind::P2pkh).unwrap();
        connect(&mut wallet, 1, vec![coinbase(1, script.clone())]);
        fill(&mut wallet, 2, 101);

        let (tx, info, outpoint) = wallet.create_hybrid_ct(101, 40_00000000, 10_000).unwrap();
        wallet.record_ct_coin(outpoint, tx.vout[0].script_pubkey.clone(), info.clone()).unwrap();
        drop(wallet);

        // The blinding survives a save/reopen.
        let wallet = Wallet::open(&file.0).unwrap();
        let coin = wallet.coins.get(&outpoint).expect("ct coin recorded");
        assert_eq!(coin.ct.as_ref().unwrap().blinding, info.blinding);
        assert_eq!(coin.ct.as_ref().unwrap().value, info.value);
        drop(wallet);

        // And the produced tx is acceptable to chain CT verification.
        let spent = [TxOut::new(SUBSIDY, script)];
        let check = |tx: &Tx, spent: &[TxOut], indices: &[usize]| {
            btc_chain::inputs::check_input_indices(
                tx,
                spent,
                btc_script::ScriptVerifyFlags::P2SH | btc_script::ScriptVerifyFlags::WITNESS,
                indices,
            )
        };
        btc_chain::confidential::verify_ct_tx_block(&tx, &spent, &check)
            .expect("hybrid CT tx must verify at chain level");
    }

    #[test]
    fn wallet_ct_spend_verifies_at_chain() {
        let file = TestFile::new("ct-spend");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let script = wallet.new_script(ScriptKind::P2pkh).unwrap();
        connect(&mut wallet, 1, vec![coinbase(1, script.clone())]);
        fill(&mut wallet, 2, 101);

        // Shield 40 coins with the wallet, record the CT coin, then spend
        // 30 of them with a ring signature.
        let (shield_tx, shield_info, shield_op) =
            wallet.create_hybrid_ct(101, 40_00000000, 10_000).unwrap();
        wallet
            .record_ct_coin(shield_op, shield_tx.vout[0].script_pubkey.clone(), shield_info)
            .unwrap();
        // Seed the CT coin as confirmed so it is spendable.
        if let Some(coin) = wallet.coins.get_mut(&shield_op) {
            coin.height = Some(101);
        }
        let (tx, _out_infos, _out_ops) = wallet.create_ct_spend(101, &[40_00000000], 0).unwrap();
        let spent = [TxOut::new(0, shield_tx.vout[0].script_pubkey.clone())];
        let check = |_tx: &Tx, _spent: &[TxOut], _indices: &[usize]| -> Result<(), btc_chain::ValidationError> { Ok(()) };
        btc_chain::confidential::verify_ct_tx_block(&tx, &spent, &check)
            .expect("CT spend with ring signature must verify");
    }

    #[test]
    fn pool_note_creation_and_spend_verify() {
        let file = TestFile::new("pool-note");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let script = wallet.new_script(ScriptKind::P2pkh).unwrap();
        connect(&mut wallet, 1, vec![coinbase(1, script.clone())]);
        fill(&mut wallet, 2, 101);

        // Create a pool note of 1 BTC.
        let (note_tx, note_info, note_op) = wallet.create_pool_note(101, 1_00000000, 10_000).unwrap();
        wallet
            .record_note_coin(note_op, note_tx.vout[1].script_pubkey.clone(), note_info)
            .unwrap();
        drop(wallet);

        let wallet = Wallet::open(&file.0).unwrap();
        let note_coin = wallet
            .coins
            .get(&note_op)
            .and_then(|c| c.note.clone())
            .expect("note coin recorded");
        assert_eq!(note_coin.value, 1_00000000);
        drop(wallet);

        // Build a spend of the mined note output and verify its witnesses.
        let mut tree = btc_chain::notes::NoteTree::new();
        let note = btc_chain::notes::Note {
            spending_pub: {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                bitcoin::secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &bitcoin::secp256k1::SecretKey::from_slice(&note_coin.secret).unwrap(),
                )
                .serialize()
            },
            value: 1_00000000,
            rcm: note_coin.rcm,
        };
        assert_eq!(tree.insert(btc_chain::notes::note_commitment(&note)), 0);
        let anchor = tree.root();
        let path = tree.path(0);
        let spendscript = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x42; 20]));
        let spent_tx = Wallet::open(&file.0)
            .unwrap()
            .create_note_spend(note_op, note.clone(), &note_coin.secret, anchor, 0, path, spendscript, 99_990000)
            .unwrap();
        let spent_outs = [btc_primitives::TxOut::new(0, note_tx.vout[0].script_pubkey.clone())];
        btc_chain::notes::verify_note_tx_block(
            &spent_tx,
            &spent_outs,
            Some(anchor),
        )
        .expect("note spend must verify at chain level");
    }

    #[test]
    fn stealth_address_is_deterministic_across_reopen() {
        let file = TestFile::new("stealth");
        let mut wallet = Wallet::create(&file.0).unwrap();
        let first = wallet.stealth_address().unwrap();
        assert_eq!(wallet.stealth_address().unwrap(), first);
        // Generating more keys must not move the invitation address.
        for _ in 0..5 {
            wallet.new_script(ScriptKind::P2wpkh).unwrap();
        }
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
