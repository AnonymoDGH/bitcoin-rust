//! In-memory wallet for the wallet RPCs. Keys are placeholders and nothing is
//! signed; only the bookkeeping and the error behaviour matter here.

use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::{PubkeyHash, ScriptHash, WPubkeyHash};
use bitcoin_hashes::{sha256, Hash};
use btc_primitives::{BlockHash, OutPoint, ScriptBuf, Tx, TxIn, TxOut, Txid};
use btc_rpc::{NoteEntry, WalletInfo, WalletRpc, WalletTx, WalletUtxo};

use super::p2wpkh_script;

/// Virtual size charged per send, so the fee is `fee_rate * 200 / 1000` sats.
const MOCK_VSIZE: i64 = 200;
const LOCKED: &str = "Error: wallet is locked; unlock it with walletpassphrase first.";
const UNENCRYPTED_PASSPHRASE: &str =
    "Error: running with an unencrypted wallet, but walletpassphrase was called.";
const UNENCRYPTED_LOCK: &str =
    "Error: running with an unencrypted wallet, but walletlock was called.";

#[derive(Default)]
struct State {
    keys: Vec<(ScriptBuf, String)>,
    utxos: Vec<WalletUtxo>,
    txs: Vec<WalletTx>,
    passphrase: Option<String>,
    unlocked_until: u64,
    counter: u8,
}

impl State {
    fn balance(&self, minconf: u32) -> i64 {
        self.utxos
            .iter()
            .filter(|utxo| utxo.spendable && utxo.confirmations >= minconf)
            .map(|utxo| utxo.amount)
            .sum()
    }

    fn is_locked(&self) -> bool {
        self.passphrase.is_some() && self.unlocked_until <= now()
    }
}

/// Wallet with one confirmed 1 BTC output, one unconfirmed 0.5 BTC output and three
/// received transactions, oldest first.
pub struct MockWallet {
    state: Mutex<State>,
}

impl MockWallet {
    pub fn new() -> Self {
        let utxos = vec![utxo(0xa1, 1_0000_0000, 6), utxo(0xa2, 5000_0000, 0)];
        let txs = [1_0000_0000, 5000_0000, 2500_0000]
            .into_iter()
            .enumerate()
            .map(|(i, amount)| WalletTx {
                txid: Txid::from_byte_array([i as u8 + 1; 32]),
                category: "receive".into(),
                amount,
                fee: None,
                script_pubkey: Some(p2wpkh_script(0xa1)),
                confirmations: 6,
                blockhash: Some(BlockHash::from_byte_array([9; 32])),
                time: 1_700_000_000 + i as i64,
            })
            .collect();
        Self {
            state: Mutex::new(State {
                utxos,
                txs,
                ..State::default()
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
}

fn utxo(seed: u8, amount: i64, confirmations: u32) -> WalletUtxo {
    WalletUtxo {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([seed; 32]),
            vout: 0,
        },
        script_pubkey: p2wpkh_script(seed),
        amount,
        confirmations,
        spendable: true,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl WalletRpc for MockWallet {
    fn get_new_address(&self, kind: Option<&str>) -> Result<ScriptBuf, String> {
        let mut state = self.lock();
        state.counter = state.counter.wrapping_add(1);
        let seed = state.counter;
        let script = match kind.unwrap_or("bech32") {
            "legacy" => ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([seed; 20])),
            "p2sh-segwit" => ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([seed; 20])),
            "bech32" => p2wpkh_script(seed),
            "bech32m" => {
                let mut bytes = vec![0x51, 0x20];
                bytes.extend([seed; 32]);
                ScriptBuf::from_bytes(bytes)
            }
            other => return Err(format!("Unknown address type '{other}'")),
        };
        state
            .keys
            .push((script.clone(), format!("cMockKey{seed:02x}")));
        Ok(script)
    }

    fn get_balance(&self, minconf: u32) -> i64 {
        self.lock().balance(minconf)
    }

    fn list_unspent(&self, minconf: u32, maxconf: u32) -> Vec<WalletUtxo> {
        self.lock()
            .utxos
            .iter()
            .filter(|utxo| (minconf..=maxconf).contains(&utxo.confirmations))
            .cloned()
            .collect()
    }

    fn send_to(
        &self,
        script: ScriptBuf,
        amount: i64,
        fee_rate: Option<i64>,
        subtract_fee: bool,
    ) -> Result<Txid, String> {
        let mut state = self.lock();
        if state.is_locked() {
            return Err(LOCKED.into());
        }
        let fee = fee_rate.unwrap_or(1_000) * MOCK_VSIZE / 1_000;
        let needed = if subtract_fee { amount } else { amount + fee };
        let mut selected = Vec::new();
        let mut total = 0;
        for (index, utxo) in state.utxos.iter().enumerate() {
            if total >= needed {
                break;
            }
            if utxo.spendable && utxo.confirmations >= 1 {
                selected.push(index);
                total += utxo.amount;
            }
        }
        if total < needed {
            return Err("Insufficient funds".into());
        }
        let inputs: Vec<TxIn> = selected
            .iter()
            .map(|&index| TxIn::new(state.utxos[index].outpoint))
            .collect();
        for &index in selected.iter().rev() {
            state.utxos.remove(index);
        }
        let change = total - needed;
        let value = if subtract_fee { amount - fee } else { amount };
        let mut outputs = vec![TxOut::new(value, script.clone())];
        if change > 0 {
            outputs.push(TxOut::new(change, p2wpkh_script(0xc0)));
        }
        let txid = Tx::new(2, inputs, outputs, 0).txid();
        if change > 0 {
            state.utxos.push(WalletUtxo {
                outpoint: OutPoint { txid, vout: 1 },
                script_pubkey: p2wpkh_script(0xc0),
                amount: change,
                confirmations: 0,
                spendable: true,
            });
        }
        state.txs.push(WalletTx {
            txid,
            category: "send".into(),
            amount: -amount,
            fee: Some(fee),
            script_pubkey: Some(script),
            confirmations: 0,
            blockhash: None,
            time: now() as i64,
        });
        Ok(txid)
    }

    fn dump_privkey(&self, script: &ScriptBuf) -> Result<String, String> {
        let state = self.lock();
        if state.is_locked() {
            return Err(LOCKED.into());
        }
        state
            .keys
            .iter()
            .find(|(key_script, _)| key_script == script)
            .map(|(_, wif)| wif.clone())
            .ok_or_else(|| "Private key for address is not known".to_owned())
    }

    fn import_privkey(&self, wif: &str) -> Result<(), String> {
        let mut state = self.lock();
        if state.is_locked() {
            return Err(LOCKED.into());
        }
        let digest = sha256::Hash::hash(wif.as_bytes()).to_byte_array();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&digest[..20]);
        let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash));
        state.keys.push((script, wif.to_owned()));
        Ok(())
    }

    fn wallet_info(&self) -> WalletInfo {
        let state = self.lock();
        WalletInfo {
            name: "mock".into(),
            balance: state.balance(1),
            unconfirmed_balance: state.balance(0) - state.balance(1),
            immature_balance: 0,
            tx_count: state.txs.len(),
            keypool_size: 1000,
            encrypted: state.passphrase.is_some(),
            unlocked_until: if state.is_locked() {
                0
            } else {
                state.unlocked_until
            },
        }
    }

    fn list_transactions(&self, count: usize, skip: usize) -> Vec<WalletTx> {
        let state = self.lock();
        let end = state.txs.len().saturating_sub(skip);
        let start = end.saturating_sub(count);
        state.txs[start..end].to_vec()
    }

    fn encrypt_wallet(&self, passphrase: &str) -> Result<(), String> {
        let mut state = self.lock();
        if state.passphrase.is_some() {
            return Err("Error: wallet already encrypted.".into());
        }
        state.passphrase = Some(passphrase.to_owned());
        state.unlocked_until = 0;
        Ok(())
    }

    fn wallet_passphrase(&self, passphrase: &str, timeout_secs: u64) -> Result<(), String> {
        let mut state = self.lock();
        let expected = state.passphrase.clone();
        match expected {
            None => Err(UNENCRYPTED_PASSPHRASE.into()),
            Some(expected) if expected != passphrase => {
                Err("Error: The wallet passphrase entered was incorrect.".into())
            }
            Some(_) => {
                state.unlocked_until = if timeout_secs == 0 {
                    u64::MAX
                } else {
                    now() + timeout_secs
                };
                Ok(())
            }
        }
    }

    fn wallet_lock(&self) -> Result<(), String> {
        let mut state = self.lock();
        if state.passphrase.is_none() {
            return Err(UNENCRYPTED_LOCK.into());
        }
        state.unlocked_until = 0;
        Ok(())
    }

    fn get_stealth_address(&self) -> Result<String, String> {
        Ok("02".to_owned() + &"ab".repeat(65))
    }

    fn list_stealth_utxos(&self, _minconf: u32, _max_blocks: u32) -> Vec<WalletUtxo> {
        Vec::new()
    }

    fn send_to_stealth(&self, _address_hex: String, _amount: i64, _fee_rate: Option<i64>) -> Result<Txid, String> {
        Ok(Txid::from_byte_array([7u8; 32]))
    }

    fn send_to_confidential(&self, _amount: i64, _fee: i64) -> Result<Txid, String> {
        Ok(Txid::from_byte_array([8u8; 32]))
    }

    fn create_pool_note(&self, _amount: i64, _fee: i64) -> Result<String, String> {
        Ok("aa".repeat(32))
    }

    fn spend_note(&self, _cmu_hex: String, _amount: i64) -> Result<Txid, String> {
        Ok(Txid::from_byte_array([9u8; 32]))
    }

    fn spend_note_shielded(&self, _cmu_hex: String, _fee: i64) -> Result<Txid, String> {
        Ok(Txid::from_byte_array([10u8; 32]))
    }

    fn list_notes(&self) -> Vec<NoteEntry> {
        Vec::new()
    }

    fn export_view_key(&self) -> Result<String, String> {
        Ok("00".repeat(32))
    }
}
