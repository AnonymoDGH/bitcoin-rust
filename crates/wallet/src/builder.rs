//! Transaction construction. Port of the funding path of CreateTransactionInternal in
//! src/wallet/spend.cpp: coin selection, fee estimation, change, then signing.
//!
//! Input and output sizes are estimated from maximal signature sizes, so the fee paid is never
//! below the fee rate times the signed transaction's virtual size.

use bitcoin::{OutPoint, Script, ScriptBuf, Sequence, Witness};
use btc_primitives::{Tx, TxIn, TxOut};
use thiserror::Error;

use crate::coinselection::{knapsack_solver, select_coins_bnb, Utxo, MAX_MONEY};
use crate::keys::{KeyStore, ScriptKind};
use crate::signer::{sign_transaction, SignError};

const TX_VERSION: u32 = 2;
const SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
/// Core's MAX_STANDARD_TX_WEIGHT.
const MAX_STANDARD_TX_WEIGHT: i64 = 400_000;
/// Smallest change Knapsack aims for (Core's CHANGE_LOWER).
const KNAPSACK_CHANGE_TARGET: i64 = 50_000;
/// Weight of a future P2WPKH spend of the change output (68 vbytes).
const CHANGE_SPEND_WEIGHT: i64 = 272;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("transaction has no recipients")]
    NoRecipients,
    #[error("invalid amount: {0} sat")]
    InvalidAmount(i64),
    #[error("invalid fee rate: {0} sat/kvB")]
    InvalidFeeRate(i64),
    #[error("output of {value} sat is below the dust threshold of {threshold} sat")]
    Dust { value: i64, threshold: i64 },
    #[error("insufficient funds: need {required} sat, have {available} sat after input fees")]
    InsufficientFunds { required: i64, available: i64 },
    #[error(transparent)]
    Sign(#[from] SignError),
}

/// Weight of a signed input, with maximal signature sizes (72 bytes for ECDSA with sighash byte,
/// 64 for schnorr).
fn input_weight(kind: ScriptKind, compressed: bool) -> i64 {
    match kind {
        ScriptKind::P2pkh if compressed => 592,
        ScriptKind::P2pkh => 720,
        ScriptKind::P2wpkh => 272,
        ScriptKind::P2shP2wpkh => 364,
        ScriptKind::P2tr => 230,
    }
}

fn varint_len(n: usize) -> i64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Serialized size of an output paying `script`: value, length prefix and script.
fn output_size(script: &Script) -> i64 {
    8 + varint_len(script.len()) + script.len() as i64
}

/// Weight of everything except the inputs' own data, with `n_inputs` inputs. The segwit marker
/// and flag are counted even for an all-legacy transaction, which only overestimates.
fn base_weight(n_inputs: usize, outputs: &[TxOut]) -> i64 {
    let outputs_size: i64 = outputs.iter().map(|o| output_size(&o.script_pubkey)).sum();
    let body = 8 + varint_len(n_inputs) + varint_len(outputs.len()) + outputs_size;
    4 * body + 2
}

/// Core's CFeeRate::GetFee: fee for `weight` at `fee_rate` (sat/kvB), rounded up per vbyte.
fn fee_for(weight: i64, fee_rate: i64) -> i64 {
    let vsize = (weight + 3) / 4;
    (fee_rate * vsize + 999) / 1000
}

/// Core's GetDustThreshold at the default 3000 sat/kvB dust relay rate.
fn dust_threshold(script: &Script) -> i64 {
    let spend_size = if script.is_witness_program() { 67 } else { 148 };
    3 * (output_size(script) + spend_size)
}

/// Builds and signs a transaction paying `recipients` from the spendable entries of `utxos`.
///
/// Entries whose script `keys` cannot sign for are ignored. Coin selection tries Branch and
/// Bound and falls back to Knapsack. Change goes to `change_script` unless it would be dust.
/// `fee_rate_sat_per_kvb` is the target rate; the long-term rate used for selection equals it.
pub fn build_transaction(
    utxos: &[(OutPoint, TxOut)],
    recipients: &[(ScriptBuf, i64)],
    change_script: ScriptBuf,
    fee_rate_sat_per_kvb: i64,
    keys: &KeyStore,
) -> Result<Tx, BuildError> {
    let rate = fee_rate_sat_per_kvb;
    if rate < 0 {
        return Err(BuildError::InvalidFeeRate(rate));
    }
    if recipients.is_empty() {
        return Err(BuildError::NoRecipients);
    }

    let mut recipient_outs = Vec::with_capacity(recipients.len());
    let mut recipient_sum = 0i64;
    for (script, value) in recipients {
        let value = *value;
        if value <= 0 {
            return Err(BuildError::InvalidAmount(value));
        }
        let threshold = dust_threshold(script);
        if value < threshold {
            return Err(BuildError::Dust { value, threshold });
        }
        recipient_sum = recipient_sum
            .checked_add(value)
            .filter(|sum| *sum <= MAX_MONEY)
            .ok_or(BuildError::InvalidAmount(value))?;
        recipient_outs.push(TxOut::new(value, script.clone()));
    }

    let mut spendable: Vec<(&OutPoint, &TxOut)> = Vec::new();
    let mut coins: Vec<Utxo> = Vec::new();
    for (outpoint, output) in utxos {
        if output.value <= 0 || output.value > MAX_MONEY {
            continue;
        }
        let Some((id, kind)) = keys.is_mine(&output.script_pubkey) else {
            continue;
        };
        let compressed = keys.private_key(&id).is_some_and(|key| key.compressed);
        let weight = input_weight(kind, compressed);
        coins.push(Utxo {
            value: output.value,
            input_bytes: (weight + 3) / 4,
        });
        spendable.push((outpoint, output));
    }

    // Sized for every spendable input, so the target covers any subset that gets selected.
    let target = recipient_sum + fee_for(base_weight(coins.len(), &recipient_outs), rate);
    let cost_of_change =
        fee_for(4 * output_size(&change_script), rate) + fee_for(CHANGE_SPEND_WEIGHT, rate);
    let selection = select_coins_bnb(
        &coins,
        target,
        cost_of_change,
        rate,
        rate,
        MAX_STANDARD_TX_WEIGHT,
    )
    .or_else(|| {
        knapsack_solver(
            &coins,
            target,
            KNAPSACK_CHANGE_TARGET,
            rate,
            rate,
            MAX_STANDARD_TX_WEIGHT,
        )
    })
    .ok_or_else(|| BuildError::InsufficientFunds {
        required: target,
        available: coins
            .iter()
            .map(|coin| coin.effective_value(rate))
            .filter(|value| *value > 0)
            .sum(),
    })?;

    let mut vin = Vec::with_capacity(selection.inputs.len());
    let mut spent = Vec::with_capacity(selection.inputs.len());
    let mut input_value = 0i64;
    let mut input_fees = 0i64;
    for &index in &selection.inputs {
        let (outpoint, output) = spendable[index];
        vin.push(TxIn {
            prevout: *outpoint,
            script_sig: ScriptBuf::new(),
            sequence: SEQUENCE,
            witness: Witness::new(),
        });
        spent.push(output.clone());
        input_value += output.value;
        input_fees += coins[index].fee(rate);
    }

    let fee_without_change = input_fees + fee_for(base_weight(vin.len(), &recipient_outs), rate);
    let remainder = input_value - recipient_sum - fee_without_change;
    if remainder < 0 {
        return Err(BuildError::InsufficientFunds {
            required: recipient_sum + fee_without_change,
            available: input_value,
        });
    }

    let mut outputs = recipient_outs;
    let change_value = remainder - fee_for(4 * output_size(&change_script), rate);
    if change_value >= dust_threshold(&change_script) {
        outputs.push(TxOut::new(change_value, change_script));
    }

    let mut tx = Tx::new(TX_VERSION, vin, outputs, 0);
    sign_transaction(&mut tx, &spent, keys)?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyId;
    use bitcoin::hashes::Hash;
    use bitcoin::{Txid, WPubkeyHash};
    use btc_script::checker::TransactionSignatureChecker;
    use btc_script::{verify_script, ScriptVerifyFlags};

    fn outpoint(n: u8) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([n; 32]), 0)
    }

    fn script_of(store: &KeyStore, id: &KeyId, kind: ScriptKind) -> ScriptBuf {
        store
            .script_pubkeys(id)
            .unwrap()
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, s)| s.clone())
            .unwrap()
    }

    fn payee(n: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([n; 20]))
    }

    /// Virtual size per BIP141: (3 * base size + total size) / 4, rounded up.
    fn vsize(tx: &Tx) -> i64 {
        let mut base = Vec::new();
        tx.encode_with(&mut base, false).unwrap();
        let weight = 3 * base.len() as i64 + tx.total_size() as i64;
        (weight + 3) / 4
    }

    fn total_in(utxos: &[(OutPoint, TxOut)], tx: &Tx) -> i64 {
        tx.vin
            .iter()
            .map(|input| {
                utxos
                    .iter()
                    .find(|(op, _)| *op == input.prevout)
                    .unwrap()
                    .1
                    .value
            })
            .sum()
    }

    fn assert_all_signed_and_valid(tx: &Tx, utxos: &[(OutPoint, TxOut)]) {
        let spent: Vec<TxOut> = tx
            .vin
            .iter()
            .map(|input| {
                utxos
                    .iter()
                    .find(|(op, _)| *op == input.prevout)
                    .unwrap()
                    .1
                    .clone()
            })
            .collect();
        let flags = ScriptVerifyFlags::P2SH
            | ScriptVerifyFlags::WITNESS
            | ScriptVerifyFlags::TAPROOT
            | ScriptVerifyFlags::DERSIG
            | ScriptVerifyFlags::LOW_S
            | ScriptVerifyFlags::NULLDUMMY
            | ScriptVerifyFlags::STRICTENC;
        for (i, input) in tx.vin.iter().enumerate() {
            let checker = TransactionSignatureChecker::new(tx, i, &spent);
            verify_script(
                input.script_sig.as_bytes(),
                spent[i].script_pubkey.as_bytes(),
                &input.witness.to_vec(),
                flags,
                &checker,
            )
            .unwrap_or_else(|e| panic!("input {i}: {}", e.as_str()));
        }
    }

    #[test]
    fn pays_recipient_and_returns_change_at_requested_rate() {
        let mut store = KeyStore::new();
        let id = store.generate().unwrap();
        let utxos = vec![
            (
                outpoint(1),
                TxOut::new(60_000, script_of(&store, &id, ScriptKind::P2wpkh)),
            ),
            (
                outpoint(2),
                TxOut::new(50_000, script_of(&store, &id, ScriptKind::P2wpkh)),
            ),
        ];
        let change = script_of(&store, &id, ScriptKind::P2wpkh);

        for rate in [1_000, 10_000] {
            let tx = build_transaction(&utxos, &[(payee(9), 70_000)], change.clone(), rate, &store)
                .unwrap();

            assert_eq!(tx.version, 2);
            assert_eq!(tx.lock_time, 0);
            assert!(tx.vin.iter().all(|i| i.sequence.0 == 0xffff_fffd));
            assert_eq!(tx.vout[0], TxOut::new(70_000, payee(9)));
            assert_eq!(tx.vout.len(), 2, "change output expected");
            assert_eq!(tx.vout[1].script_pubkey, change);

            let fee = total_in(&utxos, &tx) - tx.value_out();
            assert_eq!(tx.vout[1].value, total_in(&utxos, &tx) - 70_000 - fee);
            let size = vsize(&tx);
            assert!(
                fee >= rate * size / 1000,
                "fee {fee} below rate for vsize {size}"
            );
            // The estimate runs at most a couple of vbytes per input above the real size.
            let n_in = tx.vin.len() as i64;
            assert!(
                fee <= rate * (size + 2 * n_in + 2) / 1000 + n_in + 3,
                "fee {fee} too high"
            );
            assert_all_signed_and_valid(&tx, &utxos);
        }
    }

    #[test]
    fn dust_change_is_dropped_into_fee() {
        let mut store = KeyStore::new();
        let id = store.generate().unwrap();
        let utxos = vec![(
            outpoint(1),
            TxOut::new(70_300, script_of(&store, &id, ScriptKind::P2wpkh)),
        )];

        let tx = build_transaction(
            &utxos,
            &[(payee(9), 70_000)],
            script_of(&store, &id, ScriptKind::P2wpkh),
            1_000,
            &store,
        )
        .unwrap();

        assert_eq!(tx.vout.len(), 1);
        assert_eq!(total_in(&utxos, &tx) - tx.value_out(), 300);
        assert_all_signed_and_valid(&tx, &utxos);
    }

    #[test]
    fn knapsack_fallback_funds_payment() {
        let mut store = KeyStore::new();
        let id = store.generate().unwrap();
        let p2wpkh = script_of(&store, &id, ScriptKind::P2wpkh);
        let utxos = vec![
            (outpoint(1), TxOut::new(20_000, p2wpkh.clone())),
            (outpoint(2), TxOut::new(9_000, p2wpkh.clone())),
            (outpoint(3), TxOut::new(1_000, p2wpkh.clone())),
        ];

        let tx = build_transaction(&utxos, &[(payee(9), 25_000)], p2wpkh.clone(), 1_000, &store)
            .unwrap();

        assert_eq!(tx.vin.len(), 2);
        assert_eq!(tx.vout.len(), 2);
        let fee = total_in(&utxos, &tx) - tx.value_out();
        assert!(fee >= vsize(&tx));
        assert_all_signed_and_valid(&tx, &utxos);
    }

    #[test]
    fn insufficient_funds_is_reported() {
        let mut store = KeyStore::new();
        let id = store.generate().unwrap();
        let utxos = vec![(
            outpoint(1),
            TxOut::new(10_000, script_of(&store, &id, ScriptKind::P2wpkh)),
        )];

        let err = build_transaction(
            &utxos,
            &[(payee(9), 50_000)],
            script_of(&store, &id, ScriptKind::P2wpkh),
            1_000,
            &store,
        )
        .unwrap_err();
        assert!(matches!(err, BuildError::InsufficientFunds { .. }));
    }

    #[test]
    fn ignores_outputs_it_cannot_sign() {
        let mut ours = KeyStore::new();
        let id = ours.generate().unwrap();
        let mut theirs = KeyStore::new();
        let other = theirs.generate().unwrap();
        let utxos = vec![
            (
                outpoint(1),
                TxOut::new(100_000, script_of(&theirs, &other, ScriptKind::P2wpkh)),
            ),
            (
                outpoint(2),
                TxOut::new(200_000, script_of(&ours, &id, ScriptKind::P2wpkh)),
            ),
        ];

        let tx = build_transaction(
            &utxos,
            &[(payee(9), 50_000)],
            script_of(&ours, &id, ScriptKind::P2wpkh),
            1_000,
            &ours,
        )
        .unwrap();

        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vin[0].prevout, outpoint(2));
    }

    #[test]
    fn rejects_empty_recipients_and_dust_outputs() {
        let mut store = KeyStore::new();
        let id = store.generate().unwrap();
        let change = script_of(&store, &id, ScriptKind::P2wpkh);
        let utxos = vec![(outpoint(1), TxOut::new(100_000, change.clone()))];

        assert!(matches!(
            build_transaction(&utxos, &[], change.clone(), 1_000, &store),
            Err(BuildError::NoRecipients)
        ));
        assert!(matches!(
            build_transaction(&utxos, &[(payee(9), 100)], change, 1_000, &store),
            Err(BuildError::Dust {
                value: 100,
                threshold: 294
            })
        ));
    }

    #[test]
    fn signs_every_script_kind_in_one_transaction() {
        let mut store = KeyStore::new();
        let id = store.generate().unwrap();
        let utxos: Vec<(OutPoint, TxOut)> = [
            ScriptKind::P2pkh,
            ScriptKind::P2wpkh,
            ScriptKind::P2shP2wpkh,
            ScriptKind::P2tr,
        ]
        .into_iter()
        .enumerate()
        .map(|(n, kind)| {
            (
                outpoint(n as u8 + 1),
                TxOut::new(100_000, script_of(&store, &id, kind)),
            )
        })
        .collect();

        let tx = build_transaction(
            &utxos,
            &[(payee(9), 350_000)],
            script_of(&store, &id, ScriptKind::P2tr),
            1_000,
            &store,
        )
        .unwrap();

        assert_eq!(tx.vin.len(), 4);
        assert_all_signed_and_valid(&tx, &utxos);
    }

    #[test]
    fn uncompressed_p2pkh_input_fee_covers_signed_size() {
        let mut store = KeyStore::new();
        let id = store
            .import_wif("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj")
            .unwrap();
        let p2pkh = script_of(&store, &id, ScriptKind::P2pkh);
        let utxos = vec![(outpoint(1), TxOut::new(100_000, p2pkh.clone()))];

        let tx = build_transaction(&utxos, &[(payee(9), 50_000)], p2pkh, 5_000, &store).unwrap();

        let fee = total_in(&utxos, &tx) - tx.value_out();
        assert!(fee >= 5 * vsize(&tx));
        assert_all_signed_and_valid(&tx, &utxos);
    }
}
