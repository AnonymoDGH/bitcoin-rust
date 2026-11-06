//! Transaction signing for the wallet's own outputs. Port of the signing path of src/script/sign.cpp
//! (ProduceSignature) for P2PKH, P2WPKH, P2SH-P2WPKH and taproot key-path spends, using the
//! sighash functions of btc-script.

use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::{PrivateKey, PublicKey, ScriptBuf, Witness};
use btc_primitives::{Tx, TxOut};
use btc_script::checker::TransactionSignatureChecker;
use btc_script::sighash::{signature_hash_legacy, signature_hash_segwit_v0, SIGHASH_ALL};
use btc_script::sighash_taproot::signature_hash_taproot;
use btc_script::{verify_script, ScriptError, ScriptVerifyFlags};
use thiserror::Error;

use crate::keys::{p2wpkh_script, tweaked_keypair, KeyStore, ScriptKind};

const SIGHASH_DEFAULT: u8 = 0x00;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("{spent} spent outputs given for {inputs} inputs")]
    SpentCountMismatch { inputs: usize, spent: usize },
    #[error("no taproot sighash for input {input}")]
    Sighash { input: usize },
    #[error("input {input} failed script verification: {}", .reason.as_str())]
    Verify { input: usize, reason: ScriptError },
}

/// Signs every input of `tx` whose spent output belongs to `keys`. `spent` lists the outputs
/// being spent, one per input, in input order. Inputs spending anything else are left untouched.
///
/// Each signed input is verified with `verify_script` under the standard policy flags.
pub fn sign_transaction(tx: &mut Tx, spent: &[TxOut], keys: &KeyStore) -> Result<(), SignError> {
    if spent.len() != tx.vin.len() {
        return Err(SignError::SpentCountMismatch {
            inputs: tx.vin.len(),
            spent: spent.len(),
        });
    }

    let secp = Secp256k1::new();
    let mut signed = Vec::new();
    for (i, output) in spent.iter().enumerate() {
        let Some((id, kind)) = keys.is_mine(&output.script_pubkey) else {
            continue;
        };
        let Some(key) = keys.private_key(&id) else {
            continue;
        };
        match kind {
            ScriptKind::P2pkh => sign_p2pkh(&secp, tx, i, key),
            ScriptKind::P2wpkh => sign_p2wpkh(&secp, tx, i, key, output.value, None),
            ScriptKind::P2shP2wpkh => {
                let Some(redeem) = p2wpkh_script(&secp, key) else {
                    continue;
                };
                sign_p2wpkh(&secp, tx, i, key, output.value, Some(redeem));
            }
            ScriptKind::P2tr => sign_p2tr(&secp, tx, i, key, spent)?,
        }
        signed.push(i);
    }

    for i in signed {
        verify_input(tx, i, spent)?;
    }
    Ok(())
}

fn sign_p2pkh(secp: &Secp256k1<All>, tx: &mut Tx, i: usize, key: &PrivateKey) {
    let public = PublicKey::from_private_key(secp, key);
    let script_code = ScriptBuf::new_p2pkh(&public.pubkey_hash());
    let sighash = signature_hash_legacy(script_code.as_bytes(), tx, i, SIGHASH_ALL);
    let sig = ecdsa_signature(secp, sighash, key);

    tx.vin[i].script_sig = push_all(&[&sig, &public.to_bytes()]);
    tx.vin[i].witness = Witness::new();
}

fn sign_p2wpkh(
    secp: &Secp256k1<All>,
    tx: &mut Tx,
    i: usize,
    key: &PrivateKey,
    amount: i64,
    redeem: Option<ScriptBuf>,
) {
    let public = PublicKey::from_private_key(secp, key);
    let script_code = ScriptBuf::new_p2pkh(&public.pubkey_hash());
    let sighash = signature_hash_segwit_v0(script_code.as_bytes(), tx, i, SIGHASH_ALL, amount);
    let sig = ecdsa_signature(secp, sighash, key);

    tx.vin[i].script_sig = match redeem {
        Some(script) => push_all(&[script.as_bytes()]),
        None => ScriptBuf::new(),
    };
    tx.vin[i].witness = Witness::from_slice(&[sig, public.to_bytes()]);
}

fn sign_p2tr(
    secp: &Secp256k1<All>,
    tx: &mut Tx,
    i: usize,
    key: &PrivateKey,
    spent: &[TxOut],
) -> Result<(), SignError> {
    let sighash = signature_hash_taproot(tx, i, SIGHASH_DEFAULT, spent, None, None)
        .ok_or(SignError::Sighash { input: i })?;
    let keypair = tweaked_keypair(secp, key).to_keypair();
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &keypair);

    tx.vin[i].script_sig = ScriptBuf::new();
    tx.vin[i].witness = Witness::from_slice(&[sig.serialize().to_vec()]);
    Ok(())
}

/// DER signature from libsecp256k1 (always low-S) followed by the SIGHASH_ALL byte.
fn ecdsa_signature(secp: &Secp256k1<All>, sighash: [u8; 32], key: &PrivateKey) -> Vec<u8> {
    let sig = secp.sign_ecdsa(&Message::from_digest(sighash), &key.inner);
    let mut bytes: Vec<u8> = sig.serialize_der().iter().copied().collect();
    bytes.push(SIGHASH_ALL as u8);
    bytes
}

/// Script of direct pushes. Every item here is at most 75 bytes (signatures, public keys and
/// the 22-byte P2WPKH redeem script), so a one-byte length prefix is always the minimal push.
fn push_all(items: &[&[u8]]) -> ScriptBuf {
    let mut bytes = Vec::new();
    for item in items {
        debug_assert!(!item.is_empty() && item.len() <= 75);
        bytes.push(item.len() as u8);
        bytes.extend_from_slice(item);
    }
    ScriptBuf::from_bytes(bytes)
}

fn policy_flags() -> ScriptVerifyFlags {
    ScriptVerifyFlags::P2SH
        | ScriptVerifyFlags::WITNESS
        | ScriptVerifyFlags::TAPROOT
        | ScriptVerifyFlags::DERSIG
        | ScriptVerifyFlags::LOW_S
        | ScriptVerifyFlags::NULLDUMMY
        | ScriptVerifyFlags::STRICTENC
}

fn verify_input(tx: &Tx, i: usize, spent: &[TxOut]) -> Result<(), SignError> {
    let input = &tx.vin[i];
    let witness = input.witness.to_vec();
    let checker = TransactionSignatureChecker::new(tx, i, spent);
    verify_script(
        input.script_sig.as_bytes(),
        spent[i].script_pubkey.as_bytes(),
        &witness,
        policy_flags(),
        &checker,
    )
    .map_err(|reason| SignError::Verify { input: i, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};
    use btc_primitives::TxIn;

    /// A transaction with one input per script template of every key in `store`, each spending
    /// a distinct output paying that template.
    fn spend_each_kind(store: &KeyStore) -> (Tx, Vec<TxOut>) {
        let mut vin = Vec::new();
        let mut spent = Vec::new();
        for (n, id) in store.key_ids().enumerate() {
            for (_, script) in store.script_pubkeys(id).unwrap() {
                let prevout =
                    OutPoint::new(Txid::from_byte_array([n as u8 + 1; 32]), spent.len() as u32);
                vin.push(TxIn::new(prevout));
                spent.push(TxOut::new(100_000 + spent.len() as i64, script.clone()));
            }
        }
        let payee = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7; 20]));
        (Tx::new(2, vin, vec![TxOut::new(250_000, payee)], 0), spent)
    }

    fn key_store_with_one_compressed_key() -> KeyStore {
        let mut store = KeyStore::new();
        store.generate().unwrap();
        store
    }

    #[test]
    fn signs_and_verifies_every_script_kind() {
        let store = key_store_with_one_compressed_key();
        let (mut tx, spent) = spend_each_kind(&store);
        // One compressed key: P2PKH, P2WPKH, P2SH-P2WPKH and P2TR.
        assert_eq!(spent.len(), 4);

        sign_transaction(&mut tx, &spent, &store).unwrap();

        for (i, out) in spent.iter().enumerate() {
            let input = &tx.vin[i];
            let witness = input.witness.to_vec();
            let checker = TransactionSignatureChecker::new(&tx, i, &spent);
            verify_script(
                input.script_sig.as_bytes(),
                out.script_pubkey.as_bytes(),
                &witness,
                policy_flags(),
                &checker,
            )
            .unwrap_or_else(|e| panic!("input {i}: {}", e.as_str()));
        }
    }

    #[test]
    fn p2pkh_signature_is_der_plus_sighash_all() {
        let mut store = KeyStore::new();
        let id = store
            .import_wif("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj")
            .unwrap();
        let mut tx = Tx::new(
            2,
            vec![TxIn::new(OutPoint::new(Txid::from_byte_array([9; 32]), 0))],
            vec![TxOut::new(9_000, ScriptBuf::new())],
            0,
        );
        let spent = [TxOut::new(10_000, ScriptBuf::new_p2pkh(&id))];

        sign_transaction(&mut tx, &spent, &store).unwrap();

        // scriptSig is <push sig+hashtype> <push uncompressed pubkey>.
        let script_sig = tx.vin[0].script_sig.as_bytes();
        let sig_len = script_sig[0] as usize;
        let sig = &script_sig[1..1 + sig_len];
        let parsed = bitcoin::ecdsa::Signature::from_slice(sig).unwrap();
        assert_eq!(parsed.sighash_type.to_u32(), SIGHASH_ALL);
        assert_eq!(script_sig[1 + sig_len], 65);
        assert!(tx.vin[0].witness.is_empty());
    }

    #[test]
    fn wrong_key_leaves_inputs_unsigned() {
        let owner = key_store_with_one_compressed_key();
        let stranger = key_store_with_one_compressed_key();
        let (mut tx, spent) = spend_each_kind(&owner);

        sign_transaction(&mut tx, &spent, &stranger).unwrap();

        for input in &tx.vin {
            assert!(input.script_sig.is_empty());
            assert!(input.witness.is_empty());
        }
    }

    #[test]
    fn rejects_mismatched_spent_count() {
        let store = key_store_with_one_compressed_key();
        let (mut tx, spent) = spend_each_kind(&store);
        let err = sign_transaction(&mut tx, &spent[..1], &store).unwrap_err();
        assert!(matches!(
            err,
            SignError::SpentCountMismatch {
                inputs: 4,
                spent: 1
            }
        ));
    }

    #[test]
    fn signature_fails_verification_after_output_change() {
        let store = key_store_with_one_compressed_key();
        let (mut tx, spent) = spend_each_kind(&store);
        sign_transaction(&mut tx, &spent, &store).unwrap();

        // Changing an output after signing must invalidate every signature.
        tx.vout[0].value += 1;
        let checker = TransactionSignatureChecker::new(&tx, 0, &spent);
        let witness = tx.vin[0].witness.to_vec();
        let res = verify_script(
            tx.vin[0].script_sig.as_bytes(),
            spent[0].script_pubkey.as_bytes(),
            &witness,
            policy_flags(),
            &checker,
        );
        assert!(res.is_err());
    }
}
