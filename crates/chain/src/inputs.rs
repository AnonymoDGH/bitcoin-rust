//! Script checks for every input. Port of `CheckInputScripts` / `CScriptCheck`.

use btc_primitives::{Tx, TxOut};
use btc_script::checker::TransactionSignatureChecker;
use btc_script::{verify_script, ScriptVerifyFlags};

use crate::ValidationError;

/// Verifies every input of a non-coinbase `tx`. `spent[i]` is the output
/// spent by input i (all of them are needed for Taproot sighashes). Uses
/// `btc_script::checker::TransactionSignatureChecker` and `verify_script`.
/// On failure returns `ValidationError::Script { input, error }`.
pub fn check_input_scripts(
    tx: &Tx,
    spent: &[TxOut],
    flags: ScriptVerifyFlags,
) -> Result<(), ValidationError> {
    check_spent_len(tx, spent)?;
    for n_in in 0..tx.vin.len() {
        check_one(tx, spent, flags, n_in)?;
    }
    Ok(())
}

/// Same as `check_input_scripts` but runs inputs on `threads` std threads
/// (scoped), returning the lowest failing input index. `threads <= 1` = serial.
pub fn check_input_scripts_parallel(
    tx: &Tx,
    spent: &[TxOut],
    flags: ScriptVerifyFlags,
    threads: usize,
) -> Result<(), ValidationError> {
    let n = tx.vin.len();
    if threads <= 1 || n <= 1 {
        return check_input_scripts(tx, spent, flags);
    }
    check_spent_len(tx, spent)?;

    let chunk = n.div_ceil(threads);
    let lowest = std::thread::scope(|s| {
        let workers: Vec<_> = (0..n)
            .step_by(chunk)
            .map(|start| {
                let end = (start + chunk).min(n);
                s.spawn(move || {
                    (start..end)
                        .find_map(|n_in| check_one(tx, spent, flags, n_in).err().map(|e| (n_in, e)))
                })
            })
            .collect();
        workers
            .into_iter()
            .filter_map(|w| w.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
            .min_by_key(|(n_in, _)| *n_in)
    });
    lowest.map_or(Ok(()), |(_, e)| Err(e))
}

fn check_spent_len(tx: &Tx, spent: &[TxOut]) -> Result<(), ValidationError> {
    if spent.len() != tx.vin.len() {
        return Err(ValidationError::Other("bad-txns-inputs-missingorspent"));
    }
    Ok(())
}

fn check_one(
    tx: &Tx,
    spent: &[TxOut],
    flags: ScriptVerifyFlags,
    n_in: usize,
) -> Result<(), ValidationError> {
    let input = &tx.vin[n_in];
    let witness: Vec<Vec<u8>> = input.witness.iter().map(<[u8]>::to_vec).collect();
    let checker = TransactionSignatureChecker::new(tx, n_in, spent);
    verify_script(
        input.script_sig.as_bytes(),
        spent[n_in].script_pubkey.as_bytes(),
        &witness,
        flags,
        &checker,
    )
    .map_err(|error| ValidationError::Script { input: n_in, error })
}

/// Verifies only `indices` of a transaction (for confidential transactions,
/// whose remaining inputs are authorised by ring signatures, not scripts).
pub fn check_input_indices(
    tx: &Tx,
    spent: &[TxOut],
    flags: ScriptVerifyFlags,
    indices: &[usize],
) -> Result<(), ValidationError> {
    check_spent_len(tx, spent)?;
    for &n_in in indices {
        check_one(tx, spent, flags, n_in)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, Signing};
    use bitcoin::{OutPoint, PubkeyHash, ScriptBuf, Txid, WPubkeyHash, Witness};
    use btc_primitives::TxIn;
    use btc_script::sighash::{signature_hash_legacy, signature_hash_segwit_v0};
    use btc_script::sighash_taproot::signature_hash_taproot;

    const SIGHASH_ALL: u8 = 1;
    const AMOUNT: i64 = 100_000;

    fn flags() -> ScriptVerifyFlags {
        ScriptVerifyFlags::P2SH
            | ScriptVerifyFlags::WITNESS
            | ScriptVerifyFlags::TAPROOT
            | ScriptVerifyFlags::DERSIG
            | ScriptVerifyFlags::NULLDUMMY
            | ScriptVerifyFlags::CHECKLOCKTIMEVERIFY
            | ScriptVerifyFlags::CHECKSEQUENCEVERIFY
    }

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn hash160_of(pk: &PublicKey) -> [u8; 20] {
        hash160::Hash::hash(&pk.serialize()).to_byte_array()
    }

    fn p2wpkh_spk(pk: &PublicKey) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash160_of(pk)))
    }

    fn p2pkh_spk(pk: &PublicKey) -> ScriptBuf {
        ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash160_of(pk)))
    }

    fn outpoint(tag: u8) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([tag; 32]), 0)
    }

    fn p2wpkh_witness<C: Signing>(
        secp: &Secp256k1<C>,
        sk: &SecretKey,
        tx: &Tx,
        n_in: usize,
        amount: i64,
    ) -> Witness {
        let pk = PublicKey::from_secret_key(secp, sk);
        let script_code = p2pkh_spk(&pk);
        let sighash =
            signature_hash_segwit_v0(script_code.as_bytes(), tx, n_in, SIGHASH_ALL as u32, amount);
        let sig = secp.sign_ecdsa(&Message::from_digest(sighash), sk);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(SIGHASH_ALL);
        Witness::from_slice(&[sig_bytes, pk.serialize().to_vec()])
    }

    /// `n` P2WPKH inputs of `AMOUNT` each, all spent by one key. Inputs listed in `bad` are signed
    /// over a wrong amount and so fail verification.
    fn p2wpkh_case(n: usize, bad: &[usize]) -> (Tx, Vec<TxOut>) {
        let secp = Secp256k1::signing_only();
        let sk = key(1);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let spent: Vec<TxOut> = (0..n)
            .map(|_| TxOut::new(AMOUNT, p2wpkh_spk(&pk)))
            .collect();
        let vin = (0..n).map(|i| TxIn::new(outpoint(i as u8 + 1))).collect();
        let mut tx = Tx::new(2, vin, vec![TxOut::new(90_000, p2wpkh_spk(&pk))], 0);
        for i in 0..n {
            let amount = if bad.contains(&i) { AMOUNT + 1 } else { AMOUNT };
            tx.vin[i].witness = p2wpkh_witness(&secp, &sk, &tx, i, amount);
        }
        (tx, spent)
    }

    #[test]
    fn p2wpkh_spend_verifies() {
        let (tx, spent) = p2wpkh_case(1, &[]);
        assert_eq!(check_input_scripts(&tx, &spent, flags()), Ok(()));
    }

    #[test]
    fn p2wpkh_wrong_amount_fails_on_input_zero() {
        let (tx, mut spent) = p2wpkh_case(1, &[]);
        spent[0].value = AMOUNT + 1;
        assert!(matches!(
            check_input_scripts(&tx, &spent, flags()),
            Err(ValidationError::Script { input: 0, .. })
        ));
    }

    #[test]
    fn p2pkh_legacy_spend_verifies() {
        let secp = Secp256k1::signing_only();
        let sk = key(2);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let spk = p2pkh_spk(&pk);
        let spent = vec![TxOut::new(AMOUNT, spk.clone())];
        let mut tx = Tx::new(
            1,
            vec![TxIn::new(outpoint(7))],
            vec![TxOut::new(90_000, spk.clone())],
            0,
        );

        let sighash = signature_hash_legacy(spk.as_bytes(), &tx, 0, SIGHASH_ALL as u32);
        let sig = secp.sign_ecdsa(&Message::from_digest(sighash), &sk);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(SIGHASH_ALL);
        let pk_bytes = pk.serialize();
        let mut script_sig = vec![sig_bytes.len() as u8];
        script_sig.extend(&sig_bytes);
        script_sig.push(pk_bytes.len() as u8);
        script_sig.extend(pk_bytes);
        tx.vin[0].script_sig = ScriptBuf::from_bytes(script_sig);

        assert_eq!(check_input_scripts(&tx, &spent, flags()), Ok(()));
    }

    #[test]
    fn taproot_key_path_spend_verifies() {
        let secp_sign = Secp256k1::signing_only();
        let secp_verify = Secp256k1::verification_only();
        let internal = Keypair::from_secret_key(&secp_sign, &key(3));
        let (internal_x, _) = internal.x_only_public_key();
        let spk = ScriptBuf::new_p2tr(&secp_verify, internal_x, None);
        let spent = vec![TxOut::new(AMOUNT, spk)];
        let mut tx = Tx::new(
            2,
            vec![TxIn::new(outpoint(9))],
            vec![TxOut::new(90_000, ScriptBuf::new())],
            0,
        );

        let tweaked = internal.tap_tweak(&secp_verify, None).to_keypair();
        let sighash = signature_hash_taproot(&tx, 0, 0x00, &spent, None, None)
            .expect("SIGHASH_DEFAULT is valid");
        let sig = secp_sign.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &tweaked);
        tx.vin[0].witness = Witness::from_slice(&[sig.as_ref().to_vec()]);

        assert_eq!(check_input_scripts(&tx, &spent, flags()), Ok(()));
    }

    #[test]
    fn parallel_reports_bad_input_one_of_two() {
        let (tx, spent) = p2wpkh_case(2, &[1]);
        assert!(matches!(
            check_input_scripts_parallel(&tx, &spent, flags(), 4),
            Err(ValidationError::Script { input: 1, .. })
        ));
        assert!(matches!(
            check_input_scripts(&tx, &spent, flags()),
            Err(ValidationError::Script { input: 1, .. })
        ));
    }

    #[test]
    fn parallel_reports_lowest_failing_index_and_accepts_valid_tx() {
        let (tx, spent) = p2wpkh_case(6, &[4, 2, 5]);
        for threads in [2, 3, 4, 8] {
            assert!(matches!(
                check_input_scripts_parallel(&tx, &spent, flags(), threads),
                Err(ValidationError::Script { input: 2, .. })
            ));
        }
        let (tx, spent) = p2wpkh_case(6, &[]);
        for threads in [0, 1, 2, 4, 16] {
            assert_eq!(
                check_input_scripts_parallel(&tx, &spent, flags(), threads),
                Ok(())
            );
        }
    }

    #[test]
    fn spent_length_mismatch_is_rejected() {
        let (tx, mut spent) = p2wpkh_case(2, &[]);
        spent.pop();
        let expected = ValidationError::Other("bad-txns-inputs-missingorspent");
        assert_eq!(
            check_input_scripts(&tx, &spent, flags()),
            Err(expected.clone())
        );
        assert_eq!(
            check_input_scripts_parallel(&tx, &spent, flags(), 4),
            Err(expected)
        );
    }
}
