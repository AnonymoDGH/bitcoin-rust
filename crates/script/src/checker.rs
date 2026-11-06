//! Transaction signature checker. Port of GenericTransactionSignatureChecker in src/script/interpreter.cpp.

use btc_primitives::{Tx, TxIn, TxOut};
use bitcoin::secp256k1::{
    ecdsa::Signature as EcdsaSignature, schnorr::Signature as SchnorrSignature, Message,
    PublicKey, Secp256k1, XOnlyPublicKey,
};

use crate::context::{ExecData, SigVersion, SignatureChecker};
use crate::sighash::{signature_hash_legacy, signature_hash_segwit_v0};
use crate::opcodes::{
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_GRANULARITY, SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG, LOCKTIME_THRESHOLD,
};

pub struct TransactionSignatureChecker<'a> {
    tx: &'a Tx,
    n_in: usize,
    spent_outputs: &'a [TxOut],
}

impl<'a> TransactionSignatureChecker<'a> {
    pub fn new(tx: &'a Tx, n_in: usize, spent_outputs: &'a [TxOut]) -> Self {
        Self { tx, n_in, spent_outputs }
    }

    fn amount(&self) -> i64 {
        self.spent_outputs.get(self.n_in).map(|o| o.value).unwrap_or(-1)
    }
}

impl SignatureChecker for TransactionSignatureChecker<'_> {
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
    ) -> bool {
        if sig.is_empty() {
            return false;
        }
        let secp = Secp256k1::verification_only();

        let hash_type = sig[sig.len() - 1] as u32;
        let der_bytes = &sig[..sig.len() - 1];

        let sighash = match sigversion {
            SigVersion::Base => signature_hash_legacy(script_code, self.tx, self.n_in, hash_type),
            SigVersion::WitnessV0 => signature_hash_segwit_v0(
                script_code,
                self.tx,
                self.n_in,
                hash_type,
                self.amount(),
            ),
            // Taproot and Tapscript do not use ECDSA.
            _ => return false,
        };

        let pk = match PublicKey::from_slice(pubkey) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let ecdsa_sig = match EcdsaSignature::from_der_lax(der_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let msg = match Message::from_slice(&sighash) {
            Ok(m) => m,
            Err(_) => return false,
        };
        secp.verify_ecdsa(&msg, &ecdsa_sig, &pk).is_ok()
    }

    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        exec_data: &ExecData,
    ) -> bool {
        // Schnorr public keys are x-only and 32 bytes (caller's responsibility to enforce).
        if pubkey.len() != 32 {
            return false;
        }
        if sig.len() != 64 && sig.len() != 65 {
            return false;
        }

        let mut hashtype = 0x00u8; // SIGHASH_DEFAULT
        if sig.len() == 65 {
            hashtype = sig[64];
            if hashtype == 0x00 {
                return false; // SIGHASH_DEFAULT must not be explicitly set
            }
        }
        let raw_sig = &sig[..64];

        let ext = match sigversion {
            SigVersion::Tapscript => exec_data.tapleaf_hash.map(|tapleaf_hash| crate::context::TapscriptExt {
                tapleaf_hash,
                codeseparator_pos: exec_data.codeseparator_pos,
            }),
            _ => None,
        };
        let annex = exec_data.annex.as_deref();

        let sighash = match crate::sighash_taproot::signature_hash_taproot(
            self.tx,
            self.n_in,
            hashtype,
            self.spent_outputs,
            ext.as_ref(),
            annex,
        ) {
            Some(h) => h,
            None => return false,
        };

        let secp = Secp256k1::verification_only();
        let xonly = match XOnlyPublicKey::from_slice(pubkey) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sch_sig = match SchnorrSignature::from_slice(raw_sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let msg = match Message::from_slice(&sighash) {
            Ok(m) => m,
            Err(_) => return false,
        };
        secp.verify_schnorr(&sch_sig, &msg, &xonly).is_ok()
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        // There are two kinds of nLockTime: blockheight and blocktime, distinguished
        // by whether nLockTime < LOCKTIME_THRESHOLD. Comparisons must be apples-to-apples.
        let tx_lock = self.tx.lock_time as i64;
        let both_small = tx_lock < LOCKTIME_THRESHOLD && lock_time < LOCKTIME_THRESHOLD;
        let both_large = tx_lock >= LOCKTIME_THRESHOLD && lock_time >= LOCKTIME_THRESHOLD;
        if !(both_small || both_large) {
            return false;
        }
        if lock_time > tx_lock {
            return false;
        }
        // Disabled nLockTime feature (SEQUENCE_FINAL == disables CHECKLOCKTIMEVERIFY).
        if let Some(input) = self.tx.vin.get(self.n_in) {
            if input.sequence.0 == TxIn::SEQUENCE_FINAL {
                return false;
            }
        } else {
            return false;
        }
        true
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        // Relative lock times via the passed-in operand vs the input's sequence.
        let input = match self.tx.vin.get(self.n_in) {
            Some(i) => i,
            None => return false,
        };
        let tx_sequence = input.sequence.0 as i64;

        // BIP68: version must be >= 2.
        if self.tx.version < 2 {
            return false;
        }
        // DISABLE_FLAG set => no consensus meaning; fail.
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64 != 0 {
            return false;
        }
        // Mask consensus-relevant bits.
        const MASK: i64 = (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK) as i64;
        let tx_seq_masked = tx_sequence & MASK;
        let seq_masked = sequence & MASK;

        // Same-category comparison only (time vs blockheight).
        let tx_is_time = tx_seq_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG as i64;
        let seq_is_time = seq_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG as i64;
        if tx_is_time != seq_is_time {
            return false;
        }
        if seq_masked > tx_seq_masked {
            return false;
        }
        let _ = SEQUENCE_LOCKTIME_GRANULARITY; // kept for parity with Core constants
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::TxIn;
    use bitcoin::{OutPoint, ScriptBuf, Witness};

    fn dummy_tx(version: u32, sequence: u32, lock_time: u32) -> Tx {
        let txin = TxIn {
            prevout: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        };
        Tx::new(version, vec![txin], Vec::new(), lock_time)
    }

    #[test]
    fn lock_time_blockheight_comparison() {
        let tx = dummy_tx(2, 0x0000_0001, 500);
        let outs = [TxOut::new(1_000_000, ScriptBuf::new())];
        let c = TransactionSignatureChecker::new(&tx, 0, &outs);
        assert!(c.check_lock_time(400));
        assert!(c.check_lock_time(500));
        assert!(!c.check_lock_time(501));
    }

    #[test]
    fn lock_time_type_mismatch_fails() {
        // tx locktime is time-based (>= threshold), script operand is height-based.
        let tx = dummy_tx(2, 0x0000_0001, 500_000_001);
        let outs = [TxOut::new(1_000_000, ScriptBuf::new())];
        let c = TransactionSignatureChecker::new(&tx, 0, &outs);
        assert!(!c.check_lock_time(400));
    }

    #[test]
    fn sequence_requires_version_2() {
        let tx = dummy_tx(1, 0x0000_0100, 0);
        let outs = [TxOut::new(1_000_000, ScriptBuf::new())];
        let c = TransactionSignatureChecker::new(&tx, 0, &outs);
        assert!(!c.check_sequence(1));
    }

    #[test]
    fn sequence_disable_flag_fails() {
        let tx = dummy_tx(2, 0x8000_0000 | 100, 0);
        let outs = [TxOut::new(1_000_000, ScriptBuf::new())];
        let c = TransactionSignatureChecker::new(&tx, 0, &outs);
        assert!(!c.check_sequence(100));
    }

    #[test]
    fn sequence_blockheight_comparison() {
        let tx = dummy_tx(2, 100, 0);
        let outs = [TxOut::new(1_000_000, ScriptBuf::new())];
        let c = TransactionSignatureChecker::new(&tx, 0, &outs);
        assert!(c.check_sequence(50));
        assert!(c.check_sequence(100));
        assert!(!c.check_sequence(101));
    }
}
