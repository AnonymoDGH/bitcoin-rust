//! Transaction signature checker. Port of TransactionSignatureChecker in src/script/interpreter.cpp.
//! PLACEHOLDER: signature fixed by CONTRACT.md. Owned by agent S5.

use btc_primitives::{Tx, TxOut};

use crate::context::{ExecData, SigVersion, SignatureChecker};

pub struct TransactionSignatureChecker<'a> {
    tx: &'a Tx,
    n_in: usize,
    spent_outputs: &'a [TxOut],
}

impl<'a> TransactionSignatureChecker<'a> {
    pub fn new(tx: &'a Tx, n_in: usize, spent_outputs: &'a [TxOut]) -> Self {
        Self { tx, n_in, spent_outputs }
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
        let _ = (self.tx, self.n_in, self.spent_outputs, sig, pubkey, script_code, sigversion);
        unimplemented!("check_ecdsa_signature: owned by agent S5")
    }

    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        exec_data: &ExecData,
    ) -> bool {
        let _ = (self.tx, self.n_in, self.spent_outputs, sig, pubkey, sigversion, exec_data);
        unimplemented!("check_schnorr_signature: owned by agent S5")
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        let _ = (self.tx, lock_time);
        unimplemented!("check_lock_time: owned by agent S5")
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        let _ = (self.tx, sequence);
        unimplemented!("check_sequence: owned by agent S5")
    }
}
