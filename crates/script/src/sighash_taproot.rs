//! BIP341 taproot signature hash. Port of SignatureHashSchnorr in src/script/interpreter.cpp.
//! PLACEHOLDER: signature fixed by CONTRACT.md. Owned by agent S4.

use btc_primitives::{Tx, TxOut};

use crate::context::TapscriptExt;

pub fn signature_hash_taproot(
    tx: &Tx,
    n_in: usize,
    hash_type: u8,
    spent_outputs: &[TxOut],
    ext: Option<&TapscriptExt>,
    annex: Option<&[u8]>,
) -> Option<[u8; 32]> {
    let _ = (tx, n_in, hash_type, spent_outputs, ext, annex);
    unimplemented!("signature_hash_taproot: owned by agent S4")
}
