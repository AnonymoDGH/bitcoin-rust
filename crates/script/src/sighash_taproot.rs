//! BIP341 taproot signature hash. Port of SignatureHashSchnorr in src/script/interpreter.cpp.

use btc_primitives::{Tx, TxOut};
use bitcoin_hashes::{sha256, Hash};

use crate::context::TapscriptExt;

const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_NONE: u8 = 0x02;
const SIGHASH_SINGLE: u8 = 0x03;
const SIGHASH_ANYONECANPAY: u8 = 0x80;
const SIGHASH_OUTPUT_MASK: u8 = 0x03;
const SIGHASH_INPUT_MASK: u8 = 0x80;

const TAG_TAP_SIGNHASH: &[u8] = b"TapSighash";

/// Tagged hash as defined in BIP341 (single SHA256): SHA256(SHA256(tag) || SHA256(tag) || data).
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag);
    let mut buf = Vec::with_capacity(64 + data.len());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(data);
    sha256::Hash::hash(&buf).to_byte_array()
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn serialize_prevout(out: &mut Vec<u8>, txin: &btc_primitives::TxIn) {
    out.extend_from_slice(txin.prevout.txid.as_byte_array());
    out.extend_from_slice(&txin.prevout.vout.to_le_bytes());
}

fn serialize_script(out: &mut Vec<u8>, script: &bitcoin::Script) {
    let bytes = script.as_bytes();
    write_compact_size(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn serialize_output(out: &mut Vec<u8>, txout: &TxOut) {
    out.extend_from_slice(&txout.value.to_le_bytes());
    serialize_script(out, txout.script_pubkey.as_script());
}

fn prevouts_single_hash(tx: &Tx) -> [u8; 32] {
    let mut b = Vec::new();
    for txin in &tx.vin {
        serialize_prevout(&mut b, txin);
    }
    sha256::Hash::hash(&b).to_byte_array()
}

fn amounts_single_hash(spent_outputs: &[TxOut]) -> [u8; 32] {
    let mut b = Vec::new();
    for txout in spent_outputs {
        b.extend_from_slice(&txout.value.to_le_bytes());
    }
    sha256::Hash::hash(&b).to_byte_array()
}

fn scripts_single_hash(spent_outputs: &[TxOut]) -> [u8; 32] {
    let mut b = Vec::new();
    for txout in spent_outputs {
        serialize_script(&mut b, txout.script_pubkey.as_script());
    }
    sha256::Hash::hash(&b).to_byte_array()
}

fn sequences_single_hash(tx: &Tx) -> [u8; 32] {
    let mut b = Vec::new();
    for txin in &tx.vin {
        b.extend_from_slice(&txin.sequence.0.to_le_bytes());
    }
    sha256::Hash::hash(&b).to_byte_array()
}

fn outputs_single_hash(tx: &Tx) -> [u8; 32] {
    let mut b = Vec::new();
    for txout in &tx.vout {
        serialize_output(&mut b, txout);
    }
    sha256::Hash::hash(&b).to_byte_array()
}

/// Port of SignatureHashSchnorr.
/// `ext` = TapscriptExt for script-path spends (None for key-path).
/// `annex` = full annex buffer (starts with 0x50) when present.
/// Returns None for invalid hashtype or out-of-range SIGHASH_SINGLE (Core returns false).
pub fn signature_hash_taproot(
    tx: &Tx,
    n_in: usize,
    hash_type: u8,
    spent_outputs: &[TxOut],
    ext: Option<&TapscriptExt>,
    annex: Option<&[u8]>,
) -> Option<[u8; 32]> {
    if n_in >= tx.vin.len() {
        return None;
    }
    // Only 0x00..0x03 and 0x81..0x83 are defined hash types.
    if !(hash_type <= 0x03 || (0x81..=0x83).contains(&hash_type)) {
        return None;
    }

    let ext_flag: u8 = if ext.is_some() { 1 } else { 0 };
    let output_type = if hash_type == 0x00 { SIGHASH_ALL } else { hash_type & SIGHASH_OUTPUT_MASK };
    let input_type = hash_type & SIGHASH_INPUT_MASK;
    let have_annex = annex.is_some();

    let mut ss = Vec::new();
    // Epoch
    ss.push(0x00);
    // Hash type
    ss.push(hash_type);
    // Transaction level data
    ss.extend_from_slice(&tx.version.to_le_bytes());
    ss.extend_from_slice(&tx.lock_time.to_le_bytes());
    if input_type != SIGHASH_ANYONECANPAY {
        ss.extend_from_slice(&prevouts_single_hash(tx));
        ss.extend_from_slice(&amounts_single_hash(spent_outputs));
        ss.extend_from_slice(&scripts_single_hash(spent_outputs));
        ss.extend_from_slice(&sequences_single_hash(tx));
    }
    if output_type == SIGHASH_ALL {
        ss.extend_from_slice(&outputs_single_hash(tx));
    }

    // Data about the input/prevout being spent
    let spend_type = (ext_flag << 1) + if have_annex { 1 } else { 0 };
    ss.push(spend_type);
    if input_type == SIGHASH_ANYONECANPAY {
        serialize_prevout(&mut ss, &tx.vin[n_in]);
        ss.extend_from_slice(&spent_outputs[n_in].value.to_le_bytes());
        serialize_script(&mut ss, spent_outputs[n_in].script_pubkey.as_script());
        ss.extend_from_slice(&tx.vin[n_in].sequence.0.to_le_bytes());
    } else {
        ss.extend_from_slice(&(n_in as u32).to_le_bytes());
    }
    if let Some(annex) = annex {
        // m_annex_hash = single SHA256 of (CompactSize(annex.len()) || annex), annex includes the 0x50 tag.
        let mut b = Vec::new();
        write_compact_size(&mut b, annex.len() as u64);
        b.extend_from_slice(annex);
        let annex_hash = sha256::Hash::hash(&b).to_byte_array();
        ss.extend_from_slice(&annex_hash);
    }

    // Data about the output (only for SIGHASH_SINGLE)
    if output_type == SIGHASH_SINGLE {
        if n_in >= tx.vout.len() {
            return None;
        }
        let mut b = Vec::new();
        serialize_output(&mut b, &tx.vout[n_in]);
        let out_hash = sha256::Hash::hash(&b).to_byte_array();
        ss.extend_from_slice(&out_hash);
    }

    // Additional data for BIP 342 signatures
    if let Some(ext) = ext {
        ss.extend_from_slice(&ext.tapleaf_hash);
        ss.push(0x00); // key_version (32-byte keys)
        ss.extend_from_slice(&ext.codeseparator_pos.to_le_bytes());
    }

    Some(tagged_hash(TAG_TAP_SIGNHASH, &ss))
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{TxIn, TxOut};
    use bitcoin::{OutPoint, ScriptBuf, Witness};

    fn dummy_tx() -> Tx {
        let txin = TxIn {
            prevout: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0xffff_ffff),
            witness: Witness::new(),
        };
        let vout = TxOut {
            value: 10_000_000,
            script_pubkey: ScriptBuf::new(),
        };
        Tx::new(2, vec![txin], vec![vout], 0)
    }

    #[test]
    fn key_path_sighash_is_deterministic() {
        let tx = dummy_tx();
        let spent = [TxOut { value: 50_000_000, script_pubkey: ScriptBuf::new() }];
        let h1 = signature_hash_taproot(&tx, 0, 0x00, &spent, None, None).unwrap();
        let h2 = signature_hash_taproot(&tx, 0, 0x00, &spent, None, None).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn script_path_sighash_differs_from_key_path() {
        let tx = dummy_tx();
        let spent = [TxOut { value: 50_000_000, script_pubkey: ScriptBuf::new() }];
        let ext = TapscriptExt { tapleaf_hash: [0x11u8; 32], codeseparator_pos: 0xffff_ffff };
        let key_h = signature_hash_taproot(&tx, 0, 0x00, &spent, None, None).unwrap();
        let script_h = signature_hash_taproot(&tx, 0, 0x00, &spent, Some(&ext), None).unwrap();
        assert_ne!(key_h, script_h);
    }

    #[test]
    fn invalid_hashtype_returns_none() {
        let tx = dummy_tx();
        let spent = [TxOut { value: 50_000_000, script_pubkey: ScriptBuf::new() }];
        assert!(signature_hash_taproot(&tx, 0, 0x04, &spent, None, None).is_none());
        assert!(signature_hash_taproot(&tx, 0, 0x84, &spent, None, None).is_none());
    }

    #[test]
    fn sighash_single_out_of_range_returns_none() {
        let mut tx = dummy_tx();
        tx.vout.clear();
        tx.vout.push(TxOut { value: 1, script_pubkey: ScriptBuf::new() });
        let spent = [TxOut { value: 50_000_000, script_pubkey: ScriptBuf::new() }];
        // Two inputs would need an index; build a 2-input tx to exceed vout range.
        let txin2 = TxIn {
            prevout: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0xffff_ffff),
            witness: Witness::new(),
        };
        tx.vin.push(txin2);
        assert!(signature_hash_taproot(&tx, 1, 0x03, &spent, None, None).is_none());
    }

    #[test]
    fn annex_changes_sighash() {
        let tx = dummy_tx();
        let spent = [TxOut { value: 50_000_000, script_pubkey: ScriptBuf::new() }];
        let annex = [0x50u8, 0x00];
        let h_plain = signature_hash_taproot(&tx, 0, 0x00, &spent, None, None).unwrap();
        let h_annex = signature_hash_taproot(&tx, 0, 0x00, &spent, None, Some(&annex)).unwrap();
        assert_ne!(h_plain, h_annex);
    }
}
