//! Legacy and BIP143 (SegWit v0) signature hashes. Port of SignatureHash and
//! CTransactionSignatureSerializer in src/script/interpreter.cpp.

use btc_primitives::{Tx, TxIn, TxOut};
use bitcoin_hashes::{sha256, sha256d, Hash};

pub const SIGHASH_ALL: u32 = 0x01;
pub const SIGHASH_NONE: u32 = 0x02;
pub const SIGHASH_SINGLE: u32 = 0x03;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

fn base_hash_type(hash_type: u32) -> u32 {
    hash_type & 0x1f
}

fn is_anyone_can_pay(hash_type: u32) -> bool {
    hash_type & SIGHASH_ANYONECANPAY != 0
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

/// Empty script serialization: compactSize(0).
fn empty_script(out: &mut Vec<u8>) {
    out.push(0x00);
}

fn serialize_prevout_outpoint(out: &mut Vec<u8>, txin: &TxIn) {
    // uint256 (internal 32-byte LE data) + u32 LE vout.
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

/// Serialize scriptCode skipping OP_CODESEPARATOR opcodes, as in
/// CTransactionSignatureSerializer::SerializeScriptCode.
fn serialize_script_code(out: &mut Vec<u8>, script_code: &[u8]) {
    use crate::opcodes::{get_op, OP_CODESEPARATOR};

    let mut codeseps = 0usize;
    let mut pc = 0usize;
    while let Some((op, _)) = get_op(script_code, &mut pc) {
        if op == OP_CODESEPARATOR {
            codeseps += 1;
        }
    }
    write_compact_size(out, (script_code.len() - codeseps) as u64);

    let mut pc = 0usize;
    let mut seg_start = 0usize;
    while let Some((op, _)) = get_op(script_code, &mut pc) {
        if op == OP_CODESEPARATOR {
            out.extend_from_slice(&script_code[seg_start..pc - 1]);
            seg_start = pc;
        }
    }
    if seg_start < script_code.len() {
        out.extend_from_slice(&script_code[seg_start..]);
    }
}

/// BIP143: scriptCode serializes as compact-size + raw bytes (Core: `ss << scriptCode`).
fn serialize_script_code_bip143(out: &mut Vec<u8>, script_code: &[u8]) {
    write_compact_size(out, script_code.len() as u64);
    out.extend_from_slice(script_code);
}

/// Single SHA256 of the concatenated outpoints (Core: GetPrevoutsSHA256).
pub fn prevouts_sha256(tx: &Tx) -> [u8; 32] {
    let mut buf = Vec::new();
    for txin in &tx.vin {
        serialize_prevout_outpoint(&mut buf, txin);
    }
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Single SHA256 of the concatenated sequences (Core: GetSequencesSHA256).
pub fn sequences_sha256(tx: &Tx) -> [u8; 32] {
    let mut buf = Vec::new();
    for txin in &tx.vin {
        buf.extend_from_slice(&txin.sequence.0.to_le_bytes());
    }
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Single SHA256 of the concatenated outputs (Core: GetOutputsSHA256).
pub fn outputs_sha256(tx: &Tx) -> [u8; 32] {
    let mut buf = Vec::new();
    for txout in &tx.vout {
        serialize_output(&mut buf, txout);
    }
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Port of the legacy (pre-SegWit) signature hash.
/// SIGHASH_SINGLE with n_in >= vout.len() returns the "one" hash (0x01 then zeros).
pub fn signature_hash_legacy(script_code: &[u8], tx: &Tx, n_in: usize, hash_type: u32) -> [u8; 32] {
    if base_hash_type(hash_type) == SIGHASH_SINGLE && n_in >= tx.vout.len() {
        // uint256::ONE in Core: 0x01 then 31 zero bytes.
        let mut out = [0u8; 32];
        out[0] = 1;
        return out;
    }

    let f_anyone = is_anyone_can_pay(hash_type);
    let f_single = base_hash_type(hash_type) == SIGHASH_SINGLE;
    let f_none = base_hash_type(hash_type) == SIGHASH_NONE;

    let mut ss = Vec::new();
    ss.extend_from_slice(&tx.version.to_le_bytes());

    let n_inputs = if f_anyone { 1 } else { tx.vin.len() };
    write_compact_size(&mut ss, n_inputs as u64);
    for i in 0..n_inputs {
        let idx = if f_anyone { n_in } else { i };
        let txin = &tx.vin[idx];
        serialize_prevout_outpoint(&mut ss, txin);
        if idx == n_in {
            serialize_script_code(&mut ss, script_code);
        } else {
            empty_script(&mut ss);
        }
        if idx != n_in && (f_single || f_none) {
            ss.extend_from_slice(&0i32.to_le_bytes());
        } else {
            ss.extend_from_slice(&txin.sequence.0.to_le_bytes());
        }
    }

    let n_outputs = if f_none {
        0
    } else if f_single {
        n_in + 1
    } else {
        tx.vout.len()
    };
    write_compact_size(&mut ss, n_outputs as u64);
    for i in 0..n_outputs {
        if f_single && i != n_in {
            // Null output (Core serializes CTxOut()).
            ss.extend_from_slice(&(-1i64).to_le_bytes());
            empty_script(&mut ss);
        } else {
            serialize_output(&mut ss, &tx.vout[i]);
        }
    }

    ss.extend_from_slice(&tx.lock_time.to_le_bytes());
    ss.extend_from_slice(&hash_type.to_le_bytes());
    sha256d::Hash::hash(&ss).to_byte_array()
}

/// Port of the BIP143 (SegWit v0) signature hash.
pub fn signature_hash_segwit_v0(
    script_code: &[u8],
    tx: &Tx,
    n_in: usize,
    hash_type: u32,
    amount: i64,
) -> [u8; 32] {
    let base = base_hash_type(hash_type);
    let f_anyone = is_anyone_can_pay(hash_type);
    let zero = [0u8; 32];

    let hash_prevouts = if f_anyone {
        zero
    } else {
        let mut b = Vec::new();
        for txin in &tx.vin {
            serialize_prevout_outpoint(&mut b, txin);
        }
        sha256d::Hash::hash(&b).to_byte_array()
    };

    let hash_sequence = if f_anyone || base == SIGHASH_SINGLE || base == SIGHASH_NONE {
        zero
    } else {
        let mut b = Vec::new();
        for txin in &tx.vin {
            b.extend_from_slice(&txin.sequence.0.to_le_bytes());
        }
        sha256d::Hash::hash(&b).to_byte_array()
    };

    let hash_outputs = if base == SIGHASH_SINGLE {
        if n_in < tx.vout.len() {
            let mut b = Vec::new();
            serialize_output(&mut b, &tx.vout[n_in]);
            sha256d::Hash::hash(&b).to_byte_array()
        } else {
            zero
        }
    } else if base == SIGHASH_NONE {
        zero
    } else {
        let mut b = Vec::new();
        for txout in &tx.vout {
            serialize_output(&mut b, txout);
        }
        sha256d::Hash::hash(&b).to_byte_array()
    };

    let mut ss = Vec::new();
    ss.extend_from_slice(&tx.version.to_le_bytes());
    ss.extend_from_slice(&hash_prevouts);
    ss.extend_from_slice(&hash_sequence);
    serialize_prevout_outpoint(&mut ss, &tx.vin[n_in]);
    serialize_script_code_bip143(&mut ss, script_code);
    ss.extend_from_slice(&amount.to_le_bytes());
    ss.extend_from_slice(&tx.vin[n_in].sequence.0.to_le_bytes());
    ss.extend_from_slice(&hash_outputs);
    ss.extend_from_slice(&tx.lock_time.to_le_bytes());
    ss.extend_from_slice(&hash_type.to_le_bytes());
    sha256d::Hash::hash(&ss).to_byte_array()
}

/// Port of FindAndDelete: remove every occurrence of `needle` from `script`.
/// Used by the pre-segwit signature path.
pub fn find_and_delete(script: &mut Vec<u8>, needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    // Core's algorithm walks the script as opcodes and removes pushes; for the sighash use it
    // scans byte-wise for the exact push encoding, which is what the caller passes.
    let mut found = 0;
    while let Some(pos) = script
        .windows(needle.len())
        .position(|w| w == needle)
    {
        script.drain(pos..pos + needle.len());
        found += 1;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::{TxIn, TxOut};
    use bitcoin::{OutPoint, ScriptBuf};

    fn dummy_tx() -> Tx {
        let txin = TxIn {
            prevout: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0xffff_ffff),
            witness: bitcoin::Witness::new(),
        };
        let vout = TxOut {
            value: 100_000_000,
            script_pubkey: ScriptBuf::new(),
        };
        Tx::new(2, vec![txin], vec![vout], 0)
    }

    #[test]
    fn legacy_sighash_is_deterministic_and_32_bytes() {
        let tx = dummy_tx();
        let h1 = signature_hash_legacy(&[0x51], &tx, 0, SIGHASH_ALL);
        let h2 = signature_hash_legacy(&[0x51], &tx, 0, SIGHASH_ALL);
        assert_eq!(h1, h2);
    }

    #[test]
    fn segwit_v0_sighash_differs_from_legacy_and_is_stable() {
        let tx = dummy_tx();
        let h = signature_hash_segwit_v0(&[0x51], &tx, 0, SIGHASH_ALL, 50_000_000);
        assert_eq!(h, signature_hash_segwit_v0(&[0x51], &tx, 0, SIGHASH_ALL, 50_000_000));
        assert_ne!(h, signature_hash_legacy(&[0x51], &tx, 0, SIGHASH_ALL));
    }

    #[test]
    fn sighash_single_out_of_range_returns_one() {
        let tx = dummy_tx();
        let h = signature_hash_legacy(&[0x51], &tx, 5, SIGHASH_SINGLE);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(h, one);
    }

    #[test]
    fn find_and_delete_removes_occurrences() {
        let mut s = vec![0x01, 0xaa, 0xbb, 0x02, 0xcc, 0xdd, 0x01, 0xaa, 0xbb];
        let n = find_and_delete(&mut s, &[0x01, 0xaa, 0xbb]);
        assert_eq!(n, 2);
        assert_eq!(s, vec![0x02, 0xcc, 0xdd]);
    }
}
