//! Sigop cost. Port of `GetLegacySigOpCount`, `GetP2SHSigOpCount` and
//! `GetTransactionSigOpCost` (consensus/tx_verify.cpp).

use btc_primitives::{Tx, TxOut, Witness};
use btc_script::opcodes::{get_op, OP_0, OP_1, OP_16};
use btc_script::sigops::get_sigop_count;
use btc_script::verify::is_p2sh;
use btc_script::ScriptVerifyFlags;

/// `MAX_BLOCK_SIGOPS_COST` (consensus/consensus.h).
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

const WITNESS_SCALE_FACTOR: u64 = 4;

/// `GetLegacySigOpCount`: inaccurate count over every scriptSig and scriptPubKey.
pub fn legacy_sigop_count(tx: &Tx) -> u32 {
    let in_sigs = tx
        .vin
        .iter()
        .map(|input| get_sigop_count(input.script_sig.as_bytes(), false));
    let out_keys = tx
        .vout
        .iter()
        .map(|output| get_sigop_count(output.script_pubkey.as_bytes(), false));
    in_sigs.chain(out_keys).sum()
}

/// `GetP2SHSigOpCount`. `spent[i]` is the output spent by input i. 0 for coinbase.
pub fn p2sh_sigop_count(tx: &Tx, spent: &[TxOut]) -> u32 {
    if tx.is_coin_base() {
        return 0;
    }
    assert_eq!(spent.len(), tx.vin.len(), "one spent output per input");
    tx.vin
        .iter()
        .zip(spent)
        .map(|(input, prev)| {
            p2sh_input_sigops(input.script_sig.as_bytes(), prev.script_pubkey.as_bytes())
        })
        .sum()
}

/// `GetTransactionSigOpCost`: legacy*4 + (P2SH ? p2sh*4) + witness sigops.
pub fn transaction_sigop_cost(tx: &Tx, spent: &[TxOut], flags: ScriptVerifyFlags) -> u64 {
    let mut cost = u64::from(legacy_sigop_count(tx)) * WITNESS_SCALE_FACTOR;
    if tx.is_coin_base() {
        return cost;
    }
    assert_eq!(spent.len(), tx.vin.len(), "one spent output per input");
    if flags.contains(ScriptVerifyFlags::P2SH) {
        cost += u64::from(p2sh_sigop_count(tx, spent)) * WITNESS_SCALE_FACTOR;
    }
    if flags.contains(ScriptVerifyFlags::WITNESS) {
        cost += tx
            .vin
            .iter()
            .zip(spent)
            .map(|(input, prev)| {
                u64::from(witness_sigops(
                    input.script_sig.as_bytes(),
                    prev.script_pubkey.as_bytes(),
                    &input.witness,
                ))
            })
            .sum::<u64>();
    }
    cost
}

/// `CScript::GetSigOpCount(scriptSig)` for one input.
fn p2sh_input_sigops(script_sig: &[u8], script_pubkey: &[u8]) -> u32 {
    if !is_p2sh(script_pubkey) {
        return 0;
    }
    last_push(script_sig).map_or(0, |redeem| get_sigop_count(&redeem, true))
}

/// Data of the last push in a push-only scriptSig. `None` if the script is malformed
/// or contains a non-push opcode (Core `IsPushOnly` / `GetSigOpCount` return 0 there).
fn last_push(script_sig: &[u8]) -> Option<Vec<u8>> {
    let mut pc = 0usize;
    let mut last = Vec::new();
    while pc < script_sig.len() {
        let (op, data) = get_op(script_sig, &mut pc)?;
        if op > OP_16 {
            return None;
        }
        last = data;
    }
    Some(last)
}

/// Core `CScript::IsWitnessProgram`: `OP_0`/`OP_1..OP_16`, then a direct push of 2..=40 bytes.
fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if !(4..=42).contains(&script.len()) {
        return None;
    }
    let op = script[0];
    if op != OP_0 && !(OP_1..=OP_16).contains(&op) {
        return None;
    }
    if script[1] as usize + 2 != script.len() {
        return None;
    }
    let version = if op == OP_0 { 0 } else { op - OP_1 + 1 };
    Some((version, &script[2..]))
}

/// Core `CountWitnessSigOps`, including the P2SH-wrapped witness program case.
fn witness_sigops(script_sig: &[u8], script_pubkey: &[u8], witness: &Witness) -> u32 {
    if let Some((version, program)) = witness_program(script_pubkey) {
        return witness_program_sigops(version, program, witness);
    }
    if is_p2sh(script_pubkey) {
        if let Some(redeem) = last_push(script_sig) {
            if let Some((version, program)) = witness_program(&redeem) {
                return witness_program_sigops(version, program, witness);
            }
        }
    }
    0
}

/// Core `WitnessSigOps`.
fn witness_program_sigops(version: u8, program: &[u8], witness: &Witness) -> u32 {
    if version != 0 {
        return 0;
    }
    match program.len() {
        20 => 1,
        32 => witness
            .last()
            .map_or(0, |script| get_sigop_count(script, true)),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::Hash;
    use btc_primitives::{OutPoint, ScriptBuf, TxIn, Txid};

    const PUBKEY: [u8; 33] = [0x02; 33];

    fn push(data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 0x4c);
        let mut out = vec![data.len() as u8];
        out.extend_from_slice(data);
        out
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    /// `OP_1 <pk> <pk> OP_2 OP_CHECKMULTISIGVERIFY` (2 accurate, 20 inaccurate sigops).
    fn multisig() -> Vec<u8> {
        cat(&[vec![0x51], push(&PUBKEY), push(&PUBKEY), vec![0x52, 0xaf]])
    }

    /// `OP_HASH160 <20 bytes> OP_EQUAL`. The hash value does not affect sigop counting.
    fn p2sh() -> Vec<u8> {
        cat(&[vec![0xa9, 0x14], vec![0x11; 20], vec![0x87]])
    }

    fn p2wpkh() -> Vec<u8> {
        cat(&[vec![0x00, 0x14], vec![0x22; 20]])
    }

    fn p2wsh() -> Vec<u8> {
        cat(&[vec![0x00, 0x20], vec![0x33; 32]])
    }

    fn coinbase(spk: Vec<u8>) -> Tx {
        Tx::new(
            2,
            vec![TxIn::new(OutPoint::null())],
            vec![TxOut::new(1, ScriptBuf::from_bytes(spk))],
            0,
        )
    }

    /// A non-coinbase tx spending one output with `spk`; returns the tx and its spent output.
    fn spending(spk: Vec<u8>, script_sig: Vec<u8>, witness: &[Vec<u8>]) -> (Tx, Vec<TxOut>) {
        let mut input = TxIn::new(OutPoint::new(Txid::from_byte_array([7; 32]), 0));
        input.script_sig = ScriptBuf::from_bytes(script_sig);
        input.witness = Witness::from_slice(witness);
        let tx = Tx::new(2, vec![input], vec![TxOut::new(1, ScriptBuf::new())], 0);
        (tx, vec![TxOut::new(1, ScriptBuf::from_bytes(spk))])
    }

    fn flags() -> ScriptVerifyFlags {
        ScriptVerifyFlags::WITNESS | ScriptVerifyFlags::P2SH
    }

    #[test]
    fn legacy_multisig_counts_inaccurately() {
        // Core: creationTx is a coinbase-shaped tx with 20 inaccurate sigops in its output.
        let creation = coinbase(multisig());
        assert_eq!(legacy_sigop_count(&creation), 20);
        assert_eq!(transaction_sigop_cost(&creation, &[], flags()), 20 * 4);
        // Spending scriptSig OP_0 OP_0 has no sigops.
        let (tx, spent) = spending(multisig(), vec![0x00, 0x00], &[]);
        assert_eq!(transaction_sigop_cost(&tx, &spent, flags()), 0);
    }

    #[test]
    fn multisig_nested_in_p2sh() {
        let redeem = multisig();
        let spk = p2sh();
        let script_sig = cat(&[vec![0x00, 0x00], push(&redeem)]);
        let (tx, spent) = spending(spk, script_sig, &[]);
        assert_eq!(p2sh_sigop_count(&tx, &spent), 2);
        assert_eq!(transaction_sigop_cost(&tx, &spent, flags()), 2 * 4);
        // P2SH sigops are not counted without the P2SH flag.
        assert_eq!(
            transaction_sigop_cost(&tx, &spent, ScriptVerifyFlags::NONE),
            0
        );
    }

    #[test]
    fn p2wpkh_witness_program() {
        let spk = p2wpkh();
        let (tx, spent) = spending(spk.clone(), vec![], &[vec![], vec![]]);
        assert_eq!(transaction_sigop_cost(&tx, &spent, flags()), 1);
        // No witness sigops without the WITNESS flag.
        assert_eq!(
            transaction_sigop_cost(&tx, &spent, ScriptVerifyFlags::P2SH),
            0
        );
        // Witness version != 0 costs nothing.
        let mut v1 = spk.clone();
        v1[0] = 0x51;
        let (tx1, spent1) = spending(v1, vec![], &[vec![], vec![]]);
        assert_eq!(transaction_sigop_cost(&tx1, &spent1, flags()), 0);
        // The witness of a coinbase is not counted.
        assert_eq!(transaction_sigop_cost(&coinbase(spk), &[], flags()), 0);
    }

    #[test]
    fn p2sh_wrapped_p2wpkh() {
        let inner = p2wpkh();
        let spk = p2sh();
        let (tx, spent) = spending(spk, push(&inner), &[vec![], vec![]]);
        assert_eq!(transaction_sigop_cost(&tx, &spent, flags()), 1);
    }

    #[test]
    fn p2wsh_witness_script() {
        let ws = multisig();
        let spk = p2wsh();
        let (tx, spent) = spending(spk.clone(), vec![], &[vec![], vec![], ws.clone()]);
        assert_eq!(transaction_sigop_cost(&tx, &spent, flags()), 2);
        assert_eq!(
            transaction_sigop_cost(&tx, &spent, ScriptVerifyFlags::P2SH),
            0
        );
    }

    #[test]
    fn p2sh_wrapped_p2wsh() {
        let ws = multisig();
        let inner = p2wsh();
        let spk = p2sh();
        let (tx, spent) = spending(spk, push(&inner), &[vec![], vec![], ws]);
        assert_eq!(transaction_sigop_cost(&tx, &spent, flags()), 2);
    }

    #[test]
    fn non_direct_push_is_not_a_witness_program() {
        // Core IsWitnessProgram requires a direct push length byte, not OP_PUSHDATA1.
        let mut spk = vec![0x00, 0x4c, 0x14];
        spk.extend_from_slice(&[0x22; 20]);
        let (tx, spent) = spending(spk, vec![], &[vec![], vec![]]);
        assert_eq!(transaction_sigop_cost(&tx, &spent, flags()), 0);
    }

    #[test]
    fn malformed_p2sh_script_sig_counts_zero() {
        // scriptSig pushes 0xac, then a truncated PUSHDATA (Core GetSigOpCount returns 0).
        let spk = p2sh();
        let (tx, spent) = spending(spk, vec![0x01, 0xac, 0x05, 0x01], &[]);
        assert_eq!(p2sh_sigop_count(&tx, &spent), 0);
    }
}
