//! Signature operation counting. Port of CScript::GetSigOpCount, GetP2SHSigOpCount and
//! CountWitnessSigOps in src/script/script.h, src/script/script.cpp and src/script/interpreter.cpp.

use crate::flags::ScriptVerifyFlags;
use crate::opcodes::*;

/// Port of GetSigOpCount. With `accurate`, a CHECKMULTISIG immediately preceded by
/// OP_1..OP_16 counts that many pubkeys; otherwise MAX_PUBKEYS_PER_MULTISIG.
pub fn get_sigop_count(script: &[u8], accurate: bool) -> u32 {
    let mut count = 0u32;
    let mut pc = 0usize;
    let mut last_opcode: u8 = 0xff;
    while let Some((op, _data)) = get_op(script, &mut pc) {
        match op {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => count += 1,
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                if accurate && (OP_1..=OP_16).contains(&last_opcode) {
                    count += (last_opcode - OP_1 + 1) as u32;
                } else {
                    count += MAX_PUBKEYS_PER_MULTISIG as u32;
                }
            }
            _ => {}
        }
        last_opcode = op;
    }
    count
}

fn is_p2sh(script: &[u8]) -> bool {
    // OP_HASH160 <push 20> OP_EQUAL
    script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL
}

fn is_witness_program(script: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut pc = 0usize;
    let (op, data) = get_op(script, &mut pc)?;
    let version = match op {
        OP_0 => 0u8,
        OP_1..=OP_16 => op - 0x50,
        _ => return None,
    };
    let _ = data;
    let (op2, program) = get_op(script, &mut pc)?;
    if pc != script.len() {
        return None;
    }
    // The program must be a single push (data-carrying opcode).
    if op2 > OP_PUSHDATA4 {
        return None;
    }
    if program.len() < 2 || program.len() > 40 {
        return None;
    }
    Some((version, program))
}

/// Port of GetP2SHSigOpCount. Precise counting of signature ops inside the redeemScript.
pub fn get_p2sh_sigop_count(script_sig: &[u8], script_pubkey: &[u8]) -> u32 {
    if !is_p2sh(script_pubkey) {
        return 0;
    }
    // scriptSig must be push-only; the redeemScript is the last push.
    let mut pc = 0usize;
    let mut last_push: Option<Vec<u8>> = None;
    while let Some((op, data)) = get_op(script_sig, &mut pc) {
        if op > OP_16 {
            return 0; // not push-only
        }
        last_push = Some(data);
    }
    let redeem = match last_push {
        Some(r) if !r.is_empty() => r,
        _ => return 0,
    };
    get_sigop_count(&redeem, true)
}

/// Port of CountWitnessSigOps (simplified: no accurate multi-counting inside nested P2SH).
pub fn count_witness_sigops(
    _script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: ScriptVerifyFlags,
) -> u32 {
    if !flags.contains(ScriptVerifyFlags::WITNESS) {
        return 0;
    }
    let (version, program) = match is_witness_program(script_pubkey) {
        Some(v) => v,
        None => return 0,
    };
    match version {
        0 => {
            if program.len() == 20 {
                1 // P2WPKH: exactly one signature op
            } else if program.len() == 32 {
                // P2WSH: count the ops in the witnessScript (last witness element).
                match witness.last() {
                    Some(ws) => get_sigop_count(ws, true),
                    None => 0,
                }
            } else {
                0
            }
        }
        _ => 0, // Taproot and future versions count as 0 sigops here
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigops_counts() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG -> 1 sigop.
        let mut pk = vec![0x76, 0xa9, 0x14];
        pk.extend_from_slice(&[0u8; 20]);
        pk.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(get_sigop_count(&pk, true), 1);
        // 2-of-3 bare multisig: OP_2 <keys> OP_2 OP_CHECKMULTISIG -> 2 accurate, 20 inaccurate.
        let s = vec![0x52, 0x53, 0x52, OP_CHECKMULTISIG];
        assert_eq!(get_sigop_count(&s, true), 2);
        assert_eq!(get_sigop_count(&s, false), 20);
    }

    #[test]
    fn p2sh_sigop_count_uses_redeem() {
        // redeemScript: <SIG> OP_CHECKSIG (1 sigop) wrapped in P2SH.
        let redeem = vec![0x51, OP_CHECKSIG];
        let mut script_sig = vec![redeem.len() as u8];
        script_sig.extend_from_slice(&redeem);
        // script_pubkey: OP_HASH160 <20B> OP_EQUAL
        let mut script_pubkey = vec![OP_HASH160, 0x14];
        script_pubkey.extend_from_slice(&[0u8; 20]);
        script_pubkey.push(OP_EQUAL);
        assert_eq!(get_p2sh_sigop_count(&script_sig, &script_pubkey), 1);
        assert_eq!(get_p2sh_sigop_count(&[0x51], &script_pubkey), 0);
    }
}
