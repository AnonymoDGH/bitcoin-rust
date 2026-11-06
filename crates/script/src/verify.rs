//! Top-level script verification. Port of VerifyScript, VerifyWitnessProgram, IsWitnessProgram and
//! IsPayToScriptHash in src/script/interpreter.cpp (and src/script/script.h).

use crate::context::{ExecData, NO_CODESEPARATOR, SigVersion, SignatureChecker};
use crate::error::ScriptError;
use crate::flags::ScriptVerifyFlags;
use crate::interpreter::{cast_to_bool, eval_script};
use crate::opcodes::*;
use crate::taproot::{compute_tapleaf_hash, verify_taproot_commitment};

const WITNESS_V0_KEYHASH_SIZE: usize = 20;
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
const WITNESS_V1_TAPROOT_SIZE: usize = 32;
const ANNEX_TAG: u8 = 0x50;
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
const WITNESS_MAX_PROGRAM_SIZE: usize = 40;

/// Port of IsWitnessProgram: first opcode is OP_0..OP_16, then exactly one data push of 2..40 bytes.
pub fn is_witness_program(script: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut pc = 0usize;
    let (op, _d) = get_op(script, &mut pc)?;
    let version = match op {
        OP_0 => 0u8,
        OP_1..=OP_16 => op - 0x50,
        _ => return None,
    };
    let (op2, program) = get_op(script, &mut pc)?;
    if pc != script.len() {
        return None;
    }
    // The program must be a single push of 2..40 bytes.
    if op2 > OP_PUSHDATA4 {
        return None;
    }
    if !(2..=WITNESS_MAX_PROGRAM_SIZE).contains(&program.len()) {
        return None;
    }
    Some((version, program))
}

/// Port of IsPayToScriptHash: OP_HASH160 <push 20> OP_EQUAL.
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == OP_HASH160
        && script[1] == 0x14
        && script[22] == OP_EQUAL
}

fn is_p2wpkh_program(version: u8, program: &[u8]) -> bool {
    version == 0 && program.len() == WITNESS_V0_KEYHASH_SIZE
}

fn is_p2wsh_program(version: u8, program: &[u8]) -> bool {
    version == 0 && program.len() == WITNESS_V0_SCRIPTHASH_SIZE
}

fn is_taproot_program(version: u8, program: &[u8]) -> bool {
    version == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE
}

fn p2pkh_script(program: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.push(OP_DUP);
    s.push(OP_HASH160);
    s.push(0x14);
    s.extend_from_slice(program);
    s.push(OP_EQUALVERIFY);
    s.push(OP_CHECKSIG);
    s
}

fn encode_push(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 5);
    match data.len() {
        0 => v.push(OP_0),
        1..=75 => {
            v.push(data.len() as u8);
            v.extend_from_slice(data);
        }
        76..=255 => {
            v.push(OP_PUSHDATA1);
            v.push(data.len() as u8);
            v.extend_from_slice(data);
        }
        256..=65535 => {
            v.push(OP_PUSHDATA2);
            v.extend_from_slice(&(data.len() as u16).to_le_bytes());
            v.extend_from_slice(data);
        }
        _ => {
            v.push(OP_PUSHDATA4);
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(data);
        }
    }
    v
}

fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0usize;
    while let Some((op, _)) = get_op(script, &mut pc) {
        if op > OP_16 {
            return false;
        }
    }
    true
}

fn witness_size(witness: &[Vec<u8>]) -> usize {
    let mut size = compact_size_len(witness.len() as u64);
    for item in witness {
        size += compact_size_len(item.len() as u64) + item.len();
    }
    size
}

fn compact_size_len(n: u64) -> usize {
    if n < 253 {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Port of VerifyWitnessProgram. `witness` borrows the full witness stack; `is_p2sh` signals
/// execution inside a P2SH-wrapped witness.
fn verify_witness_program(
    witness: &[Vec<u8>],
    version: u8,
    program: &[u8],
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
    is_p2sh: bool,
) -> Result<(), ScriptError> {
    let mut stack: Vec<Vec<u8>> = witness.to_vec();
    let mut exec_data = ExecData::new();

    if version == 0 {
        if is_p2wsh_program(version, program) {
            if stack.is_empty() {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            }
            let script_bytes = stack.pop().expect("non-empty witness");
            let exec_script = script_bytes.clone();
            use bitcoin_hashes::{sha256, Hash};
            let hash = sha256::Hash::hash(&exec_script).to_byte_array();
            if hash != program {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            return execute_witness_script(
                &mut stack,
                &exec_script,
                flags,
                SigVersion::WitnessV0,
                checker,
                &mut exec_data,
            );
        } else if is_p2wpkh_program(version, program) {
            if stack.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            let exec_script = p2pkh_script(program);
            return execute_witness_script(
                &mut stack,
                &exec_script,
                flags,
                SigVersion::WitnessV0,
                checker,
                &mut exec_data,
            );
        } else {
            return Err(ScriptError::WitnessProgramWrongLength);
        }
    } else if is_taproot_program(version, program) && !is_p2sh {
        if !flags.contains(ScriptVerifyFlags::TAPROOT) {
            return Ok(()); // v1 treated as future witness program, valid
        }
        if stack.is_empty() {
            return Err(ScriptError::WitnessProgramWitnessEmpty);
        }
        // Annex: last element of a taproot witness starting with 0x50.
        if stack.len() >= 2 && !stack.last().unwrap().is_empty() && stack.last().unwrap()[0] == ANNEX_TAG {
            let annex = stack.pop().expect("annex present");
            exec_data.annex = Some(annex);
        }
        if stack.len() == 1 {
            // Key path spending.
            let ok = checker.check_schnorr_signature(
                &stack[0],
                program,
                SigVersion::Taproot,
                &exec_data,
            );
            if !ok {
                return Err(ScriptError::SchnorrSig);
            }
            return Ok(());
        }
        // Script path spending.
        let control = stack.pop().expect("control present");
        let script = stack.pop().expect("script present");
        if control.len() < TAPROOT_CONTROL_BASE_SIZE
            || control.len() > TAPROOT_CONTROL_MAX_SIZE
            || (control.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        let leaf_version = control[0] & TAPROOT_LEAF_MASK;
        let tapleaf_hash = compute_tapleaf_hash(leaf_version, &script);
        exec_data.tapleaf_hash = Some(tapleaf_hash);
        exec_data.codeseparator_pos = NO_CODESEPARATOR;
        if !verify_taproot_commitment(&control, program, tapleaf_hash) {
            return Err(ScriptError::WitnessProgramMismatch);
        }
        if leaf_version == TAPROOT_LEAF_TAPSCRIPT {
            exec_data.validation_weight_left =
                Some(witness_size(witness) as i64 + VALIDATION_WEIGHT_OFFSET);
            return execute_witness_script(
                &mut stack,
                &script,
                flags,
                SigVersion::Tapscript,
                checker,
                &mut exec_data,
            );
        }
        if flags.contains(ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) {
            return Err(ScriptError::DiscourageUpgradableTaprootVersion);
        }
        return Ok(()); // unknown leaf version: future softfork, valid
    } else if !is_p2sh && is_pay_to_anchor(version, program) {
        return Ok(()); // P2A: anchor output, future softfork
    } else {
        if flags.contains(ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return Err(ScriptError::DiscourageUpgradableWitnessProgram);
        }
        return Ok(()); // future softfork: valid
    }
}

fn is_pay_to_anchor(version: u8, program: &[u8]) -> bool {
    // BIP 231 / P2A: OP_1 <0x4e73> (34-byte? no, 2-byte program) — see Bitcoin Core IsPayToAnchor.
    version == 1 && program == [0x4e, 0x73]
}

/// Port of ExecuteWitnessScript.
fn execute_witness_script(
    stack: &mut Vec<Vec<u8>>,
    exec_script: &[u8],
    flags: ScriptVerifyFlags,
    sigversion: SigVersion,
    checker: &dyn SignatureChecker,
    exec_data: &mut ExecData,
) -> Result<(), ScriptError> {
    eval_script(stack, exec_script, flags, checker, sigversion, exec_data)?;
    if stack.len() != 1 {
        return Err(ScriptError::Cleanstack);
    }
    if !cast_to_bool(&stack[0]) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}

/// Port of VerifyScript (P2SH, SegWit v0 and Taproot paths).
pub fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    let mut had_witness = false;

    // SIGPUSHONLY applies to the scriptSig argument when the flag is set.
    if flags.contains(ScriptVerifyFlags::SIGPUSHONLY) && !is_push_only(script_sig) {
        return Err(ScriptError::SigPushonly);
    }

    let mut exec_data = ExecData::new();
    let mut stack: Vec<Vec<u8>> = Vec::new();
    eval_script(
        &mut stack,
        script_sig,
        flags,
        checker,
        SigVersion::Base,
        &mut exec_data,
    )?;
    let stack_copy = if flags.contains(ScriptVerifyFlags::P2SH) {
        Some(stack.clone())
    } else {
        None
    };

    exec_data.codeseparator_pos = NO_CODESEPARATOR;
    eval_script(
        &mut stack,
        script_pubkey,
        flags,
        checker,
        SigVersion::Base,
        &mut exec_data,
    )?;

    if stack.is_empty() {
        return Err(ScriptError::EvalFalse);
    }
    if !cast_to_bool(stack.last().expect("non-empty stack")) {
        return Err(ScriptError::EvalFalse);
    }

    // Bare witness program (witness v0 / v1 directly in the output script).
    if flags.contains(ScriptVerifyFlags::WITNESS) {
        if let Some((version, program)) = is_witness_program(script_pubkey) {
            had_witness = true;
            if !script_sig.is_empty() {
                // The scriptSig must be exactly empty, otherwise malleability.
                return Err(ScriptError::WitnessMalleated);
            }
            verify_witness_program(witness, version, &program, flags, checker, false)?;
            // Bypass the final CLEANSTACK check for witness programs.
            stack.truncate(1);
        }
    }

    // Additional validation for P2SH transactions.
    if flags.contains(ScriptVerifyFlags::P2SH) && is_p2sh(script_pubkey) {
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushonly);
        }

        // Restore stack.
        stack = stack_copy.expect("P2SH script evaluated for scriptSig");
        if stack.is_empty() {
            return Err(ScriptError::EvalFalse);
        }
        let pub_key_serialized = stack.pop().expect("non-empty stack");
        let pubkey2 = pub_key_serialized.clone();
        exec_data.codeseparator_pos = NO_CODESEPARATOR;
        eval_script(
            &mut stack,
            &pubkey2,
            flags,
            checker,
            SigVersion::Base,
            &mut exec_data,
        )?;
        if stack.is_empty() {
            return Err(ScriptError::EvalFalse);
        }
        if !cast_to_bool(stack.last().expect("non-empty stack")) {
            return Err(ScriptError::EvalFalse);
        }

        // P2SH-wrapped witness program.
        if flags.contains(ScriptVerifyFlags::WITNESS) {
            if let Some((version, program)) = is_witness_program(&pubkey2) {
                had_witness = true;
                if script_sig != encode_push(&pubkey2) {
                    // scriptSig must be exactly a single push of the redeemScript.
                    return Err(ScriptError::WitnessMalleatedP2sh);
                }
                verify_witness_program(witness, version, &program, flags, checker, true)?;
                stack.truncate(1);
            }
        }
    }

    // CLEANSTACK: only meaningful with P2SH/WITNESS enabled, as asserts elsewhere.
    if flags.contains(ScriptVerifyFlags::CLEANSTACK) && stack.len() != 1 {
        return Err(ScriptError::Cleanstack);
    }

    // Unexpected witness data.
    if flags.contains(ScriptVerifyFlags::WITNESS) && !had_witness && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }

    Ok(())
}
