//! Script interpreter. Port of EvalScript in src/script/interpreter.cpp.

use crate::context::{ExecData, NO_CODESEPARATOR, SigVersion, SignatureChecker};
use crate::error::ScriptError;
use crate::flags::ScriptVerifyFlags;
use crate::opcodes::*;
use crate::script_num::ScriptNum;
use bitcoin_hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash};

use crate::script_num::DEFAULT_MAX_NUM_SIZE;
const MAX_NUM_SIZE: usize = DEFAULT_MAX_NUM_SIZE;
const LARGE_NUM_SIZE: usize = 5; // CLTV/CSV special case (year-2038 workaround)

pub(crate) fn cast_to_bool(v: &[u8]) -> bool {
    for (i, b) in v.iter().enumerate() {
        if *b != 0 {
            if i == v.len() - 1 && *b == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

fn is_minimal_push(data: &[u8], opcode: u8) -> bool {
    // Core's CheckMinimalPush: OP_1NEGATE and OP_1..OP_16 are always minimal.
    if opcode == OP_1NEGATE || (OP_1..=OP_16).contains(&opcode) {
        return true;
    }
    match data.len() {
        0 => opcode == OP_0,
        // 1-byte data in 1..=16 must have been pushed as OP_1..OP_16.
        1 if (1..=16).contains(&data[0]) => opcode == OP_1 + (data[0] - 1),
        // 0x81 must have been pushed as OP_1NEGATE.
        1 if data[0] == 0x81 => opcode == OP_1NEGATE,
        1..=75 => opcode as usize == data.len(),
        76..=255 => opcode == OP_PUSHDATA1,
        256..=65535 => opcode == OP_PUSHDATA2,
        _ => opcode == OP_PUSHDATA4,
    }
}

fn push_number(stack: &mut Vec<Vec<u8>>, v: i64) {
    stack.push(ScriptNum::encode(v));
}

fn pop_number(
    stack: &mut Vec<Vec<u8>>,
    require_minimal: bool,
    max_len: usize,
) -> Result<ScriptNum, ScriptError> {
    let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
    ScriptNum::from_bytes(&top, require_minimal, max_len)
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

/// Remove every exact-byte occurrence of `needle` from `script`.
/// Core walks opcodes and removes pushes; scanning bytewise is equivalent for signature payloads.
fn find_and_delete(script: &[u8], needle: &[u8]) -> (Vec<u8>, usize) {
    if needle.is_empty() {
        return (script.to_vec(), 0);
    }
    let mut found = 0;
    let mut i = 0;
    let mut out = Vec::with_capacity(script.len());
    while i < script.len() {
        if script[i..].starts_with(needle) {
            i += needle.len();
            found += 1;
        } else {
            out.push(script[i]);
            i += 1;
        }
    }
    (out, found)
}

pub(crate) struct IfStack {
    stack: Vec<bool>,
}

impl IfStack {
    fn new() -> Self { Self { stack: Vec::new() } }
    fn all_true(&self) -> bool { self.stack.iter().all(|b| *b) }
    fn push(&mut self, v: bool) { self.stack.push(v); }
    fn pop(&mut self) -> Result<(), ScriptError> {
        self.stack.pop().ok_or(ScriptError::UnbalancedConditional)?;
        Ok(())
    }
    fn toggle_top(&mut self) -> Result<(), ScriptError> {
        let last = self.stack.last_mut().ok_or(ScriptError::UnbalancedConditional)?;
        *last = !*last;
        Ok(())
    }
    fn empty(&self) -> bool { self.stack.is_empty() }
}

fn check_sig_pre_tapscript(
    stack: &mut Vec<Vec<u8>>,
    script: &[u8],
    code_start: usize,
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
) -> Result<bool, ScriptError> {
    // Core: vchSig = stacktop(-2), vchPubKey = stacktop(-1); pubkey on top.
    let pubkey = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
    let sig = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;

    let mut script_code: &[u8] = &script[code_start..];
    let mut owned: Option<Vec<u8>> = None;
    if sigversion == SigVersion::Base && !sig.is_empty() {
        let sig_push = encode_push(&sig);
        let (cleaned, found) = find_and_delete(script_code, &sig_push);
        if found > 0 && flags.contains(ScriptVerifyFlags::CONST_SCRIPTCODE) {
            return Err(ScriptError::SigFindanddelete);
        }
        owned = Some(cleaned);
        script_code = owned.as_deref().unwrap();
    }

    crate::sig_encoding::check_signature_encoding(&sig, flags)?;
    crate::sig_encoding::check_pubkey_encoding(&pubkey, flags, sigversion)?;
    let ok = checker.check_ecdsa_signature(&sig, &pubkey, script_code, sigversion);
    if !ok && flags.contains(ScriptVerifyFlags::NULLFAIL) && !sig.is_empty() {
        return Err(ScriptError::SigNullfail);
    }
    Ok(ok)
}

fn check_sig_tapscript(
    stack: &mut Vec<Vec<u8>>,
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
    exec_data: &mut ExecData,
) -> Result<bool, ScriptError> {
    // Core: sig = stacktop(-2), pubkey = stacktop(-1).
    let pubkey = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
    let sig = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;

    let success = !sig.is_empty();
    if success {
        if let Some(left) = exec_data.validation_weight_left.as_mut() {
            *left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            if *left < 0 {
                return Err(ScriptError::TapscriptValidationWeight);
            }
        }
    }
    if pubkey.is_empty() {
        return Err(ScriptError::TapscriptEmptyPubkey);
    } else if pubkey.len() == 32 {
        if success && !checker.check_schnorr_signature(&sig, &pubkey, sigversion, exec_data) {
            return Err(ScriptError::SchnorrSig);
        }
    } else if flags.contains(ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE) {
        return Err(ScriptError::DiscourageUpgradablePubkeytype);
    }
    Ok(success)
}

fn multisig_verify_operands(
    stack: &mut Vec<Vec<u8>>,
    script: &[u8],
    code_start: usize,
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
    op_count: &mut i64,
) -> Result<bool, ScriptError> {
    let n_num = pop_number(stack, flags.contains(ScriptVerifyFlags::MINIMALDATA), MAX_NUM_SIZE)?;
    let n = n_num.value();
    if n < 0 || n > MAX_PUBKEYS_PER_MULTISIG as i64 {
        return Err(ScriptError::PubkeyCount);
    }
    // Core: nOpCount += nKeysCount; op count limit applies to CHECKMULTISIG too.
    *op_count += n;
    if *op_count > MAX_OPS_PER_SCRIPT as i64 {
        return Err(ScriptError::OpCount);
    }
    if stack.len() < n as usize {
        return Err(ScriptError::InvalidStackOperation);
    }
    // Core reads operands from the top of the stack downward (stacktop(-i)); collect in that order.
    let pubkeys: Vec<Vec<u8>> = stack.drain(stack.len() - n as usize..).rev().collect();

    let m_num = pop_number(stack, flags.contains(ScriptVerifyFlags::MINIMALDATA), MAX_NUM_SIZE)?;
    let m = m_num.value();
    if m < 0 || m > n {
        return Err(ScriptError::SigCount);
    }
    if stack.len() < m as usize {
        return Err(ScriptError::InvalidStackOperation);
    }
    let sigs: Vec<Vec<u8>> = stack.drain(stack.len() - m as usize..).rev().collect();

    // Core drops the dummy argument as part of the argument cleanup; NULLDUMMY checks it here.
    let dummy = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
    let null_dummy = dummy.is_empty() || (dummy.len() == 1 && dummy[0] == 0);
    if flags.contains(ScriptVerifyFlags::NULLDUMMY) && !null_dummy {
        return Err(ScriptError::SigNulldummy);
    }

    // Pre-segwit: drop the signatures from a copy of the scriptCode for every sig.
    let mut script_code = script[code_start..].to_vec();
    if sigversion == SigVersion::Base {
        for sig in &sigs {
            if sig.is_empty() {
                continue;
            }
            let sig_push = encode_push(sig);
            let (cleaned, found) = find_and_delete(&script_code, &sig_push);
            if found > 0 && flags.contains(ScriptVerifyFlags::CONST_SCRIPTCODE) {
                return Err(ScriptError::SigFindanddelete);
            }
            script_code = cleaned;
        }
    }

    let mut i = 0usize; // index into sigs (consumed)
    let mut pubkey_i = 0usize; // index into pubkeys (consumed)
    while i < m as usize && pubkey_i < n as usize {
        let sig = &sigs[i];
        let pubkey = &pubkeys[pubkey_i];
        // Encoding is checked for every attempted pair; order matters (Script_InValid tests).
        crate::sig_encoding::check_signature_encoding(sig, flags)?;
        crate::sig_encoding::check_pubkey_encoding(pubkey, flags, sigversion)?;
        let ok = checker.check_ecdsa_signature(sig, pubkey, &script_code, sigversion);
        if ok {
            i += 1;
        }
        pubkey_i += 1;
        // More signatures left than keys left: fail early without further checks.
        if (m as usize - i) > (n as usize - pubkey_i) {
            break;
        }
    }
    let success = i == m as usize;
    if !success && flags.contains(ScriptVerifyFlags::NULLFAIL) {
        // If the multisig failed, all signatures in it must be empty.
        for sig in &sigs {
            if !sig.is_empty() {
                return Err(ScriptError::SigNullfail);
            }
        }
    }
    Ok(success)
}

pub fn eval_script(
    stack: &mut Vec<Vec<u8>>,
    script: &[u8],
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
    exec_data: &mut ExecData,
) -> Result<(), ScriptError> {
    if (sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0) && script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }
    let require_minimal = flags.contains(ScriptVerifyFlags::MINIMALDATA);
    let mut f_exec = IfStack::new();
    let mut op_count: i64 = 0;
    let mut opcode_pos: u32 = 0;
    let mut code_start = 0usize;
    exec_data.codeseparator_pos = NO_CODESEPARATOR;
    let mut altstack: Vec<Vec<u8>> = Vec::new();

    let mut pc = 0usize;
    while pc < script.len() {
        let (opcode, push_bytes) = get_op(script, &mut pc).ok_or(ScriptError::BadOpcode)?;
        if push_bytes.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        if sigversion == SigVersion::Base || sigversion == SigVersion::WitnessV0 {
            if opcode > OP_16 {
                op_count += 1;
                if op_count > MAX_OPS_PER_SCRIPT as i64 {
                    return Err(ScriptError::OpCount);
                }
            }
        }

        // Disabled opcodes.
        match opcode {
            OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR | OP_2MUL
            | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                return Err(ScriptError::DisabledOpcode);
            }
            _ => {}
        }

        // CONST_SCRIPTCODE applies even to unexecuted branches.
        if opcode == OP_CODESEPARATOR && sigversion == SigVersion::Base
            && flags.contains(ScriptVerifyFlags::CONST_SCRIPTCODE)
        {
            return Err(ScriptError::OpCodeseparator);
        }

        let f_exec_branch = f_exec.all_true();

        // Tapscript: executing an OP_SUCCESSx opcode succeeds unconditionally.
        if f_exec_branch && sigversion == SigVersion::Tapscript && is_op_success(opcode) {
            if flags.contains(ScriptVerifyFlags::DISCOURAGE_OP_SUCCESS) {
                return Err(ScriptError::DiscourageOpSuccess);
            }
            return Ok(());
        }

        if f_exec_branch && opcode <= OP_PUSHDATA4 {
            if require_minimal && !is_minimal_push(&push_bytes, opcode) {
                return Err(ScriptError::Minimaldata);
            }
            stack.push(push_bytes);
            if stack.len() + altstack.len() > MAX_STACK_SIZE {
                return Err(ScriptError::StackSize);
            }
            opcode_pos += 1;
            continue;
        }

        if !f_exec_branch {
            if opcode >= OP_IF && opcode <= OP_ENDIF {
                match opcode {
                    OP_IF | OP_NOTIF => {
                        f_exec.push(false);
                    }
                    OP_ELSE => {
                        if f_exec.empty() {
                            return Err(ScriptError::UnbalancedConditional);
                        }
                        f_exec.toggle_top()?;
                    }
                    OP_ENDIF => {
                        if f_exec.empty() {
                            return Err(ScriptError::UnbalancedConditional);
                        }
                        f_exec.pop()?;
                    }
                    // Verif/Vernotif: illegal everywhere.
                    _ => return Err(ScriptError::BadOpcode),
                }
            }
            opcode_pos += 1;
            continue;
        }

        match opcode {
            OP_1NEGATE => push_number(stack, -1),
            OP_1..=OP_16 => push_number(stack, (opcode - 0x50) as i64),

            OP_NOP => {}
            OP_NOP1 => {
                if flags.contains(ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
            }
            OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                if flags.contains(ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
            }
            OP_CHECKLOCKTIMEVERIFY => {
                if flags.contains(ScriptVerifyFlags::CHECKLOCKTIMEVERIFY) {
                    let top = stack.last().ok_or(ScriptError::InvalidStackOperation)?.clone();
                    let n = ScriptNum::from_bytes(&top, require_minimal, LARGE_NUM_SIZE)
                        .map_err(|_| ScriptError::ScriptNum)?;
                    if n.value() < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if !checker.check_lock_time(n.value()) {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }
            }
            OP_CHECKSEQUENCEVERIFY => {
                if flags.contains(ScriptVerifyFlags::CHECKSEQUENCEVERIFY) {
                    let top = stack.last().ok_or(ScriptError::InvalidStackOperation)?.clone();
                    let n = ScriptNum::from_bytes(&top, require_minimal, LARGE_NUM_SIZE)
                        .map_err(|_| ScriptError::ScriptNum)?;
                    if n.value() < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if (n.value() & SEQUENCE_LOCKTIME_DISABLE_FLAG as i64) != 0 {
                        // NOP if the disable flag is set.
                    } else if !checker.check_sequence(n.value()) {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }
            }
            OP_IF | OP_NOTIF => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                if sigversion == SigVersion::Tapscript
                    && (top.len() > 1 || (top.len() == 1 && top[0] != 1))
                {
                    return Err(ScriptError::TapscriptMinimalif);
                }
                if sigversion == SigVersion::WitnessV0
                    && flags.contains(ScriptVerifyFlags::MINIMALIF)
                    && (top.len() > 1 || (top.len() == 1 && top[0] != 1))
                {
                    return Err(ScriptError::Minimalif);
                }
                let mut value = cast_to_bool(&top);
                if opcode == OP_NOTIF {
                    value = !value;
                }
                f_exec.push(value);
            }
            OP_ELSE => {
                if f_exec.empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                f_exec.toggle_top()?;
            }
            OP_ENDIF => {
                if f_exec.empty() {
                    return Err(ScriptError::UnbalancedConditional);
                }
                f_exec.pop()?;
            }
            OP_VERIFY => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                if !cast_to_bool(&top) {
                    return Err(ScriptError::Verify);
                }
            }
            OP_RETURN => return Err(ScriptError::OpReturn),

            // Stack ops
            OP_TOALTSTACK => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                altstack.push(top);
            }
            OP_FROMALTSTACK => {
                let top = altstack.pop().ok_or(ScriptError::InvalidAltstackOperation)?;
                stack.push(top);
            }
            OP_2DROP => {
                if stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                stack.truncate(stack.len() - 2);
            }
            OP_2DUP => {
                if stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let b = stack[stack.len() - 1].clone();
                let a = stack[stack.len() - 2].clone();
                stack.push(a);
                stack.push(b);
            }
            OP_3DUP => {
                if stack.len() < 3 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let c = stack[stack.len() - 1].clone();
                let b = stack[stack.len() - 2].clone();
                let a = stack[stack.len() - 3].clone();
                stack.push(a);
                stack.push(b);
                stack.push(c);
            }
            OP_2OVER => {
                if stack.len() < 4 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let d = stack[stack.len() - 4].clone();
                let c = stack[stack.len() - 3].clone();
                stack.push(d);
                stack.push(c);
            }
            OP_2ROT => {
                if stack.len() < 6 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let d = stack.remove(stack.len() - 6);
                let c = stack.remove(stack.len() - 5);
                stack.push(d);
                stack.push(c);
            }
            OP_2SWAP => {
                if stack.len() < 4 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let idx = stack.len() - 4;
                stack.swap(idx, idx + 2);
                stack.swap(idx + 1, idx + 3);
            }
            OP_IFDUP => {
                let top = stack.last().ok_or(ScriptError::InvalidStackOperation)?.clone();
                if cast_to_bool(&top) {
                    stack.push(top);
                }
            }
            OP_DEPTH => push_number(stack, stack.len() as i64),
            OP_DROP => {
                stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
            }
            OP_DUP => {
                let top = stack.last().ok_or(ScriptError::InvalidStackOperation)?.clone();
                stack.push(top);
            }
            OP_NIP => {
                if stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                stack.remove(stack.len() - 2);
            }
            OP_OVER => {
                if stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                stack.push(stack[stack.len() - 2].clone());
            }
            OP_PICK | OP_ROLL => {
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                if n < 0 || n >= stack.len() as i64 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let item = stack[stack.len() - 1 - n as usize].clone();
                if opcode == OP_ROLL {
                    stack.remove(stack.len() - 1 - n as usize);
                }
                stack.push(item);
            }
            OP_ROT => {
                if stack.len() < 3 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let item = stack.remove(stack.len() - 3);
                stack.push(item);
            }
            OP_SWAP => {
                if stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let a = stack.len() - 2;
                stack.swap(a, a + 1);
            }
            OP_TUCK => {
                if stack.len() < 2 {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let top = stack.last().unwrap().clone();
                stack.insert(stack.len() - 2, top);
            }
            // SIZE
            OP_SIZE => {
                let top = stack.last().ok_or(ScriptError::InvalidStackOperation)?.len();
                push_number(stack, top as i64);
            }

            // EQUALity
            OP_EQUAL | OP_EQUALVERIFY => {
                let b = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                let a = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                let eq = a == b;
                if opcode == OP_EQUALVERIFY {
                    if !eq {
                        return Err(ScriptError::EqualVerify);
                    }
                } else {
                    push_number(stack, if eq { 1 } else { 0 });
                }
            }
            OP_RESERVED1 | OP_RESERVED2 => return Err(ScriptError::BadOpcode),

            // Numeric ops
            OP_1ADD => {
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, n + 1);
            }
            OP_1SUB => {
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, n - 1);
            }
            OP_NEGATE => {
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, -n);
            }
            OP_ABS => {
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, n.abs());
            }
            OP_NOT => {
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, if n == 0 { 1 } else { 0 });
            }
            OP_0NOTEQUAL => {
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, if n != 0 { 1 } else { 0 });
            }
            OP_ADD => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, a + b);
            }
            OP_SUB => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, a - b);
            }
            OP_BOOLAND => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, if a != 0 && b != 0 { 1 } else { 0 });
            }
            OP_BOOLOR => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, if a != 0 || b != 0 { 1 } else { 0 });
            }
            OP_NUMEQUAL | OP_NUMEQUALVERIFY => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let eq = a == b;
                if opcode == OP_NUMEQUALVERIFY {
                    if !eq {
                        return Err(ScriptError::NumEqualVerify);
                    }
                } else {
                    push_number(stack, if eq { 1 } else { 0 });
                }
            }
            OP_NUMNOTEQUAL => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, if a != b { 1 } else { 0 });
            }
            OP_LESSTHAN | OP_GREATERTHAN | OP_LESSTHANOREQUAL | OP_GREATERTHANOREQUAL => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let r = match opcode {
                    OP_LESSTHAN => a < b,
                    OP_GREATERTHAN => a > b,
                    OP_LESSTHANOREQUAL => a <= b,
                    _ => a >= b,
                };
                push_number(stack, if r { 1 } else { 0 });
            }
            OP_MIN => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, a.min(b));
            }
            OP_MAX => {
                let b = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let a = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, a.max(b));
            }
            OP_WITHIN => {
                let max = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let min = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let x = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                push_number(stack, if x >= min && x < max { 1 } else { 0 });
            }
            // Hashes
            OP_RIPEMD160 => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                stack.push(ripemd160::Hash::hash(&top).as_byte_array().to_vec());
            }
            OP_SHA1 => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                stack.push(sha1::Hash::hash(&top).as_byte_array().to_vec());
            }
            OP_SHA256 => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                stack.push(sha256::Hash::hash(&top).as_byte_array().to_vec());
            }
            OP_HASH160 => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                stack.push(hash160::Hash::hash(&top).as_byte_array().to_vec());
            }
            OP_HASH256 => {
                let top = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                stack.push(sha256d::Hash::hash(&top).as_byte_array().to_vec());
            }

            // CODESEPARATOR
            OP_CODESEPARATOR => {
                code_start = pc;
                exec_data.codeseparator_pos = opcode_pos;
            }

            // Signatures
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                let ok = if sigversion == SigVersion::Tapscript {
                    check_sig_tapscript(stack, flags, checker, sigversion, exec_data)?
                } else {
                    check_sig_pre_tapscript(stack, script, code_start, flags, checker, sigversion)?
                };
                if opcode == OP_CHECKSIGVERIFY {
                    if !ok {
                        return Err(ScriptError::CheckSigVerify);
                    }
                } else {
                    stack.push(if ok { vec![1] } else { Vec::new() });
                }
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let ok = multisig_verify_operands(stack, script, code_start, flags, checker, sigversion, &mut op_count)?;
                if opcode == OP_CHECKMULTISIGVERIFY {
                    if !ok {
                        return Err(ScriptError::CheckMultisigVerify);
                    }
                } else {
                    stack.push(if ok { vec![1] } else { Vec::new() });
                }
            }
            OP_CHECKSIGADD => {
                if sigversion != SigVersion::Tapscript {
                    return Err(ScriptError::BadOpcode);
                }
                // Core: sig = stacktop(-3), num = stacktop(-2), pubkey = stacktop(-1).
                let pubkey = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                let n = pop_number(stack, require_minimal, MAX_NUM_SIZE)?.value();
                let sig = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;
                let success = !sig.is_empty();
                if success {
                    if let Some(left) = exec_data.validation_weight_left.as_mut() {
                        *left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
                        if *left < 0 {
                            return Err(ScriptError::TapscriptValidationWeight);
                        }
                    }
                }
                if pubkey.is_empty() {
                    return Err(ScriptError::TapscriptEmptyPubkey);
                } else if pubkey.len() == 32 {
                    if success && !checker.check_schnorr_signature(&sig, &pubkey, sigversion, exec_data) {
                        return Err(ScriptError::SchnorrSig);
                    }
                } else if flags.contains(ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE) {
                    return Err(ScriptError::DiscourageUpgradablePubkeytype);
                }
                push_number(stack, n + if success { 1 } else { 0 });
            }

            // NOPs in un-executed branches are handled above; anything else is unknown.
            _ => return Err(ScriptError::BadOpcode),
        }

        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        opcode_pos += 1;
    }

    if !f_exec.empty() {
        return Err(ScriptError::UnbalancedConditional);
    }
    exec_data.validation_weight_left; // keep field referenced in all paths
    Ok(())
}








