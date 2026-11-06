//! Top-level script verification. Port of VerifyScript and the witness paths in src/script/interpreter.cpp.
//! PLACEHOLDER: signature fixed by CONTRACT.md. Owned by agent S7.

use crate::context::SignatureChecker;
use crate::error::ScriptError;
use crate::flags::ScriptVerifyFlags;

pub fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    let _ = (script_sig, script_pubkey, witness, flags, checker);
    unimplemented!("verify_script: owned by agent S7")
}

pub fn is_witness_program(script: &[u8]) -> Option<(u8, Vec<u8>)> {
    let _ = script;
    unimplemented!("is_witness_program: owned by agent S7")
}
