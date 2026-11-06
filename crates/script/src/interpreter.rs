//! Script interpreter. Port of EvalScript in src/script/interpreter.cpp.
//! PLACEHOLDER: signature fixed by CONTRACT.md. Owned by agent S1.

use crate::context::{ExecData, SigVersion, SignatureChecker};
use crate::error::ScriptError;
use crate::flags::ScriptVerifyFlags;

pub fn eval_script(
    stack: &mut Vec<Vec<u8>>,
    script: &[u8],
    flags: ScriptVerifyFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
    exec_data: &mut ExecData,
) -> Result<(), ScriptError> {
    let _ = (stack, script, flags, checker, sigversion, exec_data);
    unimplemented!("eval_script: owned by agent S1")
}
