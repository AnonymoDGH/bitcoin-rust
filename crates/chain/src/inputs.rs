//! Script checks for every input. Port of `CheckInputScripts` / `CScriptCheck`.

use btc_primitives::{Tx, TxOut};
use btc_script::ScriptVerifyFlags;

use crate::ValidationError;

/// Verifies every input of a non-coinbase `tx`. `spent[i]` is the output
/// spent by input i (all of them are needed for Taproot sighashes). Uses
/// `btc_script::checker::TransactionSignatureChecker` and `verify_script`.
/// On failure returns `ValidationError::Script { input, error }`.
pub fn check_input_scripts(tx: &Tx, spent: &[TxOut], flags: ScriptVerifyFlags) -> Result<(), ValidationError> {
    todo!()
}

/// Same as `check_input_scripts` but runs inputs on `threads` std threads
/// (scoped), returning the lowest failing input index. `threads <= 1` = serial.
pub fn check_input_scripts_parallel(
    tx: &Tx,
    spent: &[TxOut],
    flags: ScriptVerifyFlags,
    threads: usize,
) -> Result<(), ValidationError> {
    todo!()
}
