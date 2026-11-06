# btc-script contract

Port of Bitcoin Core src/script/ (reference: D:\bitcoin-core-reference\src\script).
Crate: D:\bitcoin-rust\crates\script (package btc-script).

## Shared files (already written by the lead; do NOT change names or signatures)

- `error.rs`: `ScriptError` enum. Variants are Core's SCRIPT_ERR_* in CamelCase. `as_str()` gives Core's text.
- `flags.rs`: `ScriptVerifyFlags` with consts named like Core's SCRIPT_VERIFY_* without the prefix
  (P2SH, STRICTENC, DERSIG, LOW_S, NULLDUMMY, SIGPUSHONLY, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS,
  CLEANSTACK, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
  MINIMALIF, NULLFAIL, WITNESS_PUBKEYTYPE, CONST_SCRIPTCODE, TAPROOT, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
  DISCOURAGE_OP_SUCCESS, DISCOURAGE_UPGRADABLE_PUBKEYTYPE). Bit positions match Core's enum order in
  interpreter.h (verified): P2SH=bit0 ... CONST_SCRIPTCODE=bit16, TAPROOT=bit17,
  DISCOURAGE_UPGRADABLE_TAPROOT_VERSION=bit18, DISCOURAGE_OP_SUCCESS=bit19,
  DISCOURAGE_UPGRADABLE_PUBKEYTYPE=bit20. Methods: `contains`, `bits`, `from_bits`, `|`, `&`, `|=`.
- `opcodes.rs`: `OP_*` as u8 consts with Core's names. `get_op(script, &mut pc) -> Option<(u8, Vec<u8>)>`
  (port of GetScriptOp). `is_op_success(u8) -> bool`. Limits: MAX_SCRIPT_SIZE, MAX_SCRIPT_ELEMENT_SIZE,
  MAX_OPS_PER_SCRIPT, MAX_PUBKEYS_PER_MULTISIG, MAX_STACK_SIZE, LOCKTIME_THRESHOLD, SEQUENCE_* consts,
  ANNEX_TAG, TAPROOT_LEAF_TAPSCRIPT, TAPROOT_LEAF_MASK, TAPROOT_CONTROL_* sizes, VALIDATION_WEIGHT_*.
- `script_num.rs`: `ScriptNum` (wraps i64). `ScriptNum::new(i64)`, `.value()`,
  `ScriptNum::from_bytes(&[u8], require_minimal: bool, max_len: usize) -> Result<ScriptNum, ScriptError>`
  (returns ScriptError::ScriptNum on failure), `ScriptNum::encode(i64) -> Vec<u8>`, `.to_bytes()`.
  `DEFAULT_MAX_NUM_SIZE = 4`.
- `context.rs`: `SigVersion {Base, WitnessV0, Taproot, Tapscript}`, `ExecData` (`tapleaf_hash`, `codeseparator_pos`,
  `annex`, `validation_weight_left`, `ExecData::new()`), `TapscriptExt`, `NO_CODESEPARATOR`,
  `trait SignatureChecker` with `check_ecdsa_signature`, `check_schnorr_signature`, `check_lock_time`, `check_sequence`.

## Owned modules (fixed signatures)

- `interpreter.rs`:
  `pub fn eval_script(stack: &mut Vec<Vec<u8>>, script: &[u8], flags: ScriptVerifyFlags, checker: &dyn SignatureChecker, sigversion: SigVersion, exec_data: &mut ExecData) -> Result<(), ScriptError>`
- `sig_encoding.rs`:
  `pub fn check_signature_encoding(sig: &[u8], flags: ScriptVerifyFlags) -> Result<(), ScriptError>`
  `pub fn check_pubkey_encoding(pubkey: &[u8], flags: ScriptVerifyFlags, sigversion: SigVersion) -> Result<(), ScriptError>`
- `sighash.rs` (Tx = `btc_primitives::Tx`):
  `pub fn signature_hash_legacy(script_code: &[u8], tx: &Tx, n_in: usize, hash_type: u32) -> [u8; 32]`
  `pub fn signature_hash_segwit_v0(script_code: &[u8], tx: &Tx, n_in: usize, hash_type: u32, amount: i64) -> [u8; 32]`
- `sighash_taproot.rs`:
  `pub fn signature_hash_taproot(tx: &Tx, n_in: usize, hash_type: u8, spent_outputs: &[btc_primitives::TxOut], ext: Option<&TapscriptExt>, annex: Option<&[u8]>) -> Option<[u8; 32]>`
  (None means invalid hashtype or bad input index, same as Core returning false.)
- `checker.rs`:
  `pub struct TransactionSignatureChecker<'a> { .. }`
  `impl<'a> TransactionSignatureChecker<'a> { pub fn new(tx: &'a Tx, n_in: usize, spent_outputs: &'a [TxOut]) -> Self }`
  Implements `SignatureChecker`. Amount = `spent_outputs[n_in].value`.
  `check_ecdsa_signature` strips the hashtype byte from `sig`, hashes, verifies with secp256k1 (lax DER parse for non-strict, as Core does).
- `taproot.rs`:
  `pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32]`
  `pub fn verify_taproot_commitment(control: &[u8], program: &[u8], tapleaf_hash: [u8; 32]) -> bool`
  (`program` = 32-byte x-only output key.)
- `verify.rs`:
  `pub fn verify_script(script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>], flags: ScriptVerifyFlags, checker: &dyn SignatureChecker) -> Result<(), ScriptError>`
  `pub fn is_witness_program(script: &[u8]) -> Option<(u8, Vec<u8>)>`
  Covers P2SH, witness v0 (P2WPKH, P2WSH), taproot v1 (key path, script path, annex), tapscript, cleanstack.
- `sigops.rs`:
  `pub fn get_sigop_count(script: &[u8], accurate: bool) -> u32`
  `pub fn get_p2sh_sigop_count(script_sig: &[u8], script_pubkey: &[u8]) -> u32`
  `pub fn count_witness_sigops(script_sig: &[u8], script_pubkey: &[u8], witness: &[Vec<u8>], flags: ScriptVerifyFlags) -> u32`
- `tests/script_vectors.rs`: runs Core's src/test/data/script_tests.json.

## Rules for every agent

- Only edit the file you own. Do not edit lib.rs, Cargo.toml, error.rs, flags.rs, opcodes.rs, script_num.rs, context.rs or CONTRACT.md.
- If a shared item seems wrong or missing, say so in your report. Do not patch it.
- Port Core's logic and its error codes. Do not add stubs that return Ok in place of real checks.
- Write Rust with the write/edit tools (UTF-8). Do not use PowerShell Set-Content for .rs files.
- No emojis. Comment only non-obvious consensus logic. Do not modify D:\bitcoin-core-reference.
- Verify with: `cd D:\bitcoin-rust; cargo check -p btc-script`. Other agents' files may still be in progress, so only errors in your own file count.
- Final report, short: what you implemented, the C++ files used, and the check/test result for your file.
