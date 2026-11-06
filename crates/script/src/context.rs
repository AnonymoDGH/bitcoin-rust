//! Execution context shared by the interpreter, checker and verifier.
//! Port of SigVersion, ScriptExecutionData and BaseSignatureChecker from src/script/interpreter.h.

/// Which signature rules apply to the script being run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigVersion {
    /// Legacy scriptSig / scriptPubKey execution.
    Base,
    /// SegWit v0 (BIP141/143) witness scripts.
    WitnessV0,
    /// Taproot key-path or script-path with BIP341 rules (not used for tapscript itself).
    Taproot,
    /// Tapscript (BIP342).
    Tapscript,
}

/// Sentinel for "no OP_CODESEPARATOR executed yet".
pub const NO_CODESEPARATOR: u32 = 0xffff_ffff;

/// Per-execution data used only by taproot / tapscript.
#[derive(Clone, Debug)]
pub struct ExecData {
    /// Leaf hash of the tapscript being executed (script-path spends only).
    pub tapleaf_hash: Option<[u8; 32]>,
    /// Position of the last executed OP_CODESEPARATOR, or NO_CODESEPARATOR.
    pub codeseparator_pos: u32,
    /// Annex bytes including the leading 0x50 tag, if present.
    pub annex: Option<Vec<u8>>,
    /// Remaining sigop validation budget for tapscript (BIP342). None outside tapscript.
    pub validation_weight_left: Option<i64>,
}

impl ExecData {
    pub fn new() -> Self {
        Self {
            tapleaf_hash: None,
            codeseparator_pos: NO_CODESEPARATOR,
            annex: None,
            validation_weight_left: None,
        }
    }
}

impl Default for ExecData {
    fn default() -> Self {
        Self::new()
    }
}

/// Tapscript data needed to compute a BIP341 sighash for script-path spends.
#[derive(Clone, Copy, Debug)]
pub struct TapscriptExt {
    pub tapleaf_hash: [u8; 32],
    pub codeseparator_pos: u32,
}

/// Port of BaseSignatureChecker. Implementations do the cryptography only;
/// encoding rules (DER, low-S, hashtype, pubkey format) are checked by the interpreter first.
pub trait SignatureChecker {
    /// `sig` includes the trailing hashtype byte. `script_code` is the scriptCode for the sighash.
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
    ) -> bool;

    /// `sig` is 64 bytes, or 65 bytes when a hashtype byte is appended.
    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        exec_data: &ExecData,
    ) -> bool;

    /// OP_CHECKLOCKTIMEVERIFY check against the spending transaction.
    fn check_lock_time(&self, lock_time: i64) -> bool;

    /// OP_CHECKSEQUENCEVERIFY check against the spending input.
    fn check_sequence(&self, sequence: i64) -> bool;
}
