//! Script error codes. Port of src/script/script_error.h and ScriptErrorString in script_error.cpp.
//! Variants are Core's SCRIPT_ERR_* names in CamelCase, in the same order.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptError {
    Ok,
    UnknownError,
    EvalFalse,
    OpReturn,
    ScriptNum,

    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,

    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,

    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,

    NegativeLocktime,
    UnsatisfiedLocktime,

    SigHashtype,
    SigDer,
    Minimaldata,
    SigPushonly,
    SigHighS,
    SigNulldummy,
    Pubkeytype,
    Cleanstack,
    Minimalif,
    SigNullfail,

    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeytype,

    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    WitnessPubkeytype,

    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckmultisig,
    TapscriptMinimalif,
    TapscriptEmptyPubkey,

    OpCodeseparator,
    SigFindanddelete,
}

impl ScriptError {
    /// Core's human-readable text for this error (ScriptErrorString).
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptError::Ok => "No error",
            ScriptError::UnknownError => "unknown error",
            ScriptError::EvalFalse => "Script evaluated without error but finished with a false/empty top stack element",
            ScriptError::OpReturn => "OP_RETURN was encountered",
            ScriptError::ScriptNum => "Script number overflow",
            ScriptError::ScriptSize => "Script is too big",
            ScriptError::PushSize => "Push value size limit exceeded",
            ScriptError::OpCount => "Opcode count limit exceeded",
            ScriptError::StackSize => "Combined stack size > 1000",
            ScriptError::SigCount => "Signature count negative or greater than pubkey count",
            ScriptError::PubkeyCount => "Pubkey count negative or limit exceeded",
            ScriptError::Verify => "Script failed an OP_VERIFY operation",
            ScriptError::EqualVerify => "Script failed an OP_EQUALVERIFY operation",
            ScriptError::CheckMultisigVerify => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            ScriptError::CheckSigVerify => "Script failed an OP_CHECKSIGVERIFY operation",
            ScriptError::NumEqualVerify => "Script failed an OP_NUMEQUALVERIFY operation",
            ScriptError::BadOpcode => "Opcode missing or not understood",
            ScriptError::DisabledOpcode => "Attempted to use a disabled opcode",
            ScriptError::InvalidStackOperation => "Operation not valid with the current stack size",
            ScriptError::InvalidAltstackOperation => "Operation not valid with the current altstack size",
            ScriptError::UnbalancedConditional => "Invalid OP_IF construction",
            ScriptError::NegativeLocktime => "Negative locktime",
            ScriptError::UnsatisfiedLocktime => "Locktime requirement not satisfied",
            ScriptError::SigHashtype => "Signature hash type missing or not understood",
            ScriptError::SigDer => "Non-canonical DER signature",
            ScriptError::Minimaldata => "Data push larger than necessary",
            ScriptError::SigPushonly => "Only push operators allowed in signatures",
            ScriptError::SigHighS => "Non-canonical signature: S value is unnecessarily high",
            ScriptError::SigNulldummy => "Dummy CHECKMULTISIG argument must be zero",
            ScriptError::Pubkeytype => "Public key is neither compressed or uncompressed",
            ScriptError::Cleanstack => "Stack size must be exactly one after execution",
            ScriptError::Minimalif => "OP_IF/NOTIF argument must be minimal",
            ScriptError::SigNullfail => "Signature must be zero for failed CHECK(MULTI)SIG operation",
            ScriptError::DiscourageUpgradableNops => "NOPx reserved for soft-fork upgrades",
            ScriptError::DiscourageUpgradableWitnessProgram => "Witness version reserved for soft-fork upgrades",
            ScriptError::DiscourageUpgradableTaprootVersion => "Taproot version reserved for soft-fork upgrades",
            ScriptError::DiscourageOpSuccess => "OP_SUCCESSx reserved for soft-fork upgrades",
            ScriptError::DiscourageUpgradablePubkeytype => "Unknown public key version reserved for soft-fork upgrades",
            ScriptError::WitnessProgramWrongLength => "Witness program has incorrect length",
            ScriptError::WitnessProgramWitnessEmpty => "Witness program was passed an empty witness",
            ScriptError::WitnessProgramMismatch => "Witness program hash mismatch",
            ScriptError::WitnessMalleated => "Witness requires empty scriptSig",
            ScriptError::WitnessMalleatedP2sh => "Witness requires only-redeemscript scriptSig",
            ScriptError::WitnessUnexpected => "Witness provided for non-witness script",
            ScriptError::WitnessPubkeytype => "Using non-compressed keys in segwit",
            ScriptError::SchnorrSigSize => "Invalid Schnorr signature size",
            ScriptError::SchnorrSigHashtype => "Invalid Schnorr signature hash type",
            ScriptError::SchnorrSig => "Invalid Schnorr signature",
            ScriptError::TaprootWrongControlSize => "Invalid Taproot control block size",
            ScriptError::TapscriptValidationWeight => "Too much signature validation relative to witness weight",
            ScriptError::TapscriptCheckmultisig => "OP_CHECKMULTISIG(VERIFY) is not available in tapscript",
            ScriptError::TapscriptMinimalif => "OP_IF/NOTIF argument must be minimal in tapscript",
            ScriptError::TapscriptEmptyPubkey => "Empty public key in tapscript",
            ScriptError::OpCodeseparator => "Using OP_CODESEPARATOR in non-witness script",
            ScriptError::SigFindanddelete => "Signature is found in scriptCode",
        }
    }
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ScriptError {}
