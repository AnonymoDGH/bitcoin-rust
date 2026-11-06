//! Signature and pubkey encoding checks. Port of IsValidSignatureEncoding, IsLowDERSignature,
//! IsDefinedHashtypeSignature, CheckPubKeyEncoding and CheckSignatureEncoding in src/script/interpreter.cpp.
//! PLACEHOLDER: signature fixed by CONTRACT.md. Owned by agent S2.

use crate::context::SigVersion;
use crate::error::ScriptError;
use crate::flags::ScriptVerifyFlags;

pub fn check_signature_encoding(sig: &[u8], flags: ScriptVerifyFlags) -> Result<(), ScriptError> {
    let _ = (sig, flags);
    unimplemented!("check_signature_encoding: owned by agent S2")
}

pub fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: ScriptVerifyFlags,
    sigversion: SigVersion,
) -> Result<(), ScriptError> {
    let _ = (pubkey, flags, sigversion);
    unimplemented!("check_pubkey_encoding: owned by agent S2")
}
