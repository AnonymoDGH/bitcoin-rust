//! Signature and pubkey encoding checks. Port of IsValidSignatureEncoding, IsLowDERSignature,
//! IsDefinedHashtypeSignature, CheckPubKeyEncoding and CheckSignatureEncoding in src/script/interpreter.cpp.

use crate::context::SigVersion;
use crate::error::ScriptError;
use crate::flags::ScriptVerifyFlags;

const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_SINGLE: u8 = 0x03;
const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// secp256k1 group order n (big-endian 32 bytes).
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// n / 2 (big-endian 32 bytes); signatures with S > this must be rejected under LOW_S.
const SECP256K1_N_OVER_2: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Port of IsValidSignatureEncoding (BIP66 rules).
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [hashtype]
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }

    let len_r = sig[3] as usize;

    if 5 + len_r >= sig.len() {
        return false;
    }

    let len_s = sig[5 + len_r] as usize;

    if len_r + len_s + 7 != sig.len() {
        return false;
    }

    if sig[2] != 0x02 {
        return false;
    }

    if len_r == 0 {
        return false;
    }

    if sig[4] & 0x80 != 0 {
        return false;
    }

    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }

    if sig[len_r + 4] != 0x02 {
        return false;
    }

    if len_s == 0 {
        return false;
    }

    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }

    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }

    true
}

fn is_low_der_signature(sig: &[u8]) -> bool {
    if !is_valid_signature_encoding(sig) {
        return false;
    }
    // sig[last] is the hashtype byte; the DER payload is everything before it.
    let len_r = sig[3] as usize;
    let len_s = sig[5 + len_r] as usize;
    let s = &sig[len_r + 6..len_r + 6 + len_s];
    // Strip a single leading 0x00 if present (padding for the sign bit), then pad to 32 bytes.
    let s = if s.len() > 1 && s[0] == 0x00 { &s[1..] } else { s };
    let mut s32 = [0u8; 32];
    s32[32 - s.len()..].copy_from_slice(s);
    // S must be <= n/2.
    s32 <= SECP256K1_N_OVER_2
}

/// Port of IsDefinedHashtypeSignature. An empty signature returns false.
pub fn is_defined_hashtype_signature(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return false;
    }
    let n_hash_type = sig[sig.len() - 1] & !SIGHASH_ANYONECANPAY;
    (SIGHASH_ALL..=SIGHASH_SINGLE).contains(&n_hash_type)
}

/// Port of IsCompressedPubKey.
pub fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

/// Port of IsCompressedOrUncompressedPubKey.
pub fn is_compressed_or_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    if pubkey.len() < 33 {
        return false;
    }
    if pubkey[0] == 0x04 {
        pubkey.len() == 65
    } else if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
        pubkey.len() == 33
    } else {
        false
    }
}

/// Port of CheckSignatureEncoding.
pub fn check_signature_encoding(sig: &[u8], flags: ScriptVerifyFlags) -> Result<(), ScriptError> {
    // Empty signature: the compact way to provide an invalid signature in CHECK(MULTI)SIG.
    if sig.is_empty() {
        return Ok(());
    }
    if flags & (ScriptVerifyFlags::DERSIG | ScriptVerifyFlags::LOW_S | ScriptVerifyFlags::STRICTENC)
        != ScriptVerifyFlags::NONE
        && !is_valid_signature_encoding(sig)
    {
        return Err(ScriptError::SigDer);
    } else if flags.contains(ScriptVerifyFlags::LOW_S) && !is_low_der_signature(sig) {
        return Err(ScriptError::SigHighS);
    } else if flags.contains(ScriptVerifyFlags::STRICTENC) && !is_defined_hashtype_signature(sig) {
        return Err(ScriptError::SigHashtype);
    }
    Ok(())
}

/// Port of CheckPubKeyEncoding.
pub fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: ScriptVerifyFlags,
    sigversion: SigVersion,
) -> Result<(), ScriptError> {
    if flags.contains(ScriptVerifyFlags::STRICTENC)
        && !is_compressed_or_uncompressed_pubkey(pubkey)
    {
        return Err(ScriptError::Pubkeytype);
    }
    // Only compressed keys are accepted in segwit v0.
    if flags.contains(ScriptVerifyFlags::WITNESS_PUBKEYTYPE)
        && sigversion == SigVersion::WitnessV0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(ScriptError::WitnessPubkeytype);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_sig(r: &[u8], s: &[u8], hashtype: u8) -> Vec<u8> {
        let mut v = vec![0x30, 0, 0x02, r.len() as u8];
        v.extend_from_slice(r);
        v.push(0x02);
        v.push(s.len() as u8);
        v.extend_from_slice(s);
        v.push(hashtype);
        v[1] = (v.len() - 3) as u8;
        v
    }

    #[test]
    fn valid_der_signature_passes() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let sig = der_sig(&r, &s, 0x01);
        assert!(is_valid_signature_encoding(&sig));
        assert!(check_signature_encoding(&sig, ScriptVerifyFlags::STRICTENC).is_ok());
    }

    #[test]
    fn der_rejects_high_s() {
        let r = [0x11u8; 32];
        // 0x7fff...ffff is valid DER but strictly greater than n/2.
        let mut s = [0xffu8; 32];
        s[0] = 0x7f;
        let sig = der_sig(&r, &s, 0x01);
        assert!(is_valid_signature_encoding(&sig));
        assert_eq!(
            check_signature_encoding(&sig, ScriptVerifyFlags::LOW_S).unwrap_err(),
            ScriptError::SigHighS
        );
    }

    #[test]
    fn der_rejects_missing_hashtype() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let sig = der_sig(&r, &s, 0x99);
        assert_eq!(
            check_signature_encoding(&sig, ScriptVerifyFlags::STRICTENC).unwrap_err(),
            ScriptError::SigHashtype
        );
    }

    #[test]
    fn der_rejects_short_and_wrong_prefixes() {
        assert!(!is_valid_signature_encoding(&[0u8; 8]));
        let mut sig = der_sig(&[0x11u8; 32], &[0x22u8; 32], 0x01);
        sig[0] = 0x31;
        assert!(!is_valid_signature_encoding(&sig));
    }

    #[test]
    fn pubkey_encodings() {
        let compressed = [0x02u8; 33];
        let uncompressed = [0x04u8; 65];
        assert!(is_compressed_pubkey(&compressed));
        assert!(is_compressed_or_uncompressed_pubkey(&uncompressed));
        assert!(!is_compressed_or_uncompressed_pubkey(&[0x02u8; 65]));
        assert!(check_pubkey_encoding(
            &uncompressed,
            ScriptVerifyFlags::STRICTENC | ScriptVerifyFlags::WITNESS_PUBKEYTYPE,
            SigVersion::WitnessV0,
        ) == Err(ScriptError::WitnessPubkeytype));
    }
}
