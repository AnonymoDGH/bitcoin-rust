//! Signature operation counting. Port of CScript::GetSigOpCount, GetP2SHSigOpCount and CountWitnessSigOps.
//! PLACEHOLDER: signature fixed by CONTRACT.md. Owned by agent S8.

use crate::flags::ScriptVerifyFlags;

pub fn get_sigop_count(script: &[u8], accurate: bool) -> u32 {
    let _ = (script, accurate);
    unimplemented!("get_sigop_count: owned by agent S8")
}

pub fn get_p2sh_sigop_count(script_sig: &[u8], script_pubkey: &[u8]) -> u32 {
    let _ = (script_sig, script_pubkey);
    unimplemented!("get_p2sh_sigop_count: owned by agent S8")
}

pub fn count_witness_sigops(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: ScriptVerifyFlags,
) -> u32 {
    let _ = (script_sig, script_pubkey, witness, flags);
    unimplemented!("count_witness_sigops: owned by agent S8")
}
