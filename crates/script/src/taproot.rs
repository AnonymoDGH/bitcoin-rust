//! Taproot commitments and tapleaf hashes. Port of VerifyTaprootCommitment and ComputeTaprootMerkleRoot in src/script/interpreter.cpp.
//! PLACEHOLDER: signature fixed by CONTRACT.md. Owned by agent S6.

pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let _ = (leaf_version, script);
    unimplemented!("compute_tapleaf_hash: owned by agent S6")
}

pub fn verify_taproot_commitment(control: &[u8], program: &[u8], tapleaf_hash: [u8; 32]) -> bool {
    let _ = (control, program, tapleaf_hash);
    unimplemented!("verify_taproot_commitment: owned by agent S6")
}
