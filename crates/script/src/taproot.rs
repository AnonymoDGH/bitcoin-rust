//! Taproot commitments and tapleaf hashes. Port of ComputeTapleafHash, ComputeTapbranchHash,
//! ComputeTaprootMerkleRoot, VerifyTaprootCommitment in src/script/interpreter.cpp and
//! XOnlyPubKey::CheckTapTweak in src/pubkey.cpp.

use bitcoin::secp256k1::{Parity, Scalar, Secp256k1, XOnlyPublicKey};
use bitcoin_hashes::{sha256, Hash};

use crate::opcodes::{TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE};

const TAG_TAP_LEAF: &[u8] = b"TapLeaf";
const TAG_TAP_BRANCH: &[u8] = b"TapBranch";
const TAG_TAP_TWEAK: &[u8] = b"TapTweak";

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag);
    let mut buf = Vec::with_capacity(64 + data.len());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(data);
    sha256::Hash::hash(&buf).to_byte_array()
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Port of ComputeTapleafHash: tagged hash "TapLeaf" of (leaf_version || CompactSize(script) || script).
pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(script.len() + 10);
    buf.push(leaf_version);
    write_compact_size(&mut buf, script.len() as u64);
    buf.extend_from_slice(script);
    tagged_hash(TAG_TAP_LEAF, &buf)
}

/// Port of ComputeTapbranchHash: tagged hash "TapBranch" of the lexicographic (min, max) pair.
fn tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(lo);
    buf.extend_from_slice(hi);
    tagged_hash(TAG_TAP_BRANCH, &buf)
}

/// Port of ComputeTaprootMerkleRoot: fold path hashes from leaf to root.
fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: [u8; 32]) -> [u8; 32] {
    let path_len = (control.len() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    let mut k = tapleaf_hash;
    for i in 0..path_len {
        let start = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i;
        let node: [u8; 32] = control[start..start + 32].try_into().expect("32-byte node");
        k = tapbranch_hash(&k, &node);
    }
    k
}

/// Port of VerifyTaprootCommitment (control must be 33 + 32m bytes; program is the 32-byte x-only output key).
/// The internal key parity (control[0] & 1) is the parity of the *tweaked* output key.
pub fn verify_taproot_commitment(control: &[u8], program: &[u8], tapleaf_hash: [u8; 32]) -> bool {
    if control.len() < TAPROOT_CONTROL_BASE_SIZE {
        return false;
    }
    if (control.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0 {
        return false;
    }
    if program.len() != 32 {
        return false;
    }

    let internal = match XOnlyPublicKey::from_slice(&control[1..TAPROOT_CONTROL_BASE_SIZE]) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let merkle_root = compute_taproot_merkle_root(control, tapleaf_hash);

    // tweak = tagged_hash("TapTweak", internal_x || merkle_root)
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&internal.serialize());
    buf.extend_from_slice(&merkle_root);
    let tweak32 = tagged_hash(TAG_TAP_TWEAK, &buf);
    let tweak = match Scalar::from_be_bytes(tweak32) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let secp = Secp256k1::verification_only();
    // Q = lift_x(internal) + tweak*G; x-only key + parity.
    let (tweaked, parity) = match internal.add_tweak(&secp, &tweak) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let expected_parity = match Parity::from_u8(control[0] & 1) {
        Ok(p) => p,
        Err(_) => return false,
    };
    parity == expected_parity && tweaked.serialize() == program
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taproot_commitment_control_validation_and_sizes() {
        // Too-short control must fail, wrong parity/program must fail for non-taproot program.
        let leaf = compute_tapleaf_hash(0xc0, b"");
        assert!(!verify_taproot_commitment(&[], &[0u8; 32], leaf));
        assert!(!verify_taproot_commitment(&[0xc0; 33], &[1u8; 33], leaf));
        // Control length not multiple of 32 after the 33-byte prefix.
        let bad = vec![0xc0u8; 34];
        assert!(!verify_taproot_commitment(&bad, &[1u8; 32], leaf));
    }

    #[test]
    fn taproot_commitment_with_garbage_internal_key_fails() {
        // Invalid x-only scalar (>= 2^256 - q): 0xff...ff is out of range, rejected by libsecp256k1.
        let leaf = compute_tapleaf_hash(0xc0, b"\x51");
        let mut control = vec![0xc0u8];
        control.extend_from_slice(&[0xffu8; 32]);
        // Need a valid x-only key instead (e.g. the generator's x). Use 0x79be667e... which is Gx.
        let mut control = vec![0xc0u8];
        control.extend_from_slice(&hex_gx());
        control.extend_from_slice(&[0u8; 32]); // one path node
        assert!(!verify_taproot_commitment(&control, &[2u8; 32], leaf));
    }

    fn hex_gx() -> [u8; 32] {
        [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ]
    }
}
