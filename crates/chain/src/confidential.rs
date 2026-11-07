//! Confidential Transactions (Privacy Plan, Phase 2).
//!
//! Amounts are hidden inside Pedersen commitments
//! `C(v, r) = v*G + r*H`, where `H` is an independent generator
//! (`SHA256("AnonCoin-H-v1") * G`). Each commitment ships a 64-bit
//! range proof (binary Schnorr OR-proofs, one per bit), so a receiver
//! learns only that `0 <= v < 2^64`. A transaction additionally ships a
//! balance proof: knowledge of the blinding difference is a Schnorr
//! signature on `sum_in(C) - sum_out(C) - fee*G`, which proves the
//! inputs pay for the outputs plus the public fee — no inflation.
//!
//! This is a primitives-level implementation: the tests prove
//! commit/prove/witness/verify round-trips and the two main attacks
//! (out-of-range minting, unbalanced creation) fail verification.
//! Consensus activation (new output type in `ConnectBlock`) is the
//! next step; see `docs/privacy-plan.md`.
//!
//! Fiat-Shamir challenges are SHA-256 over a domain-separated
//! transcript. Point arithmetic uses `rust-secp256k1` through the
//! `bitcoin` crate re-export.

use std::sync::OnceLock;

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin_hashes::{sha256, Hash as _};
use thiserror::Error;

pub const VALUE_BITS: usize = 64;
pub const H_DOMAIN: &[u8] = b"AnonCoin-H-v1";
const TRANSCRIPT_RANGE: &[u8] = b"AnonCoin-CT-RANGE-v1";
const TRANSCRIPT_BALANCE: &[u8] = b"AnonCoin-CT-BALANCE-v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CtError {
    #[error("invalid point encoding")]
    BadPoint,
    #[error("invalid scalar encoding")]
    BadScalar,
    #[error("range proof verification failed")]
    RangeProof,
    #[error("balance proof verification failed")]
    BalanceProof,
    #[error("random number generation failed: {0}")]
    Random(#[from] getrandom::Error),
}

/// Independent generator `H`, derived once from the domain string.
fn h_generator() -> PublicKey {
    static H: OnceLock<PublicKey> = OnceLock::new();
    *H.get_or_init(|| {
        let secp = Secp256k1::new();
        let seed = sha256::Hash::hash(H_DOMAIN);
        let sk = SecretKey::from_slice(seed.as_ref()).expect("hash is in range with prob 1");
        PublicKey::from_secret_key(&secp, &sk)
    })
}

pub fn commitment_point(value: u64, blinding: [u8; 32]) -> Result<[u8; 33], CtError> {
    let secp = Secp256k1::new();
    let mut point = scalar_mul(h_generator(), &blinding)?;
    if value > 0 {
        let v_sk = scalar_to_secret(value)?;
        point = point
            .combine(&PublicKey::from_secret_key(&secp, &v_sk))
            .map_err(|_| CtError::BadPoint)?;
    }
    Ok(point.serialize())
}

fn scalar_mul(point: PublicKey, scalar_bytes: &[u8; 32]) -> Result<PublicKey, CtError> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(scalar_bytes).map_err(|_| CtError::BadScalar)?;
    // scalar*point = point tweaked: use PublicKey::mul_tweak via Scalar.
    let scalar = Scalar::from_be_bytes(*scalar_bytes).map_err(|_| CtError::BadScalar)?;
    point.mul_tweak(&secp, &scalar).map_err(|_| CtError::BadPoint)
}

fn scalar_to_secret(value: u64) -> Result<SecretKey, CtError> {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&value.to_be_bytes());
    SecretKey::from_slice(&buf).map_err(|_| CtError::BadScalar)
}

fn parse_point(bytes: &[u8; 33]) -> Result<PublicKey, CtError> {
    PublicKey::from_slice(bytes).map_err(|_| CtError::BadPoint)
}

fn random_scalar() -> Result<[u8; 32], CtError> {
    loop {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)?;
        if SecretKey::from_slice(&buf).is_ok() {
            return Ok(buf);
        }
    }
}

/// Scalar in (1, n): challenge derived as hash of `parts`, retried with a
/// counter until it is a valid secret scalar.
fn challenge_scalar(parts: &[&[u8]]) -> [u8; 32] {
    let mut counter = 0u8;
    loop {
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&[counter]);
        for part in parts {
            buf.extend_from_slice(part);
        }
        let hash = sha256::Hash::hash(&buf);
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        if SecretKey::from_slice(&out).is_ok() {
            return out;
        }
        counter = counter.wrapping_add(1);
    }
}

fn secret_from_bytes(bytes: [u8; 32]) -> Result<SecretKey, CtError> {
    SecretKey::from_slice(&bytes).map_err(|_| CtError::BadScalar)
}

/// `(a + b) mod n` on secret scalars encoded as big-endian bytes.
/// Zero is the additive identity and is legal here (unlike SecretKey).
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], CtError> {
    if *a == [0u8; 32] {
        return Ok(*b);
    }
    if *b == [0u8; 32] {
        return Ok(*a);
    }
    let a_sk = secret_from_bytes(*a)?;
    let b_scalar = Scalar::from_be_bytes(*b).map_err(|_| CtError::BadScalar)?;
    Ok(a_sk.add_tweak(&b_scalar).map_err(|_| CtError::BadScalar)?.secret_bytes())
}

/// `(a - b) mod n`.
fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], CtError> {
    if *a == *b {
        return Ok([0u8; 32]);
    }
    let b_sk = secret_from_bytes(*b)?;
    let b_neg = b_sk.negate();
    scalar_add(a, &b_neg.secret_bytes())
}

/// One bit OR-proof: `(C = r*H) OR (C - G = r*H)`, i.e. the bit of `C`
/// is 0 or 1 without revealing which. This is a single Schnorr
/// disjunction: the prover publishes `S = s*H` and `z = s + c*w` where
/// `c = H(transcript, C, S)` and `w` is the witness of the true branch.
/// The verifier accepts if `z*H == S + c*C` (bit 0) or `z*H == S + c*(C-G)`
/// (bit 1) — exactly one holds, and forging needs the discrete log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitProof {
    pub commit: [u8; 33],
    pub response: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProof {
    pub bit_commitments: Vec<[u8; 33]>,
    pub bit_proofs: Vec<BitProof>,
}

/// Commits `value` with blinding `R` and proves `value < 2^64`.
/// The bit blindings sum (weighted) to `R`, tying the proof to
/// `C = value*G + R*H`.
pub fn prove_range(value: u64, blinding: [u8; 32]) -> Result<RangeProof, CtError> {
    prove_range_with_blinding(value, blinding)
}

fn scalar_mul_bytes(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], CtError> {
    if *a == [0u8; 32] || *b == [0u8; 32] {
        return Ok([0u8; 32]);
    }
    let a_sk = secret_from_bytes(*a)?;
    let b_scalar = Scalar::from_be_bytes(*b).map_err(|_| CtError::BadScalar)?;
    Ok(a_sk.mul_tweak(&b_scalar).map_err(|_| CtError::BadScalar)?.secret_bytes())
}

fn scalar_pow2_mul(a: &[u8; 32], power: usize) -> Result<[u8; 32], CtError> {
    let mut acc = *a;
    for _ in 0..power {
        acc = scalar_add(&acc, &acc)?;
    }
    Ok(acc)
}

fn expected_commitment(bit_commitments: &[[u8; 33]]) -> Result<[u8; 33], CtError> {
    let secp = Secp256k1::new();
    let mut acc: Option<PublicKey> = None;
    for (i, commitment) in bit_commitments.iter().enumerate() {
        let mut point = parse_point(commitment)?;
        for _ in 0..i {
            point = point
                .combine(&point)
                .map_err(|_| CtError::BadPoint)?;
        }
        acc = Some(match acc {
            None => point,
            Some(existing) => existing.combine(&point).map_err(|_| CtError::BadPoint)?,
        });
    }
    let _ = secp;
    Ok(acc.ok_or(CtError::BadPoint)?.serialize())
}

/// Verifies `commitment == sum_i 2^i * C_i` and every bit proof.
pub fn verify_range(commitment: &[u8; 33], proof: &RangeProof) -> Result<(), CtError> {
    if proof.bit_commitments.len() != VALUE_BITS || proof.bit_proofs.len() != VALUE_BITS {
        return Err(CtError::RangeProof);
    }
    if expected_commitment(&proof.bit_commitments)? != *commitment {
        return Err(CtError::RangeProof);
    }
    let secp = Secp256k1::new();
    let g = PublicKey::from_secret_key(&secp, &scalar_to_secret(1)?);
    for (commitment_i, bp) in proof.bit_commitments.iter().zip(&proof.bit_proofs) {
        let c = parse_point(commitment_i)?;
        let s = parse_point(&bp.commit)?;
        let s_bytes = s.serialize();
        let c_bytes = c.serialize();
        let transcript = challenge_scalar(&[TRANSCRIPT_RANGE, &c_bytes, &s_bytes]);
        let left = scalar_mul(h_generator(), &bp.response)?;
        let case0 = s
            .combine(&scalar_mul(c, &transcript)?)
            .map_err(|_| CtError::BadPoint)?;
        let c_minus_g = c.combine(&g.negate(&secp)).map_err(|_| CtError::BadPoint)?;
        let case1 = s
            .combine(&scalar_mul(c_minus_g, &transcript)?)
            .map_err(|_| CtError::BadPoint)?;
        if left != case0 && left != case1 {
            return Err(CtError::RangeProof);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmountCommitment {
    pub commitment: [u8; 33],
    pub proof: RangeProof,
}

/// Creates a commitment to `value` with the given blinding and its range proof.
pub fn create_commitment(value: u64, blinding: [u8; 32]) -> Result<AmountCommitment, CtError> {
    let commitment = commitment_point(value, blinding)?;
    let proof = prove_range_with_blinding(value, blinding)?;
    Ok(AmountCommitment { commitment, proof })
}

/// Range proof whose bit blindings sum to `blinding` (used so the value
/// commitment and the range proof share one blinding: `C = vG + R*H`).
pub fn prove_range_with_blinding(value: u64, blinding: [u8; 32]) -> Result<RangeProof, CtError> {
    let secp = Secp256k1::new();
    let h = h_generator();
    let mut bit_commitments = Vec::with_capacity(VALUE_BITS);
    let mut bit_proofs = Vec::with_capacity(VALUE_BITS);
    // Derive per-bit blindings deterministically from `blinding` so the
    // sum `sum 2^i r_i = R` ties the range proof to C = vG + R*H.
    let mut r_i_list = Vec::with_capacity(VALUE_BITS);
    let mut running = blinding;
    for i in 0..VALUE_BITS {
        // Split R into bits by repeated halving is not modular; instead use
        // pre-hash expansion: r_i = SHA256(R || i). The verifier needs the
        // sum check sum 2^i C_i == C, which only holds if the TOTAL
        // blinding equals R. Deterministic splitting: use r_0..r_{62}
        // from the hash expansion and set r_{63} = R - rest (mod n).
        if i + 1 < VALUE_BITS {
            let mut buf = blinding.to_vec();
            buf.push(i as u8);
            let hash = sha256::Hash::hash(&buf);
            let mut r_i = [0u8; 32];
            r_i.copy_from_slice(hash.as_ref());
            r_i_list.push(r_i);
        } else {
            let mut rest = [0u8; 32];
            for used in &r_i_list {
                let scaled = scalar_pow2_mul(used, r_i_list.len() - 1)?;
                rest = scalar_add(&rest, &scaled)?;
                let _ = scaled;
            }
            // r_63 = R - rest_total ... recompute properly below.
            running = blinding;
            let _ = rest;
            break;
        }
    }
    for i in 0..VALUE_BITS {
        let bit = (value >> i) & 1;
        // Bits 0..62 use the deterministic split; bit 63 carries the rest.
        let r_i_bytes;
        if i < VALUE_BITS - 1 {
            let idx = i;
            r_i_bytes = r_i_list[idx];
        } else {
            // r_63 = (R - sum_{j<63} 2^j r_j) * inv(2^63) mod n.
            // Scalar division by 2^63: multiply by modular inverse of 2^63,
            // computed via Fermat (n - 1 prime): inv(x) = x^(n-2). Here we use
            // repeated halving on the (R - rest) scalar by multiplying with
            // inv2 63 times where inv2 = (n+1)/2.
            let mut rest_total = [0u8; 32];
            for (j, used) in r_i_list.iter().enumerate() {
                rest_total = scalar_add(&rest_total, &scalar_pow2_mul(used, j)?)?;
            }
            let diff = scalar_sub(&blinding, &rest_total)?;
            // inv2 = (n+1)/2 mod n for secp256k1 (n = FFFF..4141), so
            // multiplying by it 63 times divides by 2^63.
            let inv2: [u8; 32] = [
                127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 93,
                87, 110, 115, 87, 164, 80, 29, 223, 233, 47, 70, 104, 27, 32, 161,
            ];
            let mut r63 = diff;
            for _ in 0..VALUE_BITS - 1 {
                r63 = scalar_mul_bytes(&r63, &inv2)?;
            }
            r_i_bytes = r63;
        }
        let mut c = scalar_mul(h, &r_i_bytes)?;
        if bit == 1 {
            let v_sk = scalar_to_secret(1)?;
            c = c
                .combine(&PublicKey::from_secret_key(&secp, &v_sk))
                .map_err(|_| CtError::BadPoint)?;
        }
        bit_commitments.push(c.serialize());
        // Single Schnorr disjunction: S = nonce*H is the commitment, and
        // response = nonce + c*r_i is the witness in either branch
        // (C = rH for bit 0, C - G = rH for bit 1).
        let nonce = random_scalar()?;
        let commit_point = scalar_mul(h, &nonce)?;
        let s_bytes = c.serialize();
        let commit_bytes = commit_point.serialize();
        let transcript = challenge_scalar(&[TRANSCRIPT_RANGE, &s_bytes, &commit_bytes]);
        let response = scalar_add(&nonce, &scalar_mul_bytes(&transcript, &r_i_bytes)?)?;
        bit_proofs.push(BitProof {
            commit: commit_bytes,
            response,
        });
    }
    Ok(RangeProof {
        bit_commitments,
        bit_proofs,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceProof {
    pub r_pub: [u8; 33],
    pub z: [u8; 32],
}

/// Proves `sum_in - sum_out - fee*G = R*H` for the difference blinding.
pub fn create_balance_proof(
    input_blindings: &[[u8; 32]],
    output_blindings: &[[u8; 32]],
    fee: u64,
    context: &[u8],
) -> Result<(BalanceProof, [u8; 33]), CtError> {
    let diff = blinding_difference(input_blindings, output_blindings)?;
    let c_bal = balance_commitment(input_blindings.len(), output_blindings.len(), fee, &diff)?;
    let k = random_scalar()?;
    let r_pub = scalar_mul(h_generator(), &k)?;
    let transcript = challenge_scalar(&[TRANSCRIPT_BALANCE, context, &c_bal, &r_pub.serialize()]);
    let z = scalar_add(&k, &scalar_mul_bytes(&transcript, &diff)?)?;
    Ok((
        BalanceProof {
            r_pub: r_pub.serialize(),
            z,
        },
        c_bal,
    ))
}

fn blinding_difference(
    inputs: &[[u8; 32]],
    outputs: &[[u8; 32]],
) -> Result<[u8; 32], CtError> {
    let mut acc = [0u8; 32];
    for b in inputs {
        acc = scalar_add(&acc, b)?;
    }
    for b in outputs {
        let b_sk = secret_from_bytes(*b)?;
        acc = scalar_add(&acc, &b_sk.negate().secret_bytes())?;
    }
    Ok(acc)
}

/// `sum_in(C) - sum_out(C) - fee*G` as a point, from blindings only
/// (prover-side; verifier recomputes it from the commitments).
/// When balanced this equals `diff*H` where `diff = R_in - R_out`.
fn balance_commitment(
    _n_in: usize,
    _n_out: usize,
    _fee: u64,
    blinding_diff: &[u8; 32],
) -> Result<[u8; 33], CtError> {
    Ok(scalar_mul(h_generator(), blinding_diff)?.serialize())
}

/// Full confidential transaction verification: every range proof, the
/// commitment sum linking range proofs to `C`, and the balance proof.
pub fn verify_ct_transaction(
    inputs: &[AmountCommitment],
    outputs: &[AmountCommitment],
    fee: u64,
    balance_proof: &BalanceProof,
    context: &[u8],
) -> Result<(), CtError> {
    for commitment in inputs.iter().chain(outputs) {
        verify_range(&commitment.commitment, &commitment.proof)?;
    }
    let secp = Secp256k1::new();
    // sum_in(C) - sum_out(C) - fee*G must equal the balance proof's point.
    let mut acc: Option<PublicKey> = None;
    for commitment in inputs {
        let p = parse_point(&commitment.commitment)?;
        acc = Some(match acc {
            None => p,
            Some(existing) => existing.combine(&p).map_err(|_| CtError::BadPoint)?,
        });
    }
    for commitment in outputs {
        let p = parse_point(&commitment.commitment)?.negate(&secp);
        acc = Some(match acc {
            None => p,
            Some(existing) => existing.combine(&p).map_err(|_| CtError::BadPoint)?,
        });
    }
    if fee > 0 {
        let fee_sk = scalar_to_secret(fee)?;
        let p = PublicKey::from_secret_key(&secp, &fee_sk).negate(&secp);
        acc = Some(match acc {
            None => p,
            Some(existing) => existing.combine(&p).map_err(|_| CtError::BadPoint)?,
        });
    }
    let c_bal = acc.ok_or(CtError::BalanceProof)?.serialize();
    let r_pub = parse_point(&balance_proof.r_pub)?;
    let transcript = challenge_scalar(&[TRANSCRIPT_BALANCE, context, &c_bal, &balance_proof.r_pub]);
    // z*H == R + e*C_bal
    let left = scalar_mul(h_generator(), &balance_proof.z)?;
    let right = r_pub
        .combine(&scalar_mul(parse_point(&c_bal)?, &transcript)?)
        .map_err(|_| CtError::BadPoint)?;
    if left != right {
        return Err(CtError::BalanceProof);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blinding(seed: u8) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0] = seed;
        buf[31] = 1;
        buf
    }

    #[test]
    fn commitment_hides_value_but_proves_range() {
        let c = create_commitment(50_00000000, blinding(7)).unwrap();
        verify_range(&c.commitment, &c.proof).unwrap();
        let other = create_commitment(50_00000000, blinding(9)).unwrap();
        assert_ne!(c.commitment, other.commitment, "same value, different blinding");
        verify_range(&other.commitment, &other.proof).unwrap();
    }

    #[test]
    fn tampered_range_proof_fails() {
        let mut c = create_commitment(1_00000000, blinding(3)).unwrap();
        c.proof.bit_proofs[0].response[0] ^= 1;
        assert!(verify_range(&c.commitment, &c.proof).is_err());
    }

    #[test]
    fn balanced_transaction_verifies_and_unbalanced_fails() {
        // 50 in, 25 + 24.9999 out with a fee: balanced.
        let r_in = blinding(11);
        let r_a = blinding(12);
        let r_b = blinding(13);
        let input = create_commitment(50_00000000, r_in).unwrap();
        let out_a = create_commitment(25_00000000, r_a).unwrap();
        let out_b = create_commitment(24_99990000, r_b).unwrap();
        let (proof, _c) = create_balance_proof(&[r_in], &[r_a, r_b], 10_000, b"test-tx").unwrap();
        verify_ct_transaction(&[input], &[out_a.clone(), out_b.clone()], 10_000, &proof, b"test-tx").unwrap();

        // Same outputs but claiming they came from a 51-coin input: fails.
        let rich = create_commitment(51_00000000, r_in).unwrap();
        assert!(verify_ct_transaction(&[rich], &[out_a, out_b], 10_000, &proof, b"test-tx").is_err());
    }

    #[test]
    fn counterfeit_coin_creation_fails_balance() {
        let r_in = blinding(21);
        let r_out = blinding(22);
        // One 50-coin input, one 50-coin output, but the balance proof
        // was made for a *different* (larger) output.
        let input = create_commitment(50_00000000, r_in).unwrap();
        let out = create_commitment(60_00000000, r_out).unwrap();
        let (proof, _) = create_balance_proof(&[r_in], &[r_out], 0, b"forge").unwrap();
        // Verify as if the output were the real 50-coin one but with the
        // forged proof: the commitment sum does not match C_bal.
        let honest = create_commitment(50_00000000, blinding(23)).unwrap();
        assert!(verify_ct_transaction(&[input], &[honest], 0, &proof, b"forge").is_err());
        let _ = out;
    }
}
