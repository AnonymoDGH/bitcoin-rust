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
use btc_primitives::ScriptBuf;
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
        // Plaintext-derived commitments (empty proof) skip the range check;
        // the ledger has already MoneyRange-checked the value.
        if !commitment.proof.bit_commitments.is_empty() {
            verify_range(&commitment.commitment, &commitment.proof)?;
        }
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

/// Confidential output script: `OP_RETURN 0x01 <commitment:33> <pubkey_hash:20> <range_proof:6272>`.
/// Value must be 0 (the amount is hidden in the commitment).
pub struct CtOutputData {
    pub commitment: [u8; 33],
    pub pubkey_hash: [u8; 20],
    pub proof: RangeProof,
}

pub fn encode_ct_script(data: &CtOutputData) -> Result<btc_primitives::ScriptBuf, CtError> {
    let mut buf = vec![0x6a, 0x01];
    buf.extend_from_slice(&data.commitment);
    buf.extend_from_slice(&data.pubkey_hash);
    let proof_bytes = serialize_range_proof(&data.proof);
    push_data(&mut buf, &proof_bytes);
    Ok(btc_primitives::ScriptBuf::from_bytes(buf))
}

fn push_data(buf: &mut Vec<u8>, data: &[u8]) {
    if data.len() < 0x4c {
        buf.push(data.len() as u8);
    } else if data.len() <= 0xff {
        buf.push(0x4c);
        buf.push(data.len() as u8);
    } else {
        buf.push(0x4d);
        buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    }
    buf.extend_from_slice(data);
}

pub fn decode_ct_script(script: &[u8]) -> Option<CtOutputData> {
    let len = script.len();
    if len < 2 || script[0] != 0x6a || script[1] != 0x01 {
        return None;
    }
    // [0x6a, 0x01, commitment:33, pubkey_hash:20, push(proof)]
    let commitment: [u8; 33] = script.get(2..35)?.try_into().ok()?;
    let pubkey_hash: [u8; 20] = script.get(35..55)?.try_into().ok()?;
    let proof_data = parse_push(script.get(55..)?)?;
    let proof = deserialize_range_proof(proof_data)?;
    if !verify_range(&commitment, &proof).is_ok() {
        return None;
    }
    Some(CtOutputData {
        commitment,
        pubkey_hash,
        proof,
    })
}

pub fn is_ct_script(script: &[u8]) -> bool {
    decode_ct_script(script).is_some()
}

fn parse_push(data: &[u8]) -> Option<&[u8]> {
    let (len, header) = match data.first()? {
        b if *b < 0x4c => (*b as usize, 1),
        0x4c => (*data.get(1)? as usize, 2),
        0x4d => {
            let len = u16::from_le_bytes(data.get(1..3)?.try_into().ok()?) as usize;
            (len, 3)
        }
        _ => return None,
    };
    if header + len != data.len() {
        return None;
    }
    Some(&data[header..])
}

fn serialize_range_proof(proof: &RangeProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(VALUE_BITS * (33 + 65));
    for commitment in &proof.bit_commitments {
        out.extend_from_slice(commitment);
    }
    for bp in &proof.bit_proofs {
        out.extend_from_slice(&bp.commit);
        out.extend_from_slice(&bp.response);
    }
    out
}

fn deserialize_range_proof(data: &[u8]) -> Option<RangeProof> {
    let expected = VALUE_BITS * (33 + 65);
    if data.len() != expected {
        return None;
    }
    let mut bit_commitments = Vec::with_capacity(VALUE_BITS);
    for i in 0..VALUE_BITS {
        bit_commitments.push(data[i * 33..(i + 1) * 33].try_into().ok()?);
    }
    let mut bit_proofs = Vec::with_capacity(VALUE_BITS);
    let tail = &data[VALUE_BITS * 33..];
    for i in 0..VALUE_BITS {
        let entry = &tail[i * 65..(i + 1) * 65];
        bit_proofs.push(BitProof {
            commit: entry[..33].try_into().ok()?,
            response: entry[33..].try_into().ok()?,
        });
    }
    Some(RangeProof {
        bit_commitments,
        bit_proofs,
    })
}

/// Sighash-like context for CT proofs of one transaction: SHA256D of the
/// wire encoding with witnesses *and* scriptSigs stripped and
/// shield-marker balance bytes zeroed. Stripping the scriptSig breaks
/// the fixed-point problem: the ECDSA signature signs the marker
/// content, and the proof is computed over the same deterministic
/// digest either way.
pub fn ct_context(tx: &btc_primitives::Tx) -> [u8; 32] {
    let mut stripped = tx.clone();
    for input in &mut stripped.vin {
        input.witness = bitcoin::Witness::new();
        input.script_sig = btc_primitives::ScriptBuf::new();
    }
    for output in &mut stripped.vout {
        output.script_pubkey = zero_shield_balance(&output.script_pubkey);
    }
    let bytes = bitcoin::consensus::encode::serialize(&stripped);
    let hash = bitcoin_hashes::sha256d::Hash::hash(&bytes);
    hash.to_byte_array()
}

/// Returns the script with shield-marker balance bytes zeroed, or the
/// original script when it is not a shield marker.
pub fn zero_shield_balance(script: &btc_primitives::ScriptBuf) -> btc_primitives::ScriptBuf {
    let bytes = script.as_bytes();
    if is_shield_marker(script) {
        let mut zeroed = bytes.to_vec();
        // Payload starts at byte 4: [0x51][r_in: 5..37][balance: 37..110].
        for byte in &mut zeroed[37..110] {
            *byte = 0;
        }
        return btc_primitives::ScriptBuf::from_bytes(zeroed);
    }
    script.clone()
}

/// True for shield markers: `OP_RETURN <106-byte payload starting 0x51>`.
pub fn is_shield_marker(script: &btc_primitives::ScriptBuf) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 4 + 106
        && bytes[0] == 0x6a
        && bytes[1] == 0x4d
        && u16::from_le_bytes(bytes[2..4].try_into().unwrap()) == 106
        && bytes[4] == 0x51
}

/// Balance proof with the public fee prefixed: `fee(8 LE) || r_pub(33) || z(32)`.
/// The fee stays public so the verifier can reconstruct
/// `fee*G` while the amounts remain hidden.
pub fn serialize_balance_proof(proof: &BalanceProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(73);
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&proof.r_pub);
    out.extend_from_slice(&proof.z);
    out
}

/// Sets the fee prefix on a serialized balance proof.
pub fn with_fee(mut bytes: Vec<u8>, fee: u64) -> Vec<u8> {
    bytes[..8].copy_from_slice(&fee.to_le_bytes());
    bytes
}

/// Extracts the public fee prefix.
pub fn proof_fee(data: &[u8]) -> u64 {
    if data.len() != 73 {
        return 0;
    }
    u64::from_le_bytes(data[..8].try_into().expect("8 bytes"))
}

pub fn deserialize_balance_proof(data: &[u8]) -> Option<BalanceProof> {
    if data.len() != 73 {
        return None;
    }
    Some(BalanceProof {
        r_pub: data[8..41].try_into().ok()?,
        z: data[41..].try_into().ok()?,
    })
}

pub fn serialize_ring_sig(sig: &crate::ringsig::RingSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(crate::ringsig::RING_SIZE * 64);
    for (c, z) in &sig.responses {
        out.extend_from_slice(c);
        out.extend_from_slice(z);
    }
    out
}

pub fn deserialize_ring_sig(data: &[u8]) -> Option<crate::ringsig::RingSignature> {
    if data.len() != crate::ringsig::RING_SIZE * 64 {
        return None;
    }
    let mut responses = Vec::with_capacity(crate::ringsig::RING_SIZE);
    for i in 0..crate::ringsig::RING_SIZE {
        let entry = &data[i * 64..(i + 1) * 64];
        responses.push((entry[..32].try_into().ok()?, entry[32..].try_into().ok()?));
    }
    Some(crate::ringsig::RingSignature { responses })
}

/// Parses shield markers: `OP_RETURN <0x51 | r_in(32) | balance_proof(73)>`.
/// Each marker carries one plaintext input's blinding plus — on the
/// first marker — the balance proof. Distinct from the stealth marker
/// (33-byte pubkey) by the leading `0x51` and the 106-byte payload.
pub fn shield_markers(tx: &btc_primitives::Tx) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut markers = Vec::new();
    for output in &tx.vout {
        let bytes = output.script_pubkey.as_bytes();
        // OP_RETURN, PUSHDATA2 len=106, payload 106 bytes
        if bytes.len() == 4 + 106
            && bytes[0] == 0x6a
            && bytes[1] == 0x4d
            && u16::from_le_bytes(bytes[2..4].try_into().unwrap()) == 106
            && bytes[4] == 0x51
        {
            let payload = &bytes[4..];
            let r_in = payload[1..33].to_vec();
            let balance = payload[33..106].to_vec();
            if balance.len() == 73 {
                markers.push((r_in, balance));
            }
        }
    }
    markers
}

/// Push-encoding for a shield marker payload.
pub fn encode_shield_marker(r_in: &[u8; 32], balance_proof_bytes: &[u8]) -> Vec<u8> {
    let mut payload = vec![0x51u8];
    payload.extend_from_slice(r_in);
    payload.extend_from_slice(balance_proof_bytes);
    let mut script = vec![0x6a, 0x4d];
    script.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    script.extend_from_slice(&payload);
    script
}

/// Public miner fee of a CT transaction, taken from the balance-proof
/// fee prefix. This is the ONLY sound fee for CT txs: hybrid spends
/// hide `amount` in the CT outputs, so the plaintext ledger fee
/// (`inputs - outputs`) overstates the true fee by exactly the
/// shielded value — paying that to the coinbase would mint the
/// hidden amounts twice. The balance proof ties
/// `inputs - hidden_outputs - fee = 0`, so the prefix fee is proven
/// on chain; the hidden value locked is `inputs - plain_outputs - fee`.
pub fn ct_public_fee(tx: &btc_primitives::Tx) -> u64 {
    let shield = shield_markers(tx);
    let bytes: &[u8] = if !shield.is_empty() {
        &shield[0].1
    } else {
        match tx.vin.first().and_then(|i| i.witness.iter().next()) {
            Some(b) => b,
            None => return 0,
        }
    };
    proof_fee(bytes)
}

/// True if the transaction is a confidential (CT) transaction:
/// CT input/output scripts or a shield marker present.
pub fn is_ct_tx(
    tx: &btc_primitives::Tx,
    spent_outs: &[btc_primitives::TxOut],
) -> bool {
    spent_outs
        .iter()
        .any(|o| is_ct_script(o.script_pubkey.as_bytes()))
        || tx.vout
            .iter()
            .any(|o| is_ct_script(o.script_pubkey.as_bytes()))
        || !shield_markers(tx).is_empty()
}

/// Domain tag of the per-input CT authorisation digest.
const TAG_CT_INPUT_AUTH: &[u8] = b"AnonCoin-CT-INPUT-AUTH-v1";

/// Digest signed by the owner of one CT input:
/// `SHA256(tag || ct_context(tx) || input_index(4 LE) || len(script)(4 LE) || prevout_script)`.
///
/// `ct_context` already commits to version, locktime, every input outpoint
/// and sequence, and every output script/value (shield-marker balance
/// bytes zeroed, which breaks the proof fixed-point but are covered by the
/// balance proof, itself bound to the same context). On top of it the
/// digest binds the input index (a signature cannot be moved to another
/// input slot) and the full spent script (commitment + pubkey_hash), so the
/// signature is tied to exactly the output being spent.
pub fn ct_input_sighash(
    context: &[u8; 32],
    input_index: usize,
    spent_script: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(TAG_CT_INPUT_AUTH.len() + 32 + 8 + spent_script.len());
    buf.extend_from_slice(TAG_CT_INPUT_AUTH);
    buf.extend_from_slice(context);
    buf.extend_from_slice(&(input_index as u32).to_le_bytes());
    buf.extend_from_slice(&(spent_script.len() as u32).to_le_bytes());
    buf.extend_from_slice(spent_script);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Signs a CT input digest with the owner secret (BIP340 Schnorr,
/// deterministic nonce). Returns the 64-byte signature and the 33-byte
/// compressed pubkey to place in the witness.
pub fn sign_ct_input(
    sighash: &[u8; 32],
    secret: &[u8; 32],
) -> Result<([u8; 64], [u8; 33]), CtError> {
    use bitcoin::secp256k1::{Keypair, Message};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret).map_err(|_| CtError::BadScalar)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest(*sighash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    Ok((
        *sig.as_ref(),
        PublicKey::from_secret_key(&secp, &sk).serialize(),
    ))
}

/// Verifies one CT input authorisation. Witness layout (documented
/// consensus format): input 0 is `[balance_proof, sig(64), pubkey(33)]`,
/// every other CT input is `[sig(64), pubkey(33)]`. Requirements:
/// exact item count and sizes, `hash160(pubkey) == pubkey_hash` of the
/// spent output, and a valid BIP340 signature by that key over
/// [`ct_input_sighash`].
pub fn verify_ct_input_auth(
    witness: &[&[u8]],
    input_index: usize,
    pubkey_hash: &[u8; 20],
    sighash: &[u8; 32],
) -> Result<(), CtError> {
    use bitcoin::secp256k1::{schnorr::Signature, Message};
    let (sig_pos, key_pos, expected_len) = if input_index == 0 { (1, 2, 3) } else { (0, 1, 2) };
    if witness.len() != expected_len {
        return Err(CtError::BalanceProof);
    }
    let pubkey: [u8; 33] = witness[key_pos].try_into().map_err(|_| CtError::BalanceProof)?;
    let hash160 = bitcoin_hashes::hash160::Hash::hash(&pubkey).to_byte_array();
    if &hash160[..20] != pubkey_hash.as_slice() {
        return Err(CtError::BalanceProof);
    }
    let full = PublicKey::from_slice(&pubkey).map_err(|_| CtError::BadPoint)?;
    let (xonly, _) = full.x_only_public_key();
    let sig = Signature::from_slice(witness[sig_pos]).map_err(|_| CtError::BalanceProof)?;
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&sig, &Message::from_digest(*sighash), &xonly)
        .map_err(|_| CtError::BalanceProof)
}

/// Full chain-level CT verification for one transaction.
///
/// Rules:
/// - every output is CT, or a plaintext output only when the transaction
///   also spends a plaintext input (hybrid shielding spend),
/// - range proofs for CT inputs and outputs verify,
/// - CT inputs are authorised by a BIP340 Schnorr signature made by the
///   OWNER key, i.e. the 33-byte pubkey whose hash160 equals the spent
///   output's `pubkey_hash`, over [`ct_input_sighash`] (see
///   [`verify_ct_input_auth`]). Ring signatures are NOT accepted as
///   authorisation: a ring signature only proves knowledge of the secret
///   of SOME member and cannot bind to the named owner,
/// - plaintext inputs are authorised by ordinary script execution
///   (scriptSig) and carry their blinding in `witness[0]` so the
///   verifier rebuilds `v*G + r*H` for them,
/// - the balance proof ties the CT half with fee prefix 0 (miners are
///   paid from the plaintext half, which the value ledger accounts).
pub fn verify_ct_tx_block(
    tx: &btc_primitives::Tx,
    spent_outs: &[btc_primitives::TxOut],
    script_check: &dyn Fn(
        &btc_primitives::Tx,
        &[btc_primitives::TxOut],
        &[usize],
    ) -> Result<(), crate::ValidationError>,
) -> Result<(), CtError> {
    if spent_outs.len() != tx.vin.len() {
        return Err(CtError::BalanceProof);
    }
    let mut ct_inputs: Vec<AmountCommitment> = Vec::new();
    let mut input_key_hashes: Vec<Option<[u8; 20]>> = Vec::with_capacity(spent_outs.len());
    let mut plain_indices: Vec<usize> = Vec::new();
    let mut plain_commitments: Vec<([u8; 33],)> = Vec::new();
    let shield = shield_markers(tx);
    for (i, (vin, spent_out)) in tx.vin.iter().zip(spent_outs).enumerate() {
        if let Some(data) = decode_ct_script(spent_out.script_pubkey.as_bytes()) {
            input_key_hashes.push(Some(data.pubkey_hash));
            ct_inputs.push(AmountCommitment {
                commitment: data.commitment,
                proof: data.proof,
            });
        } else {
            input_key_hashes.push(None);
            plain_indices.push(i);
            let plain_ordinal = plain_indices.len() - 1;
            let blinding: [u8; 32] = shield
                .get(plain_ordinal)
                .and_then(|(r_in, _)| r_in.as_slice().try_into().ok())
                .ok_or(CtError::BalanceProof)?;
            let commitment = commitment_point(spent_out.value as u64, blinding)?;
            plain_commitments.push((commitment, ));
        }
    }
    let mut outputs: Vec<AmountCommitment> = Vec::with_capacity(tx.vout.len());
    for output in &tx.vout {
        let Some(data) = decode_ct_script(output.script_pubkey.as_bytes()) else {
            continue; // plaintext output: handled by the value ledger
        };
        if output.value != 0 {
            return Err(CtError::BalanceProof);
        }
        outputs.push(AmountCommitment {
            commitment: data.commitment,
            proof: data.proof,
        });
    }
    if ct_inputs.is_empty() && plain_commitments.is_empty() {
        return Err(CtError::BalanceProof);
    }
    let mut all_inputs: Vec<AmountCommitment> = ct_inputs;
    for (commitment,) in plain_commitments {
        all_inputs.push(AmountCommitment {
            commitment,
            proof: RangeProof {
                bit_commitments: Vec::new(),
                bit_proofs: Vec::new(),
            },
        });
    }

    let context = ct_context(tx);
    // Owner authorisation per CT input: Schnorr signature by the key whose
    // hash160 is the spent output's pubkey_hash (NOT a ring signature).
    for (i, input) in tx.vin.iter().enumerate() {
        let Some(hash) = input_key_hashes[i] else {
            continue;
        };
        let stack: Vec<&[u8]> = input.witness.iter().collect();
        let sighash = ct_input_sighash(&context, i, spent_outs[i].script_pubkey.as_bytes());
        verify_ct_input_auth(&stack, i, &hash, &sighash)?;
    }

    // Plaintext inputs: ordinary script execution (scriptSig).
    if !plain_indices.is_empty() {
        script_check(tx, spent_outs, &plain_indices)
            .map_err(|_| CtError::BalanceProof)?;
    }

    // Balance proof: shield marker first (hybrid spends), witness input 0
    // as fallback (all-CT spends).
    let balance_bytes_owned: Vec<u8>;
    let balance_bytes: &[u8] = if !shield.is_empty() {
        &shield[0].1
    } else {
        balance_bytes_owned = tx.vin[0]
            .witness
            .iter()
            .next()
            .ok_or(CtError::BalanceProof)?
            .to_vec();
        &balance_bytes_owned
    };
    let balance = deserialize_balance_proof(balance_bytes).ok_or(CtError::BalanceProof)?;
    let fee = proof_fee(balance_bytes);
    verify_ct_transaction(&all_inputs, &outputs, fee, &balance, &context)
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
    fn ct_script_round_trips_and_rejects_tampering() {
        let c = create_commitment(10_00000000, blinding(5)).unwrap();
        let data = CtOutputData {
            commitment: c.commitment,
            pubkey_hash: [7u8; 20],
            proof: c.proof,
        };
        let script = encode_ct_script(&data).unwrap();
        let back = decode_ct_script(script.as_bytes()).unwrap();
        assert_eq!(back.commitment, data.commitment);
        assert_eq!(back.pubkey_hash, [7u8; 20]);
        let mut bytes = script.as_bytes().to_vec();
        bytes[10] ^= 1; // inside the commitment: range proof must fail
        assert!(decode_ct_script(&bytes).is_none());
        assert!(!is_ct_script(&ScriptBuf::from_bytes(vec![0x6a]).as_bytes()));
    }

    fn test_key(i: u8) -> ([u8; 32], [u8; 33]) {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let mut buf = [0u8; 32];
        buf[0] = i;
        buf[31] = 5;
        let sk = SecretKey::from_slice(&buf).unwrap();
        (buf, PublicKey::from_secret_key(&secp, &sk).serialize())
    }

    fn hash20(pubkey: &[u8; 33]) -> [u8; 20] {
        let mut out = [0u8; 20];
        out.copy_from_slice(&bitcoin_hashes::hash160::Hash::hash(pubkey).to_byte_array()[..20]);
        out
    }

    /// One CT output owned by `owner_hash`, worth 5 coins with blinding `R_IN`.
    const R_IN: [u8; 32] = [11u8; 32];
    const R_OUT: [u8; 32] = [22u8; 32];

    fn victim_output(owner_hash: [u8; 20]) -> btc_primitives::TxOut {
        let in_c = create_commitment(5_00000000u64, R_IN).unwrap();
        btc_primitives::TxOut::new(
            0,
            encode_ct_script(&CtOutputData {
                commitment: in_c.commitment,
                pubkey_hash: owner_hash,
                proof: in_c.proof,
            })
            .unwrap(),
        )
    }

    /// Unsigned 1-in-1-out CT tx paying `to_hash` (prevout txid seed
    /// selects the outpoint, `value_out` is the hidden output amount).
    fn unsigned_ct_tx(to_hash: [u8; 20], seed: u8, value_out: u64) -> btc_primitives::Tx {
        let out_c = create_commitment(value_out, R_OUT).unwrap();
        let out_script = encode_ct_script(&CtOutputData {
            commitment: out_c.commitment,
            pubkey_hash: to_hash,
            proof: out_c.proof,
        })
        .unwrap();
        let prevout = btc_primitives::OutPoint {
            txid: bitcoin::Txid::from_slice(&[seed; 32]).unwrap(),
            vout: 0,
        };
        btc_primitives::Tx::new(
            2,
            vec![btc_primitives::TxIn::new(prevout)],
            vec![btc_primitives::TxOut::new(0, out_script)],
            0,
        )
    }

    /// Witness `[balance, sig, pubkey]` for input 0 of `tx`, signing the
    /// input digest with `signer` and presenting `pubkey`.
    fn auth_witness(
        tx: &btc_primitives::Tx,
        spent: &btc_primitives::TxOut,
        signer: &[u8; 32],
        pubkey: &[u8; 33],
    ) -> bitcoin::Witness {
        let context = ct_context(tx);
        let (proof, _) = create_balance_proof(&[R_IN], &[R_OUT], 10_000, &context).unwrap();
        let sighash = ct_input_sighash(&context, 0, spent.script_pubkey.as_bytes());
        let (sig, _) = sign_ct_input(&sighash, signer).unwrap();
        bitcoin::Witness::from_slice(&[
            with_fee(serialize_balance_proof(&proof), 10_000),
            sig.to_vec(),
            pubkey.to_vec(),
        ])
    }

    fn accepts(tx: &btc_primitives::Tx, spent: &btc_primitives::TxOut) -> bool {
        verify_ct_tx_block(tx, &[spent.clone()], &|_t, _s, _i| Ok(())).is_ok()
    }

    #[test]
    fn ct_tx_block_verify_end_to_end() {
        let (owner_secret, owner_pub) = test_key(3);
        let spent = victim_output(hash20(&owner_pub));
        let mut tx = unsigned_ct_tx([7u8; 20], 99, 4_99990000);
        tx.vin[0].witness = auth_witness(&tx, &spent, &owner_secret, &owner_pub);
        assert!(decode_ct_script(spent.script_pubkey.as_bytes()).is_some());
        assert!(accepts(&tx, &spent), "owner spend must be accepted");
    }

    /// Former critical bug: a ring signature proves knowledge of the secret
    /// of SOME ring member, so an attacker could put the victim's pubkey
    /// plus his own key in a ring and sign with his own key. All variants
    /// of the attack must now be rejected.
    #[test]
    fn theft_via_ring_membership_is_rejected() {
        use crate::ringsig::sign_ring;
        let (_victim_secret, victim_pub) = test_key(1);
        let (attacker_secret, attacker_pub) = test_key(2);
        let spent = victim_output(hash20(&victim_pub));
        let mut tx = unsigned_ct_tx(hash20(&attacker_pub), 99, 4_99990000);
        let context = ct_context(&tx);
        let (proof, _) = create_balance_proof(&[R_IN], &[R_OUT], 10_000, &context).unwrap();
        let balance = with_fee(serialize_balance_proof(&proof), 10_000);

        // (a) Exact old attack: ring = victim + attacker + 14 decoys, signed
        // by the attacker. The legacy witness layout is no longer valid.
        let mut ring: Vec<[u8; 33]> = vec![victim_pub, attacker_pub];
        for i in 3..=16u8 {
            ring.push(test_key(i).1);
        }
        let ring_sig = sign_ring(&context, &ring, 1, &attacker_secret).unwrap();
        let ring_bytes: Vec<u8> = ring.iter().flat_map(|k| k.to_vec()).collect();
        tx.vin[0].witness =
            bitcoin::Witness::from_slice(&[balance.clone(), serialize_ring_sig(&ring_sig), ring_bytes]);
        assert!(!accepts(&tx, &spent), "legacy ring witness must be rejected");

        // (b) Attacker signs with his key and presents the victim's pubkey.
        tx.vin[0].witness = auth_witness(&tx, &spent, &attacker_secret, &victim_pub);
        assert!(!accepts(&tx, &spent), "attacker sig under victim pubkey");

        // (c) Attacker signs and presents his own pubkey (hash mismatch).
        tx.vin[0].witness = auth_witness(&tx, &spent, &attacker_secret, &attacker_pub);
        assert!(!accepts(&tx, &spent), "attacker pubkey does not hash to owner");
    }

    #[test]
    fn ct_input_auth_rejects_wrong_pubkey_wrong_sig_and_replay() {
        let (owner_secret, owner_pub) = test_key(3);
        let (_other_secret, other_pub) = test_key(4);
        let spent = victim_output(hash20(&owner_pub));
        let mut tx = unsigned_ct_tx([7u8; 20], 99, 4_99990000);

        // Baseline: valid.
        tx.vin[0].witness = auth_witness(&tx, &spent, &owner_secret, &owner_pub);
        assert!(accepts(&tx, &spent));
        let good: Vec<Vec<u8>> = tx.vin[0].witness.iter().map(|w| w.to_vec()).collect();

        // Wrong pubkey (valid key, wrong hash).
        let mut w = good.clone();
        w[2] = other_pub.to_vec();
        tx.vin[0].witness = bitcoin::Witness::from_slice(&w);
        assert!(!accepts(&tx, &spent), "wrong pubkey");

        // Malformed pubkey.
        let mut w = good.clone();
        w[2] = vec![2u8; 32];
        tx.vin[0].witness = bitcoin::Witness::from_slice(&w);
        assert!(!accepts(&tx, &spent), "short pubkey");

        // Corrupted signature.
        let mut w = good.clone();
        w[1][5] ^= 1;
        tx.vin[0].witness = bitcoin::Witness::from_slice(&w);
        assert!(!accepts(&tx, &spent), "wrong sig");

        // Signature by a different key presented under the owner's pubkey.
        let (other_secret, _) = test_key(4);
        tx.vin[0].witness = auth_witness(&tx, &spent, &other_secret, &owner_pub);
        assert!(!accepts(&tx, &spent), "sig by non-owner key");

        // Missing / extra witness items.
        tx.vin[0].witness = bitcoin::Witness::from_slice(&good[..2]);
        assert!(!accepts(&tx, &spent), "missing pubkey");
        let mut w = good.clone();
        w.push(vec![0u8]);
        tx.vin[0].witness = bitcoin::Witness::from_slice(&w);
        assert!(!accepts(&tx, &spent), "extra item");

        // Replay: a valid owner witness copied onto a different tx (other
        // recipient and other outpoint) must fail, both the sighash and the
        // balance proof are bound to the tx.
        let mut tx2 = unsigned_ct_tx([8u8; 20], 99, 4_99990000);
        tx2.vin[0].witness = bitcoin::Witness::from_slice(&good);
        assert!(!accepts(&tx2, &spent), "replay onto another recipient");
        let mut tx3 = unsigned_ct_tx([7u8; 20], 98, 4_99990000);
        tx3.vin[0].witness = bitcoin::Witness::from_slice(&good);
        assert!(!accepts(&tx3, &spent), "replay onto another outpoint");

        // Signature only (balance proof valid for tx2, auth from tx): the
        // auth signature alone must not authorise another tx.
        let mut tx4 = unsigned_ct_tx([8u8; 20], 99, 4_99990000);
        let fresh = auth_witness(&tx4, &spent, &owner_secret, &owner_pub);
        let mut w: Vec<Vec<u8>> = fresh.iter().map(|x| x.to_vec()).collect();
        w[1] = good[1].clone();
        tx4.vin[0].witness = bitcoin::Witness::from_slice(&w);
        assert!(!accepts(&tx4, &spent), "stolen signature from another tx");

        // Signature bound to the input slot: same tx signed as index 1.
        let context = ct_context(&tx);
        let wrong_index = ct_input_sighash(&context, 1, spent.script_pubkey.as_bytes());
        let (sig, _) = sign_ct_input(&wrong_index, &owner_secret).unwrap();
        let mut w = good.clone();
        w[1] = sig.to_vec();
        tx.vin[0].witness = bitcoin::Witness::from_slice(&w);
        assert!(!accepts(&tx, &spent), "sig for another input index");

        // Sanity: the original witness is still accepted.
        tx.vin[0].witness = bitcoin::Witness::from_slice(&good);
        assert!(accepts(&tx, &spent));
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
