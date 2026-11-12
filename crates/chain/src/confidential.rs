//! Confidential Transactions (Privacy Plan, Phase 2).
//!
//! Amounts are hidden inside Pedersen commitments
//! `C(v, r) = v*G + r*H`, where `H` is a "nothing up my sleeve" (NUMS)
//! generator: its discrete log with respect to `G` is unknown to everyone
//! (see [`h_generator`]). That independence is what makes commitments
//! *binding*; if anybody knew `h = log_G(H)` then `v*G + r*H =
//! (v + r*h)*G` would open to any value and balance proofs could be
//! forged (unlimited inflation). The earlier `SHA256(..)*G` derivation had
//! exactly that flaw.
//!
//! Each commitment ships a 64-bit range proof: 64 bit commitments
//! `C_i = b_i*G + r_i*H` with `sum 2^i * C_i == C`, and for every bit a
//! two-member ring (Abe-Ohkubo-Suzuki / Borromean-style) OR-proof that
//! `C_i` opens to 0 *or* 1 without revealing which. A transaction
//! additionally ships a balance proof: a Schnorr signature (base `H`) with
//! the witness `sum_in(r) - sum_out(r)` over the point
//! `sum_in(C) - sum_out(C) - fee*G`; it proves the inputs pay for the
//! outputs plus the public fee, so no inflation is possible.
//!
//! Fiat-Shamir challenges are SHA-256 over a domain-separated,
//! length-prefixed transcript. Point arithmetic uses `rust-secp256k1`
//! through the `bitcoin` crate re-export. Every function that handles
//! consensus input returns an error instead of panicking; the point at
//! infinity is handled explicitly (`Option<PublicKey>` with `None` =
//! infinity) so degenerate inputs are rejected deterministically.

use std::sync::OnceLock;

use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin_hashes::{sha256, Hash as _};
use btc_primitives::ScriptBuf;
use thiserror::Error;

pub const VALUE_BITS: usize = 64;

/// Domain string of the NUMS derivation of `H`. `H` is the first valid
/// compressed point `0x02 || x` with
/// `x = SHA256(H_DOMAIN || counter_le32)`, `counter = 0, 1, 2, ...`
/// (try-and-increment hash-to-curve). Nobody knows `log_G(H)` because `x`
/// is the output of a hash that was not chosen as a multiple of `G`.
pub const H_DOMAIN: &[u8] = b"AnonCoin-H-v2";

/// The derived `H` (compressed SEC1), hardcoded so a derivation bug can
/// never silently change consensus; a test re-derives it from
/// [`H_DOMAIN`] and asserts equality.
/// Derivation result: counter 0 is not a valid x-coordinate, counter 1 is
/// (x = 5bc06fba...14bf).
pub const H_COMPRESSED: [u8; 33] = [
    0x02, 0x5b, 0xc0, 0x6f, 0xba, 0x2c, 0x84, 0x0e, 0x90, 0xed, 0xec,
    0xde, 0x0b, 0x1e, 0x21, 0x37, 0x43, 0x07, 0xd1, 0x4f, 0x02, 0x0f,
    0xea, 0xfd, 0x4e, 0xbe, 0x6f, 0x23, 0x39, 0xff, 0xb1, 0x14, 0xbf
];

const TRANSCRIPT_RANGE: &[u8] = b"AnonCoin-CT-RANGE-v2";
const TRANSCRIPT_BALANCE: &[u8] = b"AnonCoin-CT-BALANCE-v2";

/// Serialized size of one range proof: 64 bit commitments (33 bytes each)
/// followed by 64 ring proofs `e0 || z0 || z1` (96 bytes each).
pub const RANGE_PROOF_BYTES: usize = VALUE_BITS * (33 + 96);

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

fn secp() -> &'static Secp256k1<All> {
    static CTX: OnceLock<Secp256k1<All>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::new)
}

/// Re-derives `H` from [`H_DOMAIN`] by try-and-increment.
pub fn derive_h_nums() -> PublicKey {
    let mut counter: u32 = 0;
    loop {
        let mut preimage = Vec::with_capacity(H_DOMAIN.len() + 4);
        preimage.extend_from_slice(H_DOMAIN);
        preimage.extend_from_slice(&counter.to_le_bytes());
        let x = sha256::Hash::hash(&preimage);
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(x.as_ref());
        if let Ok(point) = PublicKey::from_slice(&compressed) {
            return point;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Independent (NUMS) generator `H`. Parsed from the hardcoded constant;
/// falls back to the (identical) derivation only if the constant were
/// ever malformed.
fn h_generator() -> PublicKey {
    static H: OnceLock<PublicKey> = OnceLock::new();
    *H.get_or_init(|| PublicKey::from_slice(&H_COMPRESSED).unwrap_or_else(|_| derive_h_nums()))
}

/// The standard generator `G`.
fn g_generator() -> PublicKey {
    static G: OnceLock<PublicKey> = OnceLock::new();
    *G.get_or_init(|| {
        let mut one = [0u8; 32];
        one[31] = 1;
        // 1 is always a valid secret key.
        match SecretKey::from_slice(&one) {
            Ok(sk) => PublicKey::from_secret_key(secp(), &sk),
            Err(_) => derive_h_nums(), // unreachable
        }
    })
}

// ---------------------------------------------------------------------
// Scalar arithmetic on 32-byte big-endian values mod n (zero allowed).
// ---------------------------------------------------------------------

const ZERO: [u8; 32] = [0u8; 32];

fn secret_from_bytes(bytes: [u8; 32]) -> Result<SecretKey, CtError> {
    SecretKey::from_slice(&bytes).map_err(|_| CtError::BadScalar)
}

/// Rejects encodings `>= n`. Zero is accepted.
fn check_scalar(bytes: &[u8; 32]) -> Result<Scalar, CtError> {
    Scalar::from_be_bytes(*bytes).map_err(|_| CtError::BadScalar)
}

fn scalar_neg(a: &[u8; 32]) -> Result<[u8; 32], CtError> {
    check_scalar(a)?;
    if *a == ZERO {
        return Ok(ZERO);
    }
    Ok(secret_from_bytes(*a)?.negate().secret_bytes())
}

/// `(a + b) mod n`; zero is the identity and a zero result is legal.
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], CtError> {
    check_scalar(a)?;
    let b_scalar = check_scalar(b)?;
    if *a == ZERO {
        return Ok(*b);
    }
    if *b == ZERO {
        return Ok(*a);
    }
    let a_sk = secret_from_bytes(*a)?;
    if a_sk.negate().secret_bytes() == *b {
        return Ok(ZERO);
    }
    Ok(a_sk.add_tweak(&b_scalar).map_err(|_| CtError::BadScalar)?.secret_bytes())
}

/// `(a - b) mod n`.
fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], CtError> {
    scalar_add(a, &scalar_neg(b)?)
}

/// `(a * b) mod n`; a zero result is legal.
fn scalar_mul_bytes(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], CtError> {
    check_scalar(a)?;
    let b_scalar = check_scalar(b)?;
    if *a == ZERO || *b == ZERO {
        return Ok(ZERO);
    }
    let a_sk = secret_from_bytes(*a)?;
    Ok(a_sk.mul_tweak(&b_scalar).map_err(|_| CtError::BadScalar)?.secret_bytes())
}

fn u64_to_scalar(value: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&value.to_be_bytes());
    buf
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

/// Scalar in `[1, n)`: SHA-256 over a length-prefixed transcript, retried
/// with a counter until it is a valid secret scalar.
fn challenge_scalar(parts: &[&[u8]]) -> [u8; 32] {
    let mut counter = 0u8;
    loop {
        let mut buf = Vec::with_capacity(1 + parts.iter().map(|p| p.len() + 4).sum::<usize>());
        buf.push(counter);
        for part in parts {
            buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
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

// ---------------------------------------------------------------------
// Point arithmetic. `None` is the point at infinity.
// ---------------------------------------------------------------------

type Pt = Option<PublicKey>;

fn parse_point(bytes: &[u8; 33]) -> Result<PublicKey, CtError> {
    PublicKey::from_slice(bytes).map_err(|_| CtError::BadPoint)
}

/// `scalar * point`; zero scalar or infinity point give infinity.
fn mul_opt(point: Pt, scalar: &[u8; 32]) -> Result<Pt, CtError> {
    let scalar_checked = check_scalar(scalar)?;
    let Some(p) = point else { return Ok(None) };
    if *scalar == ZERO {
        return Ok(None);
    }
    p.mul_tweak(secp(), &scalar_checked)
        .map(Some)
        .map_err(|_| CtError::BadPoint)
}

fn add_opt(a: Pt, b: Pt) -> Pt {
    match (a, b) {
        (None, x) | (x, None) => x,
        // `combine` fails only when the sum is the point at infinity.
        (Some(x), Some(y)) => x.combine(&y).ok(),
    }
}

fn neg_opt(p: Pt) -> Pt {
    p.map(|p| p.negate(secp()))
}

/// Compressed encoding, or an error for the point at infinity.
fn ser(p: Pt) -> Result<[u8; 33], CtError> {
    Ok(p.ok_or(CtError::BadPoint)?.serialize())
}

pub fn commitment_point(value: u64, blinding: [u8; 32]) -> Result<[u8; 33], CtError> {
    secret_from_bytes(blinding)?; // blinding must be in [1, n)
    let r_h = mul_opt(Some(h_generator()), &blinding)?;
    let v_g = mul_opt(Some(g_generator()), &u64_to_scalar(value))?;
    ser(add_opt(r_h, v_g))
}

/// `Sum_i 2^i * C_i` by Horner evaluation.
fn weighted_sum(points: &[Pt]) -> Pt {
    let mut acc: Pt = None;
    for p in points.iter().rev() {
        acc = add_opt(add_opt(acc, acc), *p);
    }
    acc
}

// ---------------------------------------------------------------------
// Range proof
// ---------------------------------------------------------------------

/// One bit proof: a two-member ring signature (AOS) over the statements
/// `P0 = C_i = r*H` (bit 0) and `P1 = C_i - G = r*H` (bit 1) with base
/// `H`. The verifier recomputes
/// `R0 = z0*H - e0*P0`, `e1 = Hash(R0, branch 0)`,
/// `R1 = z1*H - e1*P1`, `e0' = Hash(R1, branch 1)` and requires
/// `e0' == e0`. Both branches use the bit commitment `C_i`, the chain of
/// challenges is the Fiat-Shamir split of a single challenge between the
/// two branches (an unsimulated branch needs the dlog of `C_i` or
/// `C_i - G` w.r.t. `H`), and the proof is witness-indistinguishable: it
/// does not reveal which branch is real, hence not the bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitProof {
    pub e0: [u8; 32],
    pub z0: [u8; 32],
    pub z1: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeProof {
    pub bit_commitments: Vec<[u8; 33]>,
    pub bit_proofs: Vec<BitProof>,
}

/// Commits `value` with blinding `R` and proves `value < 2^64`.
pub fn prove_range(value: u64, blinding: [u8; 32]) -> Result<RangeProof, CtError> {
    prove_range_with_blinding(value, blinding)
}

/// Digest of the full set of bit commitments (transcript binding).
fn bits_digest(bit_commitments: &[[u8; 33]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(bit_commitments.len() * 33);
    for c in bit_commitments {
        buf.extend_from_slice(c);
    }
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Challenge of one bit ring step. Binds the domain, the total commitment,
/// all bit commitments (through their digest), the bit index, this bit's
/// commitment, the ring point `R` and the branch number.
fn bit_challenge(
    total: &[u8; 33],
    digest: &[u8; 32],
    index: usize,
    bit_commitment: &[u8; 33],
    ring_point: &[u8; 33],
    branch: u8,
) -> [u8; 32] {
    challenge_scalar(&[
        TRANSCRIPT_RANGE,
        total,
        digest,
        &(index as u32).to_le_bytes(),
        bit_commitment,
        ring_point,
        &[branch],
    ])
}

/// `z*H - e*P`.
fn ring_point(z: &[u8; 32], e: &[u8; 32], p: Pt) -> Result<Pt, CtError> {
    let z_h = mul_opt(Some(h_generator()), z)?;
    let e_p = mul_opt(p, &scalar_neg(e)?)?;
    Ok(add_opt(z_h, e_p))
}

/// Range proof for `C = value*G + blinding*H`. The bit blindings are
/// fresh random scalars constrained so that `sum 2^i r_i = blinding`
/// (bit 0 absorbs the remainder), tying the proof to `C`.
pub fn prove_range_with_blinding(value: u64, blinding: [u8; 32]) -> Result<RangeProof, CtError> {
    secret_from_bytes(blinding)?;
    let total = commitment_point(value, blinding)?;
    let h = Some(h_generator());
    let g = Some(g_generator());
    let neg_g = neg_opt(g);

    // r_1..r_63 random; r_0 = R - sum_{i>=1} 2^i r_i.
    let mut r = [ZERO; VALUE_BITS];
    let mut rest = ZERO; // sum_{i>=1} 2^i r_i via Horner (r_0 slot is 0)
    for i in (1..VALUE_BITS).rev() {
        r[i] = random_scalar()?;
        rest = scalar_add(&scalar_add(&rest, &rest)?, &r[i])?;
    }
    rest = scalar_add(&rest, &rest)?; // multiply by 2 for the missing r_0 slot
    r[0] = scalar_sub(&blinding, &rest)?;
    if r[0] == ZERO {
        return Err(CtError::BadScalar); // negligible-probability retry case
    }

    let mut bit_commitments = Vec::with_capacity(VALUE_BITS);
    let mut bits = [0u8; VALUE_BITS];
    for i in 0..VALUE_BITS {
        bits[i] = ((value >> i) & 1) as u8;
        let mut c = mul_opt(h, &r[i])?;
        if bits[i] == 1 {
            c = add_opt(c, g);
        }
        bit_commitments.push(ser(c)?);
    }
    let digest = bits_digest(&bit_commitments);

    let mut bit_proofs = Vec::with_capacity(VALUE_BITS);
    for i in 0..VALUE_BITS {
        let c_bytes = bit_commitments[i];
        let c = Some(parse_point(&c_bytes)?);
        let p0 = c;
        let p1 = add_opt(c, neg_g);
        let k = random_scalar()?;
        let z_sim = random_scalar()?;
        let proof = if bits[i] == 0 {
            // Real branch 0: R0 = k*H. Simulate branch 1 with random z1.
            let r0 = ser(mul_opt(h, &k)?)?;
            let e1 = bit_challenge(&total, &digest, i, &c_bytes, &r0, 0);
            let r1 = ser(ring_point(&z_sim, &e1, p1)?)?;
            let e0 = bit_challenge(&total, &digest, i, &c_bytes, &r1, 1);
            let z0 = scalar_add(&k, &scalar_mul_bytes(&e0, &r[i])?)?;
            BitProof { e0, z0, z1: z_sim }
        } else {
            // Real branch 1: R1 = k*H. Simulate branch 0 with random z0.
            let r1 = ser(mul_opt(h, &k)?)?;
            let e0 = bit_challenge(&total, &digest, i, &c_bytes, &r1, 1);
            let r0 = ser(ring_point(&z_sim, &e0, p0)?)?;
            let e1 = bit_challenge(&total, &digest, i, &c_bytes, &r0, 0);
            let z1 = scalar_add(&k, &scalar_mul_bytes(&e1, &r[i])?)?;
            BitProof { e0, z0: z_sim, z1 }
        };
        bit_proofs.push(proof);
    }
    Ok(RangeProof {
        bit_commitments,
        bit_proofs,
    })
}

/// Verifies one bit proof.
fn verify_bit(
    total: &[u8; 33],
    digest: &[u8; 32],
    index: usize,
    c_bytes: &[u8; 33],
    bp: &BitProof,
) -> Result<(), CtError> {
    let c = Some(parse_point(c_bytes).map_err(|_| CtError::RangeProof)?);
    let p0 = c;
    let p1 = add_opt(c, neg_opt(Some(g_generator())));
    let r0 = ser(ring_point(&bp.z0, &bp.e0, p0).map_err(|_| CtError::RangeProof)?)
        .map_err(|_| CtError::RangeProof)?;
    let e1 = bit_challenge(total, digest, index, c_bytes, &r0, 0);
    let r1 = ser(ring_point(&bp.z1, &e1, p1).map_err(|_| CtError::RangeProof)?)
        .map_err(|_| CtError::RangeProof)?;
    let e0 = bit_challenge(total, digest, index, c_bytes, &r1, 1);
    if e0 != bp.e0 {
        return Err(CtError::RangeProof);
    }
    Ok(())
}

/// Verifies `commitment == sum_i 2^i * C_i` and every bit proof. Anything
/// but exactly [`VALUE_BITS`] bit commitments and proofs is rejected.
pub fn verify_range(commitment: &[u8; 33], proof: &RangeProof) -> Result<(), CtError> {
    if proof.bit_commitments.len() != VALUE_BITS || proof.bit_proofs.len() != VALUE_BITS {
        return Err(CtError::RangeProof);
    }
    parse_point(commitment).map_err(|_| CtError::RangeProof)?;
    let mut points: Vec<Pt> = Vec::with_capacity(VALUE_BITS);
    for c in &proof.bit_commitments {
        points.push(Some(parse_point(c).map_err(|_| CtError::RangeProof)?));
    }
    match weighted_sum(&points) {
        Some(sum) if sum.serialize() == *commitment => {}
        _ => return Err(CtError::RangeProof),
    }
    let digest = bits_digest(&proof.bit_commitments);
    for (i, (c_bytes, bp)) in proof.bit_commitments.iter().zip(&proof.bit_proofs).enumerate() {
        verify_bit(commitment, &digest, i, c_bytes, bp)?;
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

// ---------------------------------------------------------------------
// Balance proof
// ---------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceProof {
    pub r_pub: [u8; 33],
    pub z: [u8; 32],
}

/// Transcript of the balance Schnorr proof: domain, transaction context,
/// the balance point `C_bal` and the nonce point `R`. The public fee is
/// bound through `C_bal = sum_in - sum_out - fee*G` (a different fee gives
/// a different point), so it is not hashed separately.
fn balance_challenge(context: &[u8], c_bal: &[u8; 33], r_pub: &[u8; 33]) -> [u8; 32] {
    challenge_scalar(&[TRANSCRIPT_BALANCE, context, c_bal, r_pub])
}

/// Proves `sum_in - sum_out - fee*G = D*H` with `D = R_in - R_out`.
/// A zero `D` (the point at infinity) cannot be proven and is an error.
/// The prover only needs the blindings: the fee enters the statement on
/// the verifier side (`fee*G` is subtracted from the commitment sum), so
/// the proof verifies exactly for the fee the amounts actually leave
/// unaccounted for.
pub fn create_balance_proof(
    input_blindings: &[[u8; 32]],
    output_blindings: &[[u8; 32]],
    _fee: u64,
    context: &[u8],
) -> Result<(BalanceProof, [u8; 33]), CtError> {
    let diff = blinding_difference(input_blindings, output_blindings)?;
    let c_bal = ser(mul_opt(Some(h_generator()), &diff)?)?;
    let k = random_scalar()?;
    let r_pub = ser(mul_opt(Some(h_generator()), &k)?)?;
    let e = balance_challenge(context, &c_bal, &r_pub);
    let z = scalar_add(&k, &scalar_mul_bytes(&e, &diff)?)?;
    Ok((BalanceProof { r_pub, z }, c_bal))
}

fn blinding_difference(inputs: &[[u8; 32]], outputs: &[[u8; 32]]) -> Result<[u8; 32], CtError> {
    let mut acc = ZERO;
    for b in inputs {
        acc = scalar_add(&acc, b)?;
    }
    for b in outputs {
        acc = scalar_sub(&acc, b)?;
    }
    Ok(acc)
}

/// Full confidential transaction verification: range proofs, the
/// commitment sum linking range proofs to `C`, and the balance proof.
///
/// Range-proof policy:
/// - every OUTPUT must carry a complete, valid 64-bit range proof; an
///   empty or short proof is rejected;
/// - an INPUT with a completely empty proof is a verifier-rebuilt
///   plaintext-derived commitment (`v*G + r*H` for a spent plaintext
///   coin whose value the ledger already range-checked) and is exempt.
///   Inputs that come from CT scripts always carry a full proof because
///   [`decode_ct_script`] cannot return anything else. Any non-empty
///   input proof must verify completely.
pub fn verify_ct_transaction(
    inputs: &[AmountCommitment],
    outputs: &[AmountCommitment],
    fee: u64,
    balance_proof: &BalanceProof,
    context: &[u8],
) -> Result<(), CtError> {
    if inputs.is_empty() {
        return Err(CtError::BalanceProof);
    }
    for commitment in inputs {
        let plaintext_derived = commitment.proof.bit_commitments.is_empty()
            && commitment.proof.bit_proofs.is_empty();
        if plaintext_derived {
            parse_point(&commitment.commitment)?;
        } else {
            verify_range(&commitment.commitment, &commitment.proof)?;
        }
    }
    for commitment in outputs {
        verify_range(&commitment.commitment, &commitment.proof)?;
    }
    // sum_in(C) - sum_out(C) - fee*G must equal the balance proof's point.
    let mut acc: Pt = None;
    for commitment in inputs {
        acc = add_opt(acc, Some(parse_point(&commitment.commitment)?));
    }
    for commitment in outputs {
        acc = add_opt(acc, neg_opt(Some(parse_point(&commitment.commitment)?)));
    }
    let fee_g = mul_opt(Some(g_generator()), &u64_to_scalar(fee))?;
    acc = add_opt(acc, neg_opt(fee_g));
    // Point at infinity: no valid proof of knowledge exists; reject.
    let c_bal_point = acc.ok_or(CtError::BalanceProof)?;
    let c_bal = c_bal_point.serialize();
    let r_pub = parse_point(&balance_proof.r_pub).map_err(|_| CtError::BalanceProof)?;
    let e = balance_challenge(context, &c_bal, &balance_proof.r_pub);
    // z*H == R + e*C_bal
    let left = mul_opt(Some(h_generator()), &balance_proof.z).map_err(|_| CtError::BalanceProof)?;
    let right = add_opt(
        Some(r_pub),
        mul_opt(Some(c_bal_point), &e).map_err(|_| CtError::BalanceProof)?,
    );
    match (left, right) {
        (Some(l), Some(r)) if l == r => Ok(()),
        _ => Err(CtError::BalanceProof),
    }
}

/// Confidential output script:
/// `OP_RETURN 0x01 <commitment:33> <pubkey_hash:20> PUSHDATA2(<range_proof>)`.
/// Value must be 0 (the amount is hidden in the commitment).
pub struct CtOutputData {
    pub commitment: [u8; 33],
    pub pubkey_hash: [u8; 20],
    pub proof: RangeProof,
}

pub fn encode_ct_script(data: &CtOutputData) -> Result<btc_primitives::ScriptBuf, CtError> {
    if data.proof.bit_commitments.len() != VALUE_BITS || data.proof.bit_proofs.len() != VALUE_BITS {
        return Err(CtError::RangeProof);
    }
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

/// Decodes and fully verifies a CT output script. Only a script carrying
/// a complete, valid 64-bit range proof of exactly [`RANGE_PROOF_BYTES`]
/// bytes decodes; everything else (including empty or short proofs) is
/// `None`.
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
    if verify_range(&commitment, &proof).is_err() {
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
    let mut out = Vec::with_capacity(RANGE_PROOF_BYTES);
    for commitment in &proof.bit_commitments {
        out.extend_from_slice(commitment);
    }
    for bp in &proof.bit_proofs {
        out.extend_from_slice(&bp.e0);
        out.extend_from_slice(&bp.z0);
        out.extend_from_slice(&bp.z1);
    }
    out
}

fn deserialize_range_proof(data: &[u8]) -> Option<RangeProof> {
    if data.len() != RANGE_PROOF_BYTES {
        return None;
    }
    let mut bit_commitments = Vec::with_capacity(VALUE_BITS);
    for i in 0..VALUE_BITS {
        bit_commitments.push(data[i * 33..(i + 1) * 33].try_into().ok()?);
    }
    let mut bit_proofs = Vec::with_capacity(VALUE_BITS);
    let tail = &data[VALUE_BITS * 33..];
    for i in 0..VALUE_BITS {
        let entry = &tail[i * 96..(i + 1) * 96];
        bit_proofs.push(BitProof {
            e0: entry[..32].try_into().ok()?,
            z0: entry[32..64].try_into().ok()?,
            z1: entry[64..].try_into().ok()?,
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
        && u16::from_le_bytes([bytes[2], bytes[3]]) == 106
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
    let mut fee = [0u8; 8];
    fee.copy_from_slice(&data[..8]);
    u64::from_le_bytes(fee)
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
            && u16::from_le_bytes([bytes[2], bytes[3]]) == 106
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
        c.proof.bit_proofs[0].z0[0] ^= 1;
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

    // ---------------------------------------------------------------
    // Regression: inflation attack against the legacy H = h*G (public h).
    // ---------------------------------------------------------------

    /// n - 2 (secp256k1 group order minus two), big-endian: Fermat exponent.
    const N_MINUS_2: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x3F,
    ];

    /// Modular inverse via Fermat exponentiation `x^(n-2) mod n`.
    fn scalar_inverse_for_test(x: &[u8; 32]) -> [u8; 32] {
        let mut result = {
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        };
        let mut base = *x;
        for byte in N_MINUS_2.iter().rev() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = scalar_mul_bytes(&result, &base).unwrap();
                }
                base = scalar_mul_bytes(&base, &base).unwrap();
            }
        }
        result
    }

    fn u64_scalar(v: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&v.to_be_bytes());
        b
    }

    /// Builds the forged transaction: spends a value-10 input into a
    /// value-10^15 output (with a perfectly valid range proof) and signs the
    /// balance proof with the witness `d' = (r_in - r_out) + dv * h^-1` that
    /// only exists if the attacker knows `h = log_G(H)` of the *legacy* H.
    fn forge_with_legacy_h() -> Result<(), CtError> {
        let legacy_h: [u8; 32] = sha256::Hash::hash(b"AnonCoin-H-v1").to_byte_array();
        let h_inv = scalar_inverse_for_test(&legacy_h);
        let (v_in, v_out, fee) = (10u64, 1_000_000_000_000_000u64, 0u64);
        let (r_in, r_out) = (blinding(41), blinding(42));
        let input = create_commitment(v_in, r_in).unwrap();
        let output = create_commitment(v_out, r_out).unwrap();
        // dv = v_in - v_out - fee (mod n)  =  -(v_out + fee - v_in)
        let dv_neg = u64_scalar(v_out + fee - v_in);
        let dv = secret_from_bytes(dv_neg).unwrap().negate().secret_bytes();
        let dr = scalar_sub(&r_in, &r_out).unwrap();
        let witness = scalar_add(&dr, &scalar_mul_bytes(&dv, &h_inv).unwrap()).unwrap();
        // The balance prover signs `witness*H`; it only matches the real
        // sum_in - sum_out - fee*G when H = h*G with h known.
        let (proof, _) = create_balance_proof(&[witness], &[], fee as u64, b"forge-ctx").unwrap();
        verify_ct_transaction(&[input], &[output], fee, &proof, b"forge-ctx")
    }

    #[test]
    fn exploit_inflation_via_public_dlog_of_h_is_rejected() {
        // 10 coins in, 10^15 out. Must NOT verify.
        assert_eq!(
            forge_with_legacy_h(),
            Err(CtError::BalanceProof),
            "inflation forgery must be rejected: log_G(H) must be unknown"
        );
    }

    // ---------------------------------------------------------------
    // NUMS generator
    // ---------------------------------------------------------------

    #[test]
    fn h_constant_matches_nums_derivation() {
        assert_eq!(derive_h_nums().serialize(), H_COMPRESSED);
        assert_eq!(h_generator().serialize(), H_COMPRESSED);
        assert_ne!(h_generator(), g_generator());
        // Not the old SHA256-multiple-of-G generator.
        let old = sha256::Hash::hash(b"AnonCoin-H-v1").to_byte_array();
        let old_h = PublicKey::from_secret_key(secp(), &SecretKey::from_slice(&old).unwrap());
        assert_ne!(h_generator(), old_h);
        assert_eq!(H_DOMAIN, b"AnonCoin-H-v2");
    }

    // ---------------------------------------------------------------
    // Range proof soundness
    // ---------------------------------------------------------------

    #[test]
    fn range_proof_edge_values_round_trip() {
        for v in [0u64, 1, 2, u64::MAX, 1 << 63, 21_000_000 * 100_000_000] {
            let c = create_commitment(v, blinding(50)).unwrap();
            verify_range(&c.commitment, &c.proof).unwrap();
            assert_eq!(c.commitment, commitment_point(v, blinding(50)).unwrap());
        }
    }

    #[test]
    fn every_bit_proof_field_is_enforced() {
        let c = create_commitment(0xDEAD_BEEF, blinding(51)).unwrap();
        for i in [0usize, 1, 31, 63] {
            for field in 0..3 {
                let mut bad = c.proof.clone();
                match field {
                    0 => bad.bit_proofs[i].e0[5] ^= 1,
                    1 => bad.bit_proofs[i].z0[5] ^= 1,
                    _ => bad.bit_proofs[i].z1[5] ^= 1,
                }
                assert!(verify_range(&c.commitment, &bad).is_err(), "bit {i} field {field}");
            }
        }
    }

    #[test]
    fn challenge_chain_is_enforced_by_e0() {
        // A fresh e0 breaks the closure e0' == e0.
        let c = create_commitment(77, blinding(52)).unwrap();
        let mut bad = c.proof.clone();
        bad.bit_proofs[3].e0 = random_scalar().unwrap();
        assert_eq!(verify_range(&c.commitment, &bad), Err(CtError::RangeProof));
        // Out-of-range scalar encodings are rejected, not reduced.
        let mut bad = c.proof.clone();
        bad.bit_proofs[3].z0 = [0xFF; 32];
        assert!(verify_range(&c.commitment, &bad).is_err());
    }

    #[test]
    fn out_of_range_bit_commitment_is_rejected() {
        // Attacker bumps bit commitment 5 by 2*G (the "bit" would be 2) and
        // shifts the total commitment so the weighted sum still holds.
        let c = create_commitment(0, blinding(53)).unwrap();
        let g = Some(g_generator());
        let two_g = add_opt(g, g);
        let c5 = add_opt(Some(parse_point(&c.proof.bit_commitments[5]).unwrap()), two_g);
        let mut bad = c.proof.clone();
        bad.bit_commitments[5] = ser(c5).unwrap();
        let points: Vec<Pt> = bad
            .bit_commitments
            .iter()
            .map(|b| Some(parse_point(b).unwrap()))
            .collect();
        let total = ser(weighted_sum(&points)).unwrap();
        assert_eq!(verify_range(&total, &bad), Err(CtError::RangeProof));
    }

    #[test]
    fn negative_value_wrap_is_rejected() {
        // Shift C of a zero-value proof by -G (value -1 mod n).
        let c = create_commitment(0, blinding(54)).unwrap();
        let minus_g = neg_opt(Some(g_generator()));
        let shifted = ser(add_opt(Some(parse_point(&c.commitment).unwrap()), minus_g)).unwrap();
        assert!(verify_range(&shifted, &c.proof).is_err());
    }

    #[test]
    fn bit_commitment_sum_is_checked() {
        let c = create_commitment(0b1010, blinding(55)).unwrap();
        let mut swapped = c.proof.clone();
        swapped.bit_commitments.swap(0, 1);
        swapped.bit_proofs.swap(0, 1);
        assert!(verify_range(&c.commitment, &swapped).is_err());
        // Another valid proof (different value) cannot be grafted onto C.
        let other = create_commitment(0b0101, blinding(56)).unwrap();
        assert!(verify_range(&c.commitment, &other.proof).is_err());
    }

    #[test]
    fn range_proof_is_bound_to_total_commitment() {
        let c = create_commitment(5, blinding(57)).unwrap();
        let g = Some(g_generator());
        let shifted = ser(add_opt(Some(parse_point(&c.commitment).unwrap()), g)).unwrap();
        assert!(verify_range(&shifted, &c.proof).is_err());
    }

    #[test]
    fn short_or_empty_range_proofs_are_rejected() {
        let c = create_commitment(9, blinding(58)).unwrap();
        let empty = RangeProof { bit_commitments: vec![], bit_proofs: vec![] };
        assert!(verify_range(&c.commitment, &empty).is_err());
        let mut short = c.proof.clone();
        short.bit_commitments.pop();
        short.bit_proofs.pop();
        assert!(verify_range(&c.commitment, &short).is_err());
        let mut long = c.proof.clone();
        long.bit_commitments.push(long.bit_commitments[0]);
        long.bit_proofs.push(long.bit_proofs[0].clone());
        assert!(verify_range(&c.commitment, &long).is_err());
    }

    #[test]
    fn garbage_points_error_instead_of_panicking() {
        let c = create_commitment(9, blinding(59)).unwrap();
        assert!(verify_range(&[0u8; 33], &c.proof).is_err());
        let mut bad = c.proof.clone();
        bad.bit_commitments[7] = [0u8; 33];
        assert!(verify_range(&c.commitment, &bad).is_err());
        let proof = BalanceProof { r_pub: [0u8; 33], z: [0xFF; 32] };
        assert!(verify_ct_transaction(&[c.clone()], &[c.clone()], 0, &proof, b"x").is_err());
        assert!(commitment_point(1, [0u8; 32]).is_err());
        assert!(commitment_point(1, [0xFF; 32]).is_err());
    }

    // ---------------------------------------------------------------
    // CT script decoding: only full 64-bit proofs
    // ---------------------------------------------------------------

    fn script_with_proof_bytes(commitment: [u8; 33], proof_bytes: &[u8]) -> Vec<u8> {
        let mut buf = vec![0x6a, 0x01];
        buf.extend_from_slice(&commitment);
        buf.extend_from_slice(&[7u8; 20]);
        push_data(&mut buf, proof_bytes);
        buf
    }

    #[test]
    fn ct_script_size_is_below_script_limit() {
        let c = create_commitment(1, blinding(60)).unwrap();
        let script = encode_ct_script(&CtOutputData {
            commitment: c.commitment,
            pubkey_hash: [1u8; 20],
            proof: c.proof,
        })
        .unwrap();
        assert_eq!(script.as_bytes().len(), 2 + 33 + 20 + 3 + RANGE_PROOF_BYTES);
        assert!(script.as_bytes().len() <= 10_000);
    }

    #[test]
    fn decode_rejects_empty_short_and_long_proofs() {
        let c = create_commitment(3, blinding(61)).unwrap();
        let full = serialize_range_proof(&c.proof);
        assert!(decode_ct_script(&script_with_proof_bytes(c.commitment, &full)).is_some());
        // Empty proof.
        assert!(decode_ct_script(&script_with_proof_bytes(c.commitment, &[])).is_none());
        // Missing push entirely.
        let mut no_push = vec![0x6a, 0x01];
        no_push.extend_from_slice(&c.commitment);
        no_push.extend_from_slice(&[7u8; 20]);
        assert!(decode_ct_script(&no_push).is_none());
        // 63 bits only.
        let short = &full[..full.len() - 96];
        assert!(decode_ct_script(&script_with_proof_bytes(c.commitment, short)).is_none());
        // Trailing byte.
        let mut long = full.clone();
        long.push(0);
        assert!(decode_ct_script(&script_with_proof_bytes(c.commitment, &long)).is_none());
        // Proof for the wrong commitment.
        let other = create_commitment(4, blinding(62)).unwrap();
        assert!(decode_ct_script(&script_with_proof_bytes(other.commitment, &full)).is_none());
        // Truncated scripts never panic.
        let script = script_with_proof_bytes(c.commitment, &full);
        for n in 0..70 {
            assert!(decode_ct_script(&script[..n]).is_none());
        }
    }

    #[test]
    fn encode_rejects_incomplete_proof() {
        let c = create_commitment(3, blinding(63)).unwrap();
        let mut proof = c.proof.clone();
        proof.bit_commitments.clear();
        proof.bit_proofs.clear();
        assert!(encode_ct_script(&CtOutputData {
            commitment: c.commitment,
            pubkey_hash: [0u8; 20],
            proof,
        })
        .is_err());
    }

    // ---------------------------------------------------------------
    // verify_ct_transaction: range-proof policy
    // ---------------------------------------------------------------

    fn empty_proof() -> RangeProof {
        RangeProof { bit_commitments: Vec::new(), bit_proofs: Vec::new() }
    }

    #[test]
    fn output_with_empty_range_proof_is_rejected() {
        // Balanced on paper (10 in = 10 out), but the output has no range proof.
        let (r_in, r_out) = (blinding(64), blinding(65));
        let input = create_commitment(10, r_in).unwrap();
        let output = AmountCommitment {
            commitment: commitment_point(10, r_out).unwrap(),
            proof: empty_proof(),
        };
        let (proof, _) = create_balance_proof(&[r_in], &[r_out], 0, b"ctx").unwrap();
        assert_eq!(
            verify_ct_transaction(&[input], &[output], 0, &proof, b"ctx"),
            Err(CtError::RangeProof)
        );
    }

    #[test]
    fn output_with_short_range_proof_is_rejected() {
        let (r_in, r_out) = (blinding(66), blinding(67));
        let input = create_commitment(10, r_in).unwrap();
        let mut output = create_commitment(10, r_out).unwrap();
        output.proof.bit_commitments.truncate(63);
        output.proof.bit_proofs.truncate(63);
        let (proof, _) = create_balance_proof(&[r_in], &[r_out], 0, b"ctx").unwrap();
        assert!(verify_ct_transaction(&[input], &[output], 0, &proof, b"ctx").is_err());
    }

    #[test]
    fn short_non_empty_input_proof_is_rejected_but_plaintext_input_allowed() {
        let (r_in, r_out) = (blinding(68), blinding(69));
        let output = create_commitment(10, r_out).unwrap();
        let (proof, _) = create_balance_proof(&[r_in], &[r_out], 0, b"ctx").unwrap();
        // Verifier-rebuilt plaintext commitment (empty proof) is accepted.
        let plain = AmountCommitment {
            commitment: commitment_point(10, r_in).unwrap(),
            proof: empty_proof(),
        };
        verify_ct_transaction(&[plain], &[output.clone()], 0, &proof, b"ctx").unwrap();
        // The same commitment with a partial proof is not.
        let mut partial = create_commitment(10, r_in).unwrap();
        partial.proof.bit_commitments.truncate(10);
        partial.proof.bit_proofs.truncate(10);
        assert!(verify_ct_transaction(&[partial], &[output.clone()], 0, &proof, b"ctx").is_err());
        // Plaintext input of a different value does not balance.
        let wrong = AmountCommitment {
            commitment: commitment_point(11, r_in).unwrap(),
            proof: empty_proof(),
        };
        assert!(verify_ct_transaction(&[wrong], &[output], 0, &proof, b"ctx").is_err());
    }

    #[test]
    fn no_inputs_is_rejected() {
        let r = blinding(70);
        let output = create_commitment(1, r).unwrap();
        let (proof, _) = create_balance_proof(&[r], &[], 0, b"ctx").unwrap();
        assert!(verify_ct_transaction(&[], &[output], 0, &proof, b"ctx").is_err());
    }

    // ---------------------------------------------------------------
    // Balance proof
    // ---------------------------------------------------------------

    #[test]
    fn balance_proof_binds_context_fee_and_r() {
        let (r_in, r_out) = (blinding(71), blinding(72));
        let input = create_commitment(50, r_in).unwrap();
        let output = create_commitment(40, r_out).unwrap();
        let (proof, _) = create_balance_proof(&[r_in], &[r_out], 10, b"ctx-a").unwrap();
        let ins = [input];
        let outs = [output];
        verify_ct_transaction(&ins, &outs, 10, &proof, b"ctx-a").unwrap();
        // Other context.
        assert!(verify_ct_transaction(&ins, &outs, 10, &proof, b"ctx-b").is_err());
        // Other fee.
        assert!(verify_ct_transaction(&ins, &outs, 9, &proof, b"ctx-a").is_err());
        assert!(verify_ct_transaction(&ins, &outs, 0, &proof, b"ctx-a").is_err());
        // Tampered z / R.
        let mut bad = proof.clone();
        bad.z[31] ^= 1;
        assert!(verify_ct_transaction(&ins, &outs, 10, &bad, b"ctx-a").is_err());
        let mut bad = proof.clone();
        bad.r_pub = commitment_point(1, blinding(73)).unwrap();
        assert!(verify_ct_transaction(&ins, &outs, 10, &bad, b"ctx-a").is_err());
        // z = 0 and z >= n are errors, never panics.
        let mut bad = proof.clone();
        bad.z = [0u8; 32];
        assert!(verify_ct_transaction(&ins, &outs, 10, &bad, b"ctx-a").is_err());
        bad.z = [0xFF; 32];
        assert!(verify_ct_transaction(&ins, &outs, 10, &bad, b"ctx-a").is_err());
    }

    #[test]
    fn point_at_infinity_balance_is_rejected_without_panic() {
        // input == output with the same blinding and zero fee: the balance
        // point is the point at infinity.
        let r = blinding(74);
        let input = create_commitment(5, r).unwrap();
        let output = input.clone();
        // The honest prover cannot even create the proof...
        assert!(create_balance_proof(&[r], &[r], 0, b"ctx").is_err());
        // ...and any proof the attacker invents is rejected.
        let junk = BalanceProof {
            r_pub: commitment_point(1, blinding(75)).unwrap(),
            z: blinding(76),
        };
        assert!(verify_ct_transaction(&[input], &[output], 0, &junk, b"ctx").is_err());
    }

    #[test]
    fn fee_is_added_as_fee_times_g() {
        let (r_in, r_out) = (blinding(77), blinding(78));
        let input = create_commitment(1_000, r_in).unwrap();
        let output = create_commitment(900, r_out).unwrap();
        let (proof, _) = create_balance_proof(&[r_in], &[r_out], 100, b"ctx").unwrap();
        verify_ct_transaction(&[input.clone()], &[output.clone()], 100, &proof, b"ctx").unwrap();
        // Claiming a smaller fee than the true one fails.
        assert!(verify_ct_transaction(&[input], &[output], 99, &proof, b"ctx").is_err());
    }

    #[test]
    fn scalar_helpers_handle_zero_results() {
        let a = blinding(80);
        assert_eq!(scalar_add(&a, &scalar_neg(&a).unwrap()).unwrap(), ZERO);
        assert_eq!(scalar_sub(&a, &a).unwrap(), ZERO);
        assert_eq!(scalar_mul_bytes(&a, &ZERO).unwrap(), ZERO);
        assert_eq!(scalar_neg(&ZERO).unwrap(), ZERO);
        assert!(scalar_add(&[0xFF; 32], &a).is_err());
    }
}
