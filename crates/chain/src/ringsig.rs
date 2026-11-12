//! Fixed-size ring signatures (Privacy Plan, Phase 2).
//!
//! A signer proves knowledge of the secret key of one of 16 public keys
//! in a ring, without revealing which (1-out-of-16 Schnorr ring, in the
//! style of Rivest et al. / the construction Monero popularised).
//!
//! Construction (`RING_SIZE = 16`):
//! - The signer picks a random scalar `a`, sets the signer limb
//!   `L_s = a*G`, and random-simulates the other 15 limbs
//!   `L_i = z_i*G - c_i*P_i`.
//! - `e = H(message || L_0 || ... || L_15)` (Fiat-Shamir), split as
//!   `c_s = e - sum_{i != s} c_i`, and the signer closes with
//!   `z_s = a + c_s * x_s`.
//! - Verification recomputes every `L_i = z_i*G - c_i*P_i` and checks
//!   `sum(c_i) == H(message || L_0 || ... || L_15)`.
//!
//! # NOT consensus authorisation
//!
//! This is library code for a future Monero-style design. A ring
//! signature proves knowledge of the secret of SOME ring member and
//! binds to no particular owner, so it MUST NOT be used to authorise
//! spending an output that explicitly names its owner (that was the
//! CT theft bug: attacker ring = victim key + attacker key, signed by
//! the attacker). It also has no key image, hence no double-spend
//! detection. CT inputs are authorised by an owner Schnorr signature
//! (`confidential::verify_ct_input_auth`). A sound ring design needs
//! inputs that reference a ring of outputs, a linkable scheme
//! (LSAG/CLSAG) and a key-image registry; see `docs/privacy-plan.md`.
//!
//! Fixed ring size matters: variable sizes leak how many decoys a
//! signer bothered to add, which shrinks the anonymity set.

use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin_hashes::{sha256, Hash as _};
use thiserror::Error;

pub const RING_SIZE: usize = 16;
const TRANSCRIPT_RING: &[u8] = b"AnonCoin-RING-v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RingError {
    #[error("invalid public key")]
    BadKey,
    #[error("invalid scalar")]
    BadScalar,
    #[error("ring size must be {0}")]
    WrongRingSize(usize),
    #[error("signer index out of range")]
    BadIndex,
    #[error("ring signature verification failed")]
    Verify,
    #[error("random number generation failed: {0}")]
    Random(#[from] getrandom::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingSignature {
    pub responses: Vec<([u8; 32], [u8; 32])>, // (c_i, z_i) per limb
}

fn random_scalar() -> Result<[u8; 32], RingError> {
    loop {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)?;
        if SecretKey::from_slice(&buf).is_ok() {
            return Ok(buf);
        }
    }
}

fn parse_pub(bytes: &[u8; 33]) -> Result<PublicKey, RingError> {
    PublicKey::from_slice(bytes).map_err(|_| RingError::BadKey)
}

fn scalar_mul(point: PublicKey, scalar_bytes: &[u8; 32]) -> Result<PublicKey, RingError> {
    let secp = Secp256k1::new();
    let scalar = Scalar::from_be_bytes(*scalar_bytes).map_err(|_| RingError::BadScalar)?;
    point.mul_tweak(&secp, &scalar).map_err(|_| RingError::BadKey)
}

fn challenge_scalar(parts: &[&[u8]]) -> [u8; 32] {
    let mut counter = 0u8;
    loop {
        let mut buf = vec![counter];
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

fn hash_limbs(message: &[u8], limbs: &[[u8; 33]]) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(limbs.len() + 2);
    parts.push(TRANSCRIPT_RING);
    parts.push(message);
    for limb in limbs {
        parts.push(limb);
    }
    challenge_scalar(&parts)
}

fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], RingError> {
    if *a == [0u8; 32] {
        return Ok(*b);
    }
    if *b == [0u8; 32] {
        return Ok(*a);
    }
    let a_sk = SecretKey::from_slice(a).map_err(|_| RingError::BadScalar)?;
    let b_scalar = Scalar::from_be_bytes(*b).map_err(|_| RingError::BadScalar)?;
    Ok(a_sk.add_tweak(&b_scalar).map_err(|_| RingError::BadScalar)?.secret_bytes())
}

fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], RingError> {
    if *a == *b {
        return Ok([0u8; 32]);
    }
    let b_sk = SecretKey::from_slice(b).map_err(|_| RingError::BadScalar)?;
    let neg = b_sk.negate().secret_bytes();
    scalar_add(a, &neg)
}

fn scalar_mul_bytes(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], RingError> {
    let a_sk = SecretKey::from_slice(a).map_err(|_| RingError::BadScalar)?;
    let b_scalar = Scalar::from_be_bytes(*b).map_err(|_| RingError::BadScalar)?;
    Ok(a_sk.mul_tweak(&b_scalar).map_err(|_| RingError::BadScalar)?.secret_bytes())
}

/// Signs `message` (a 32-byte sighash) as the owner of `ring[signer]`.
pub fn sign_ring(
    message: &[u8],
    ring: &[[u8; 33]],
    signer: usize,
    secret: &[u8; 32],
) -> Result<RingSignature, RingError> {
    if ring.len() != RING_SIZE {
        return Err(RingError::WrongRingSize(ring.len()));
    }
    if signer >= RING_SIZE {
        return Err(RingError::BadIndex);
    }
    let secp = Secp256k1::new();
    let pubs: Vec<PublicKey> = ring.iter().map(parse_pub).collect::<Result<_, _>>()?;
    // Sanity: the secret must match ring[signer].
    let expected = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(secret).map_err(|_| RingError::BadScalar)?,
    );
    if expected != pubs[signer] {
        return Err(RingError::BadScalar);
    }

    let mut limbs: Vec<[u8; 33]> = vec![[0u8; 33]; RING_SIZE];
    let mut c = vec![[0u8; 32]; RING_SIZE];
    let mut z = vec![[0u8; 32]; RING_SIZE];

    // The signer limb: L_s = a*G.
    let a = random_scalar()?;
    let g = g(&secp)?;
    let a_sk = SecretKey::from_slice(&a).map_err(|_| RingError::BadScalar)?;
    limbs[signer] = PublicKey::from_secret_key(&secp, &a_sk).serialize();

    // Simulated limbs.
    for i in 0..RING_SIZE {
        if i == signer {
            continue;
        }
        c[i] = random_scalar()?;
        z[i] = random_scalar()?;
        let z_g = scalar_mul(g, &z[i])?;
        let c_p = scalar_mul(pubs[i], &c[i])?;
        limbs[i] = z_g
            .combine(&c_p.negate(&secp))
            .map_err(|_| RingError::BadKey)?
            .serialize();
    }

    let e = hash_limbs(message, &limbs);
    let mut sum_others = [0u8; 32];
    for i in 0..RING_SIZE {
        if i != signer {
            sum_others = scalar_add(&sum_others, &c[i])?;
        }
    }
    c[signer] = scalar_sub(&e, &sum_others)?;
    z[signer] = scalar_add(&a, &scalar_mul_bytes(&c[signer], secret)?)?;
    Ok(RingSignature {
        responses: c.into_iter().zip(z).collect(),
    })
}

/// Verifies `sig` against `message` and the ring of public keys.
pub fn verify_ring(message: &[u8], ring: &[[u8; 33]], sig: &RingSignature) -> Result<(), RingError> {
    if ring.len() != RING_SIZE || sig.responses.len() != RING_SIZE {
        return Err(RingError::WrongRingSize(ring.len()));
    }
    let secp = Secp256k1::new();
    let pubs: Vec<PublicKey> = ring.iter().map(parse_pub).collect::<Result<_, _>>()?;
    let mut limbs = Vec::with_capacity(RING_SIZE);
    let mut sum_c = [0u8; 32];
    for ((c_i, z_i), pub_i) in sig.responses.iter().zip(&pubs) {
        let limb = scalar_mul(g(&secp)?, z_i)?
            .combine(&scalar_mul(*pub_i, c_i)?.negate(&secp))
            .map_err(|_| RingError::BadKey)?;
        limbs.push(limb.serialize());
        sum_c = scalar_add(&sum_c, c_i)?;
    }
    if hash_limbs(message, &limbs) != sum_c {
        return Err(RingError::Verify);
    }
    Ok(())
}

fn g(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Result<PublicKey, RingError> {
    let mut one = [0u8; 32];
    one[31] = 1;
    Ok(PublicKey::from_secret_key(
        secp,
        &SecretKey::from_slice(&one).map_err(|_| RingError::BadScalar)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (Vec<[u8; 32]>, Vec<[u8; 33]>) {
        let secp = Secp256k1::new();
        let mut secrets = Vec::new();
        let mut pubs = Vec::new();
        for i in 1..=RING_SIZE as u8 {
            let mut buf = [0u8; 32];
            buf[0] = i;
            buf[31] = 7;
            let sk = SecretKey::from_slice(&buf).unwrap();
            secrets.push(buf);
            pubs.push(PublicKey::from_secret_key(&secp, &sk).serialize());
        }
        (secrets, pubs)
    }

    #[test]
    fn signer_hides_among_sixteen_and_verifies() {
        let (secrets, pubs) = test_keys();
        let msg = [42u8; 32];
        let sig = sign_ring(&msg, &pubs, 5, &secrets[5]).unwrap();
        verify_ring(&msg, &pubs, &sig).unwrap();
    }

    #[test]
    fn scalar_mul_matches_secret_key() {
        let secp = Secp256k1::new();
        let g = g(&secp).unwrap();
        let mut secret = [0u8; 32];
        secret[31] = 42;
        let via_mul = scalar_mul(g, &secret).unwrap().serialize();
        let via_key = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret).unwrap())
            .serialize();
        assert_eq!(via_mul, via_key);
    }

    #[test]
    fn wrong_message_or_key_fails() {
        let (secrets, pubs) = test_keys();
        let msg = [42u8; 32];
        let sig = sign_ring(&msg, &pubs, 3, &secrets[3]).unwrap();
        assert!(verify_ring(&[99u8; 32], &pubs, &sig).is_err());
        // A signer whose key is not in the ring cannot produce a valid sig.
        assert!(sign_ring(&msg, &pubs, 0, &secrets[1]).is_err());
    }

    #[test]
    fn tampered_response_fails() {
        let (secrets, pubs) = test_keys();
        let msg = [7u8; 32];
        let mut sig = sign_ring(&msg, &pubs, 15, &secrets[15]).unwrap();
        sig.responses[0].0[0] ^= 1;
        assert!(verify_ring(&msg, &pubs, &sig).is_err());
    }
}
