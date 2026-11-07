//! Stealth addresses (BIP47-style) for AnonCoin.
//!
//! A recipient publishes a reusable invitation address: a pair of
//! public keys `(spending_pub, scan_pub)`. Each sender picks an
//! ephemeral key and (via ECDH with `scan_pub`) derives a fresh
//! one-time public key `spending_pub + tweak*G`, paying to its
//! HASH160. Observers see unrelated addresses for every payment and
//! cannot link them to the recipient; the recipient scans outputs
//! with their scan secret and recovers the one-time spending secret.
//!
//! This is the first Privacy Plan phase: it breaks the address graph
//! (common-input clustering, reuse, change heuristics). Amounts are
//! still in cleartext until confidential transactions land.

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{PubkeyHash, ScriptBuf};
use bitcoin_hashes::{hash160, sha256, Hash};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StealthError {
    #[error("random number generation failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("invalid secret key bytes")]
    InvalidSecret,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("tweak derivation failed")]
    Tweak,
}

/// Recipient keypair for stealth payments.
/// `spending` controls funds; `scan` only tests incoming outputs.
#[derive(Clone, Debug)]
pub struct StealthKeys {
    spending: SecretKey,
    scan: SecretKey,
}

impl StealthKeys {
    /// Generates a fresh spending/scan keypair from the OS RNG.
    pub fn generate() -> Result<Self, StealthError> {
        Ok(Self {
            spending: random_secret()?,
            scan: random_secret()?,
        })
    }

    /// Builds from raw 32-byte secrets (for import / tests).
    pub fn from_secrets(spending: &[u8; 32], scan: &[u8; 32]) -> Result<Self, StealthError> {
        Ok(Self {
            spending: SecretKey::from_slice(spending).map_err(|_| StealthError::InvalidSecret)?,
            scan: SecretKey::from_slice(scan).map_err(|_| StealthError::InvalidSecret)?,
        })
    }

    pub fn spending_pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.spending)
    }

    pub fn scan_pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.scan)
    }

    /// Internal view key for audit: `SHA256(scan_secret || "anon-view")`.
    /// It detects payments without the spending key.
    pub fn view_key(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 + 9);
        buf.extend_from_slice(&self.scan.secret_bytes());
        buf.extend_from_slice(b"anon-view");
        sha256::Hash::hash(&buf).to_byte_array()
    }

    /// The reusable invitation address shown to senders.
    pub fn address(&self) -> StealthAddress {
        StealthAddress {
            spending_pub: self.spending_pubkey(),
            scan_pub: self.scan_pubkey(),
        }
    }

    /// Scans an output's HASH160 against `ephemeral_pub`.
    /// Returns the one-time secret if the output pays this recipient.
    pub fn scan_output(
        &self,
        ephemeral_pub: &PublicKey,
        candidate: &PubkeyHash,
    ) -> Result<Option<SecretKey>, StealthError> {
        let secp = Secp256k1::new();
        let shared = SharedSecret::new(ephemeral_pub, &self.scan);
        let tweak = shared_tweak(shared.secret_bytes());
        let one_time_pub = self
            .spending_pubkey()
            .add_exp_tweak(&secp, &tweak)
            .map_err(|_| StealthError::Tweak)?;
        let derived = PubkeyHash::from_slice(hash160::Hash::hash(&one_time_pub.serialize()).as_ref())
            .map_err(|_| StealthError::InvalidPublicKey)?;
        if derived != *candidate {
            return Ok(None);
        }
        Ok(Some(
            self.spending
                .add_tweak(&tweak)
                .map_err(|_| StealthError::Tweak)?,
        ))
    }
}

/// Reusable stealth invitation address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StealthAddress {
    pub spending_pub: PublicKey,
    pub scan_pub: PublicKey,
}

impl StealthAddress {
    /// Serialises to 66 bytes: spending pubkey || scan pubkey.
    pub fn to_bytes(self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(&self.spending_pub.serialize());
        out[33..].copy_from_slice(&self.scan_pub.serialize());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StealthError> {
        if bytes.len() != 66 {
            return Err(StealthError::InvalidPublicKey);
        }
        Ok(Self {
            spending_pub: PublicKey::from_slice(&bytes[..33])
                .map_err(|_| StealthError::InvalidPublicKey)?,
            scan_pub: PublicKey::from_slice(&bytes[33..])
                .map_err(|_| StealthError::InvalidPublicKey)?,
        })
    }

    /// Derives the unique one-time payment address for `ephemeral`.
    pub fn payment(
        &self,
        ephemeral: &SecretKey,
    ) -> Result<StealthPayment, StealthError> {
        let secp = Secp256k1::new();
        let ephemeral_pub = PublicKey::from_secret_key(&secp, ephemeral);
        let shared = SharedSecret::new(&self.scan_pub, ephemeral);
        let tweak = shared_tweak(shared.secret_bytes());
        let one_time_pub = self
            .spending_pub
            .add_exp_tweak(&secp, &tweak)
            .map_err(|_| StealthError::Tweak)?;
        let hash = PubkeyHash::from_slice(hash160::Hash::hash(&one_time_pub.serialize()).as_ref())
            .map_err(|_| StealthError::InvalidPublicKey)?;
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(hash.as_ref());
        script.extend_from_slice(&[0x88, 0xac]);
        Ok(StealthPayment {
            ephemeral_pub,
            one_time_pub,
            script_pubkey: ScriptBuf::from_bytes(script),
        })
    }
}

/// One sender's payment to a stealth address.
#[derive(Clone, Debug)]
pub struct StealthPayment {
    /// Published with the transaction so the recipient can scan.
    pub ephemeral_pub: PublicKey,
    /// The fresh key actually paid (never reused).
    pub one_time_pub: PublicKey,
    /// P2PKH script of `one_time_pub`.
    pub script_pubkey: ScriptBuf,
}

/// BIP47-style marker output: `OP_RETURN <ephemeral_pub>`.
/// Senders include this output (value 0) in the same transaction as the
/// stealth payment so the recipient's scanner can find the ephemeral key
/// and derive the one-time address to look for.
pub fn marker_script(ephemeral_pub: &PublicKey) -> ScriptBuf {
    let mut buf = vec![0x6a, 0x21];
    buf.extend_from_slice(&ephemeral_pub.serialize());
    ScriptBuf::from_bytes(buf)
}

/// Parses a marker output back to the ephemeral public key.
pub fn parse_marker(script: &ScriptBuf) -> Option<PublicKey> {
    let bytes = script.as_bytes();
    if bytes.len() == 35 && bytes[0] == 0x6a && bytes[1] == 0x21 {
        PublicKey::from_slice(&bytes[2..]).ok()
    } else {
        None
    }
}

/// Extracts the 20-byte HASH160 from a P2PKH or P2WPKH script,
/// which is what stealth one-time keys are compared against.
pub fn extract_hash160(script: &ScriptBuf) -> Option<PubkeyHash> {
    let b = script.as_bytes();
    if script.is_p2pkh() {
        PubkeyHash::from_slice(&b[3..23]).ok()
    } else if script.is_p2wpkh() {
        PubkeyHash::from_slice(&b[2..22]).ok()
    } else {
        None
    }
}

fn shared_tweak(shared: [u8; 32]) -> Scalar {
    // SHA256 of the ECDH secret; the chance of it exceeding the curve
    // order (and Scalar::from_be_bytes failing) is negligible, but fall
    // back to a reduced hash instead of panicking.
    let hashed = sha256::Hash::hash(&shared);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hashed.as_ref());
    Scalar::from_be_bytes(buf).unwrap_or_else(|_| {
        let again = sha256::Hash::hash(&buf);
        let mut smaller = [0u8; 32];
        smaller.copy_from_slice(again.as_ref());
        // Mask the high bits so the reduced value is provably in range.
        smaller[0] &= 0x1f;
        Scalar::from_be_bytes(smaller).expect("masked scalar is in range")
    })
}

/// Generates a fresh ephemeral secret for one stealth payment.
pub fn ephemeral_secret() -> Result<SecretKey, StealthError> {
    random_secret()
}

fn random_secret() -> Result<SecretKey, StealthError> {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)?;
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Ok(secret);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Message, SecretKey as Sk};

    #[test]
    fn sender_and_recipient_derive_the_same_one_time_key() {
        let recipient = StealthKeys::generate().unwrap();
        let addr = recipient.address();
        let ephemeral = random_secret().unwrap();

        let payment = addr.payment(&ephemeral).unwrap();
        let hash = PubkeyHash::from_slice(
            hash160::Hash::hash(&payment.one_time_pub.serialize()).as_ref(),
        )
        .unwrap();

        // Recipient scans and recovers a secret matching the one-time pubkey.
        let one_time_secret = recipient.scan_output(&payment.ephemeral_pub, &hash).unwrap().expect("must scan");
        let secp = Secp256k1::new();
        assert_eq!(
            PublicKey::from_secret_key(&secp, &one_time_secret),
            payment.one_time_pub
        );

        // The recovered secret can actually sign for the derived pubkey.
        let msg = Message::from_digest_slice(&[7u8; 32]).unwrap();
        let sig = secp.sign_ecdsa(&msg, &one_time_secret);
        assert!(secp.verify_ecdsa(&msg, &sig, &payment.one_time_pub).is_ok());
    }

    #[test]
    fn each_payment_gets_a_fresh_address() {
        let recipient = StealthKeys::generate().unwrap();
        let addr = recipient.address();
        let a = addr.payment(&random_secret().unwrap()).unwrap();
        let b = addr.payment(&random_secret().unwrap()).unwrap();
        assert_ne!(a.ephemeral_pub, b.ephemeral_pub);
        assert_ne!(a.script_pubkey, b.script_pubkey);
    }

    #[test]
    fn wrong_recipient_cannot_scan() {
        let recipient = StealthKeys::generate().unwrap();
        let stranger = StealthKeys::generate().unwrap();
        let payment = recipient.address().payment(&random_secret().unwrap()).unwrap();
        let hash = PubkeyHash::from_slice(
            hash160::Hash::hash(&payment.one_time_pub.serialize()).as_ref(),
        )
        .unwrap();
        assert!(stranger.scan_output(&payment.ephemeral_pub, &hash).unwrap().is_none());
    }

    #[test]
    fn address_round_trips_through_bytes() {
        let keys = StealthKeys::generate().unwrap();
        let addr = keys.address();
        assert_eq!(StealthAddress::from_bytes(&addr.to_bytes()).unwrap(), addr);
        assert!(StealthAddress::from_bytes(&[1u8; 65]).is_err());
    }

    #[test]
    fn marker_round_trips() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let marker = marker_script(&pk);
        assert_eq!(parse_marker(&marker), Some(pk));
        assert!(parse_marker(&ScriptBuf::from_bytes(vec![0x6a])).is_none());
        assert_eq!(extract_hash160(&ScriptBuf::from_bytes(vec![0x6a])), None);
    }

    #[test]
    fn fixed_secrets_are_deterministic() {
        let keys =
            StealthKeys::from_secrets(&[1u8; 32], &[2u8; 32]).unwrap();
        let ephemeral = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let payment = keys.address().payment(&ephemeral).unwrap();
        let hash = PubkeyHash::from_slice(
            hash160::Hash::hash(&payment.one_time_pub.serialize()).as_ref(),
        )
        .unwrap();
        let scanned = keys.scan_output(&payment.ephemeral_pub, &hash).unwrap().unwrap();
        let secp = Secp256k1::new();
        assert_eq!(
            PublicKey::from_secret_key(&secp, &scanned),
            payment.one_time_pub
        );
        let _ = Sk::from_slice(&[9u8; 32]).unwrap(); // touch import path
    }
}
