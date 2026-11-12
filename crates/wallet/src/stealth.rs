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
    #[error("spending and scan keys must be distinct")]
    KeysNotSeparated,
    #[error("invalid view key encoding")]
    InvalidViewKey,
}

/// Domain tag for the stealth tweak hash. Binds the tweak to this protocol
/// so the ECDH secret is never hashed bare (any other protocol hashing the
/// same shared secret would otherwise yield the same scalar).
const TWEAK_DOMAIN: &[u8] = b"AnonCoin/stealth-tweak/v1";

/// Most stealth output indices scanned per ephemeral key in one transaction
/// (bounds the work an attacker-crafted marker can cost the scanner).
pub const MAX_SCAN_INDEX: u32 = 64;

/// Recipient keypair for stealth payments.
/// `spending` controls funds; `scan` only tests incoming outputs.
#[derive(Clone)]
pub struct StealthKeys {
    spending: SecretKey,
    scan: SecretKey,
}

impl std::fmt::Debug for StealthKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StealthKeys { <redacted> }")
    }
}

impl Drop for StealthKeys {
    fn drop(&mut self) {
        self.spending.non_secure_erase();
        self.scan.non_secure_erase();
    }
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
        // Equal keys would let anyone holding the (shareable) scan key spend.
        if spending == scan {
            return Err(StealthError::KeysNotSeparated);
        }
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

    /// View key for audit scans: the scan secret plus the spending *public*
    /// key. It can recognise every payment to this wallet (and compute the
    /// one-time public keys) but contains no spending secret, so it cannot
    /// sign. (The previous `SHA256(scan_secret || "anon-view")` was a one-way
    /// hash that could not scan anything.)
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            scan: self.scan,
            spending_pub: self.spending_pubkey(),
        }
    }

    /// The reusable invitation address shown to senders.
    pub fn address(&self) -> StealthAddress {
        StealthAddress {
            spending_pub: self.spending_pubkey(),
            scan_pub: self.scan_pubkey(),
        }
    }

    /// Scans an output's HASH160 against `ephemeral_pub` (first stealth
    /// output of that ephemeral key, plus the legacy un-indexed derivation
    /// so earlier payments stay recoverable). Returns the one-time secret
    /// if the output pays this recipient.
    pub fn scan_output(
        &self,
        ephemeral_pub: &PublicKey,
        candidate: &PubkeyHash,
    ) -> Result<Option<SecretKey>, StealthError> {
        self.scan_output_indexed(ephemeral_pub, 0, candidate)
    }

    /// Like [`scan_output`](Self::scan_output) for the stealth output
    /// numbered `index` under one ephemeral key.
    pub fn scan_output_indexed(
        &self,
        ephemeral_pub: &PublicKey,
        index: u32,
        candidate: &PubkeyHash,
    ) -> Result<Option<SecretKey>, StealthError> {
        let secp = Secp256k1::new();
        let shared = SharedSecret::new(ephemeral_pub, &self.scan);
        let mut candidates = vec![shared_tweak(shared.secret_bytes(), index)];
        if index == 0 {
            candidates.push(legacy_tweak(shared.secret_bytes()));
        }
        for tweak in candidates {
            if one_time_hash(&secp, &self.spending_pubkey(), &tweak)? == *candidate {
                return Ok(Some(
                    self.spending
                        .add_tweak(&tweak)
                        .map_err(|_| StealthError::Tweak)?,
                ));
            }
        }
        Ok(None)
    }
}

impl StealthKeys {
    /// Scans every candidate output of one transaction against a single
    /// ephemeral key: one ECDH, then the current indexed derivation for
    /// `index` in `0..candidates.len()` (capped at [`MAX_SCAN_INDEX`]) and the
    /// legacy un-indexed derivation. Returns `(position, one_time_secret)`
    /// for each candidate that pays this recipient. `candidates` pairs an
    /// output position with its HASH160.
    pub fn scan_tx_outputs(
        &self,
        ephemeral_pub: &PublicKey,
        candidates: &[(usize, PubkeyHash)],
    ) -> Result<Vec<(usize, SecretKey)>, StealthError> {
        let secp = Secp256k1::new();
        let spending_pub = self.spending_pubkey();
        let shared = SharedSecret::new(ephemeral_pub, &self.scan).secret_bytes();
        let max_index = (candidates.len() as u32).min(MAX_SCAN_INDEX);
        let mut tweaks: Vec<Scalar> = (0..max_index).map(|i| shared_tweak(shared, i)).collect();
        tweaks.push(legacy_tweak(shared));
        let mut found: Vec<(usize, SecretKey)> = Vec::new();
        for tweak in tweaks {
            let hash = one_time_hash(&secp, &spending_pub, &tweak)?;
            for (pos, candidate) in candidates {
                if *candidate == hash && !found.iter().any(|(p, _)| p == pos) {
                    let secret = self
                        .spending
                        .add_tweak(&tweak)
                        .map_err(|_| StealthError::Tweak)?;
                    found.push((*pos, secret));
                }
            }
        }
        Ok(found)
    }
}

/// Watch-only key for stealth payments: detects incoming outputs but cannot
/// spend (it holds the scan secret and only the spending public key).
#[derive(Clone)]
pub struct ViewKey {
    scan: SecretKey,
    spending_pub: PublicKey,
}

impl std::fmt::Debug for ViewKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ViewKey { <redacted> }")
    }
}

impl Drop for ViewKey {
    fn drop(&mut self) {
        self.scan.non_secure_erase();
    }
}

impl ViewKey {
    /// 65 bytes: scan secret || compressed spending public key.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.scan.secret_bytes());
        out[32..].copy_from_slice(&self.spending_pub.serialize());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StealthError> {
        if bytes.len() != 65 {
            return Err(StealthError::InvalidViewKey);
        }
        Ok(Self {
            scan: SecretKey::from_slice(&bytes[..32]).map_err(|_| StealthError::InvalidViewKey)?,
            spending_pub: PublicKey::from_slice(&bytes[32..])
                .map_err(|_| StealthError::InvalidViewKey)?,
        })
    }

    /// The one-time public key paid by `ephemeral_pub` at `index` if
    /// `candidate` matches it (legacy derivation tried for index 0).
    pub fn scan_output(
        &self,
        ephemeral_pub: &PublicKey,
        index: u32,
        candidate: &PubkeyHash,
    ) -> Result<Option<PublicKey>, StealthError> {
        let secp = Secp256k1::new();
        let shared = SharedSecret::new(ephemeral_pub, &self.scan);
        let mut tweaks = vec![shared_tweak(shared.secret_bytes(), index)];
        if index == 0 {
            tweaks.push(legacy_tweak(shared.secret_bytes()));
        }
        for tweak in tweaks {
            let one_time = self
                .spending_pub
                .add_exp_tweak(&secp, &tweak)
                .map_err(|_| StealthError::Tweak)?;
            if pubkey_hash_of(&one_time)? == *candidate {
                return Ok(Some(one_time));
            }
        }
        Ok(None)
    }
}

fn pubkey_hash_of(pk: &PublicKey) -> Result<PubkeyHash, StealthError> {
    PubkeyHash::from_slice(hash160::Hash::hash(&pk.serialize()).as_ref())
        .map_err(|_| StealthError::InvalidPublicKey)
}

fn one_time_hash(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    spending_pub: &PublicKey,
    tweak: &Scalar,
) -> Result<PubkeyHash, StealthError> {
    let one_time = spending_pub
        .add_exp_tweak(secp, tweak)
        .map_err(|_| StealthError::Tweak)?;
    pubkey_hash_of(&one_time)
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

    /// Derives the one-time payment address for `ephemeral` (output 0).
    pub fn payment(&self, ephemeral: &SecretKey) -> Result<StealthPayment, StealthError> {
        self.payment_indexed(ephemeral, 0)
    }

    /// Derives the one-time payment address for stealth output `index`
    /// under `ephemeral`. Distinct indices give unrelated addresses even
    /// for the same recipient and ephemeral key, so one transaction can
    /// pay a recipient several times without address reuse.
    pub fn payment_indexed(
        &self,
        ephemeral: &SecretKey,
        index: u32,
    ) -> Result<StealthPayment, StealthError> {
        let secp = Secp256k1::new();
        let ephemeral_pub = PublicKey::from_secret_key(&secp, ephemeral);
        let shared = SharedSecret::new(&self.scan_pub, ephemeral);
        let tweak = shared_tweak(shared.secret_bytes(), index);
        let one_time_pub = self
            .spending_pub
            .add_exp_tweak(&secp, &tweak)
            .map_err(|_| StealthError::Tweak)?;
        let hash = pubkey_hash_of(&one_time_pub)?;
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

/// `SHA256(domain || shared_secret || index_be)` reduced into the scalar
/// range. Out-of-range hashes (probability ~2^-128) are re-hashed with a
/// counter instead of panicking.
fn shared_tweak(shared: [u8; 32], index: u32) -> Scalar {
    let mut counter = 0u8;
    loop {
        let mut buf = Vec::with_capacity(TWEAK_DOMAIN.len() + 32 + 4 + 1);
        buf.extend_from_slice(TWEAK_DOMAIN);
        buf.extend_from_slice(&shared);
        buf.extend_from_slice(&index.to_be_bytes());
        if counter > 0 {
            buf.push(counter);
        }
        let hashed = sha256::Hash::hash(&buf).to_byte_array();
        if let Ok(scalar) = Scalar::from_be_bytes(hashed) {
            return scalar;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Pre-audit derivation (`SHA256(shared)`), kept only so outputs paid
/// before the domain-separated tweak existed can still be recovered.
fn legacy_tweak(shared: [u8; 32]) -> Scalar {
    let hashed = sha256::Hash::hash(&shared).to_byte_array();
    Scalar::from_be_bytes(hashed).unwrap_or_else(|_| {
        let mut smaller = sha256::Hash::hash(&hashed).to_byte_array();
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

    fn hash_of(pk: &PublicKey) -> PubkeyHash {
        PubkeyHash::from_slice(hash160::Hash::hash(&pk.serialize()).as_ref()).unwrap()
    }

    /// Audit: the tweak was a bare `SHA256(shared_secret)`: no domain
    /// separation, no output index. Any other protocol hashing the same ECDH
    /// secret got the same scalar, and one ephemeral key paid twice to the
    /// same recipient produced the *same* address (address reuse).
    #[test]
    fn tweak_is_domain_separated_and_not_the_bare_hash() {
        let keys = StealthKeys::from_secrets(&[1u8; 32], &[2u8; 32]).unwrap();
        let ephemeral = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let payment = keys.address().payment(&ephemeral).unwrap();
        let secp = Secp256k1::new();
        let shared = SharedSecret::new(&keys.address().scan_pub, &ephemeral);
        let bare = Scalar::from_be_bytes(sha256::Hash::hash(&shared.secret_bytes()).to_byte_array())
            .unwrap();
        let bare_pub = keys.spending_pubkey().add_exp_tweak(&secp, &bare).unwrap();
        assert_ne!(payment.one_time_pub, bare_pub, "tweak must be domain separated");
    }

    #[test]
    fn same_ephemeral_different_index_gives_different_addresses() {
        let keys = StealthKeys::generate().unwrap();
        let ephemeral = random_secret().unwrap();
        let a = keys.address().payment_indexed(&ephemeral, 0).unwrap();
        let b = keys.address().payment_indexed(&ephemeral, 1).unwrap();
        assert_ne!(a.script_pubkey, b.script_pubkey);
        assert_eq!(a.ephemeral_pub, b.ephemeral_pub);
        // Both are recoverable at their own index only.
        let (ha, hb) = (hash_of(&a.one_time_pub), hash_of(&b.one_time_pub));
        assert!(keys.scan_output_indexed(&a.ephemeral_pub, 1, &hb).unwrap().is_some());
        assert!(keys.scan_output_indexed(&a.ephemeral_pub, 0, &ha).unwrap().is_some());
        assert!(keys.scan_output_indexed(&a.ephemeral_pub, 0, &hb).unwrap().is_none());
    }

    #[test]
    fn legacy_outputs_remain_recoverable() {
        let keys = StealthKeys::from_secrets(&[1u8; 32], &[2u8; 32]).unwrap();
        let ephemeral = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let shared = SharedSecret::new(&keys.address().scan_pub, &ephemeral);
        let tweak = legacy_tweak(shared.secret_bytes());
        let old_pub = keys.spending_pubkey().add_exp_tweak(&secp, &tweak).unwrap();
        let eph_pub = PublicKey::from_secret_key(&secp, &ephemeral);
        let secret = keys.scan_output(&eph_pub, &hash_of(&old_pub)).unwrap().unwrap();
        assert_eq!(PublicKey::from_secret_key(&secp, &secret), old_pub);
    }

    /// Audit: the old "view key" was `SHA256(scan_secret || "anon-view")`,
    /// a one-way hash that cannot scan anything. A real view key must find
    /// payments yet carry no spending secret.
    #[test]
    fn view_key_scans_but_cannot_spend() {
        let keys = StealthKeys::generate().unwrap();
        let payment = keys.address().payment(&random_secret().unwrap()).unwrap();
        let hash = hash_of(&payment.one_time_pub);

        let exported = keys.view_key().to_bytes();
        let view = ViewKey::from_bytes(&exported).unwrap();
        assert_eq!(
            view.scan_output(&payment.ephemeral_pub, 0, &hash).unwrap(),
            Some(payment.one_time_pub)
        );
        let stranger = StealthKeys::generate().unwrap();
        let other = stranger.address().payment(&random_secret().unwrap()).unwrap();
        assert!(view
            .scan_output(&other.ephemeral_pub, 0, &hash_of(&other.one_time_pub))
            .unwrap()
            .is_none());

        // The exported bytes hold neither the spending secret nor anything
        // from which the one-time secret follows.
        let spending = keys.spending.secret_bytes();
        assert!(!exported.windows(32).any(|w| w == spending));
        assert_eq!(&exported[32..], &keys.spending_pubkey().serialize());
        assert!(ViewKey::from_bytes(&exported[..64]).is_err());
    }

    #[test]
    fn spend_and_scan_keys_must_differ() {
        assert!(matches!(
            StealthKeys::from_secrets(&[5u8; 32], &[5u8; 32]),
            Err(StealthError::KeysNotSeparated)
        ));
    }

    #[test]
    fn hostile_chain_data_never_panics() {
        // Truncated / non-curve markers and odd scripts are rejected, not panicked on.
        let mut bad = vec![0x6a, 0x21];
        bad.extend_from_slice(&[0x05; 33]);
        assert!(parse_marker(&ScriptBuf::from_bytes(bad)).is_none());
        let mut zero = vec![0x6a, 0x21, 0x02];
        zero.extend_from_slice(&[0u8; 32]);
        assert!(parse_marker(&ScriptBuf::from_bytes(zero)).is_none());
        assert_eq!(extract_hash160(&ScriptBuf::from_bytes(vec![0x76, 0xa9])), None);
        assert!(StealthAddress::from_bytes(&[0u8; 66]).is_err());
        assert!(StealthAddress::from_bytes(&[]).is_err());
    }

    #[test]
    fn debug_output_does_not_leak_secrets() {
        let keys = StealthKeys::from_secrets(&[0xabu8; 32], &[0xcdu8; 32]).unwrap();
        let shown = format!("{keys:?} {:?}", keys.view_key());
        assert!(!shown.contains("abab") && !shown.contains("cdcd") && !shown.contains("171"));
    }

    #[test]
    fn scan_tx_outputs_finds_indexed_and_legacy_outputs() {
        let keys = StealthKeys::from_secrets(&[1u8; 32], &[2u8; 32]).unwrap();
        let ephemeral = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let eph_pub = PublicKey::from_secret_key(&secp, &ephemeral);
        let addr = keys.address();
        let p0 = addr.payment_indexed(&ephemeral, 0).unwrap();
        let p2 = addr.payment_indexed(&ephemeral, 2).unwrap();
        let shared = SharedSecret::new(&addr.scan_pub, &ephemeral);
        let legacy = keys
            .spending_pubkey()
            .add_exp_tweak(&secp, &legacy_tweak(shared.secret_bytes()))
            .unwrap();
        let stranger = StealthKeys::generate().unwrap()
            .address().payment(&random_secret().unwrap()).unwrap();
        let candidates = vec![
            (0usize, hash_of(&stranger.one_time_pub)),
            (1, hash_of(&p2.one_time_pub)),
            (3, hash_of(&p0.one_time_pub)),
            (4, hash_of(&legacy)),
        ];
        let found = keys.scan_tx_outputs(&eph_pub, &candidates).unwrap();
        let mut positions: Vec<usize> = found.iter().map(|(p, _)| *p).collect();
        positions.sort_unstable();
        assert_eq!(positions, vec![1, 3, 4]);
        for (pos, secret) in found {
            let expected = match pos {
                1 => p2.one_time_pub,
                3 => p0.one_time_pub,
                _ => legacy,
            };
            assert_eq!(PublicKey::from_secret_key(&secp, &secret), expected);
        }
        // A different ephemeral key matches nothing.
        let other = PublicKey::from_secret_key(&secp, &random_secret().unwrap());
        assert!(keys.scan_tx_outputs(&other, &candidates).unwrap().is_empty());
    }
}
