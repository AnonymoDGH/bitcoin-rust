//! Key storage and output-script derivation. Port of the key handling in src/key.cpp and
//! src/pubkey.cpp, and of the destinations a wallet derives from each key.
//!
//! Keys are held as `bitcoin::PrivateKey` (secp256k1 secret plus compression flag). A
//! compressed key yields P2PKH, P2WPKH, P2SH-P2WPKH and P2TR key-path scripts (BIP86 tweak, no
//! script tree). An uncompressed key yields P2PKH only, as in Core.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use bitcoin::key::{FromWifError, Keypair, TapTweak, TweakedKeypair};
use bitcoin::secp256k1::{All, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{CompressedPublicKey, NetworkKind, PrivateKey, PubkeyHash, PublicKey, ScriptBuf};
use thiserror::Error;

/// A key is identified by the HASH160 of its serialized public key (Core's `CKeyID`).
pub type KeyId = PubkeyHash;

/// Output template through which a key can be paid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScriptKind {
    P2pkh,
    P2wpkh,
    P2shP2wpkh,
    P2tr,
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("random number generation failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("invalid WIF private key: {0}")]
    InvalidWif(#[from] FromWifError),
}

struct KeyEntry {
    key: PrivateKey,
    scripts: Vec<(ScriptKind, ScriptBuf)>,
}

/// Private keys the wallet can sign with, plus an index from output script to owning key.
#[derive(Default)]
pub struct KeyStore {
    keys: BTreeMap<KeyId, KeyEntry>,
    index: HashMap<ScriptBuf, (KeyId, ScriptKind)>,
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Secret material is never printed.
        f.debug_struct("KeyStore")
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates a new compressed mainnet key from the OS random source.
    pub fn generate(&mut self) -> Result<KeyId, KeyError> {
        loop {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes)?;
            // Only zero or a value at or above the curve order is rejected: practically never.
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Ok(self.import_private_key(PrivateKey::new(secret, NetworkKind::Main)));
            }
        }
    }

    pub fn import_wif(&mut self, wif: &str) -> Result<KeyId, KeyError> {
        Ok(self.import_private_key(PrivateKey::from_wif(wif)?))
    }

    /// Adds `key` and returns its id. Importing a key that is already present changes nothing.
    pub fn import_private_key(&mut self, key: PrivateKey) -> KeyId {
        let secp = Secp256k1::new();
        let id = PublicKey::from_private_key(&secp, &key).pubkey_hash();
        if self.keys.contains_key(&id) {
            return id;
        }
        let scripts = derive_scripts(&secp, &key);
        for (kind, script) in &scripts {
            self.index.insert(script.clone(), (id, *kind));
        }
        self.keys.insert(id, KeyEntry { key, scripts });
        id
    }

    /// WIF encoding of the key, or None if the id is unknown.
    pub fn export_wif(&self, id: &KeyId) -> Option<String> {
        self.keys.get(id).map(|entry| entry.key.to_wif())
    }

    pub fn private_key(&self, id: &KeyId) -> Option<&PrivateKey> {
        self.keys.get(id).map(|entry| &entry.key)
    }

    /// Every output script this key can be paid through, with its kind.
    pub fn script_pubkeys(&self, id: &KeyId) -> Option<&[(ScriptKind, ScriptBuf)]> {
        self.keys.get(id).map(|entry| entry.scripts.as_slice())
    }

    /// The key and template that own `script_pubkey`, if this store can sign for it.
    pub fn is_mine(&self, script_pubkey: &ScriptBuf) -> Option<(KeyId, ScriptKind)> {
        self.index.get(script_pubkey).copied()
    }

    pub fn key_ids(&self) -> impl Iterator<Item = &KeyId> {
        self.keys.keys()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// P2WPKH script of a compressed key. Also the redeem script of its P2SH-P2WPKH output.
pub(crate) fn p2wpkh_script(secp: &Secp256k1<All>, key: &PrivateKey) -> Option<ScriptBuf> {
    let compressed = CompressedPublicKey::from_private_key(secp, key).ok()?;
    Some(ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash()))
}

/// The BIP86 tweaked keypair that signs key-path spends of the key's P2TR output.
pub(crate) fn tweaked_keypair(secp: &Secp256k1<All>, key: &PrivateKey) -> TweakedKeypair {
    Keypair::from_secret_key(secp, &key.inner).tap_tweak(secp, None)
}

fn derive_scripts(secp: &Secp256k1<All>, key: &PrivateKey) -> Vec<(ScriptKind, ScriptBuf)> {
    let public = PublicKey::from_private_key(secp, key);
    let mut scripts = vec![(
        ScriptKind::P2pkh,
        ScriptBuf::new_p2pkh(&public.pubkey_hash()),
    )];
    let Some(redeem) = p2wpkh_script(secp, key) else {
        return scripts;
    };
    let (xonly, _) = XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(secp, &key.inner));
    let (tweaked, _) = xonly.tap_tweak(secp, None);
    scripts.push((ScriptKind::P2wpkh, redeem.clone()));
    scripts.push((
        ScriptKind::P2shP2wpkh,
        ScriptBuf::new_p2sh(&redeem.script_hash()),
    ));
    scripts.push((ScriptKind::P2tr, ScriptBuf::new_p2tr_tweaked(tweaked)));
    scripts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{encode_address, Network};
    use bitcoin::hashes::Hash;

    // Vectors from src/test/key_tests.cpp.
    const CORE_SECRET_UNCOMPRESSED: &str = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    const CORE_ADDRESS_UNCOMPRESSED: &str = "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ";
    const CORE_SECRET_COMPRESSED: &str = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw";
    const CORE_ADDRESS_COMPRESSED: &str = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs";
    const CORE_BAD_KEY: &str = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF";
    // Secret key 1 (compressed).
    const KEY_ONE_WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

    fn p2pkh_address(id: &KeyId) -> String {
        encode_address(Network::Main, &ScriptBuf::new_p2pkh(id)).unwrap()
    }

    fn script_of(store: &KeyStore, id: &KeyId, kind: ScriptKind) -> ScriptBuf {
        store
            .script_pubkeys(id)
            .unwrap()
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, s)| s.clone())
            .unwrap()
    }

    #[test]
    fn wif_roundtrip_uncompressed_core_vector() {
        let mut store = KeyStore::new();
        let id = store.import_wif(CORE_SECRET_UNCOMPRESSED).unwrap();
        assert_eq!(store.export_wif(&id).unwrap(), CORE_SECRET_UNCOMPRESSED);
        assert_eq!(p2pkh_address(&id), CORE_ADDRESS_UNCOMPRESSED);
        // Uncompressed keys are paid through P2PKH only.
        assert_eq!(store.script_pubkeys(&id).unwrap().len(), 1);
    }

    #[test]
    fn wif_roundtrip_compressed_core_vector() {
        let mut store = KeyStore::new();
        let id = store.import_wif(CORE_SECRET_COMPRESSED).unwrap();
        assert_eq!(store.export_wif(&id).unwrap(), CORE_SECRET_COMPRESSED);
        assert_eq!(p2pkh_address(&id), CORE_ADDRESS_COMPRESSED);
        assert_eq!(store.script_pubkeys(&id).unwrap().len(), 4);

        let mut other = KeyStore::new();
        let again = other.import_wif(&store.export_wif(&id).unwrap()).unwrap();
        assert_eq!(again, id);
    }

    #[test]
    fn rejects_invalid_wif() {
        let mut store = KeyStore::new();
        assert!(matches!(
            store.import_wif(CORE_BAD_KEY),
            Err(KeyError::InvalidWif(_))
        ));
        assert!(store.is_empty());
    }

    #[test]
    fn key_one_derives_known_segwit_addresses() {
        let mut store = KeyStore::new();
        let id = store.import_wif(KEY_ONE_WIF).unwrap();

        let p2wpkh = script_of(&store, &id, ScriptKind::P2wpkh);
        assert_eq!(
            encode_address(Network::Main, &p2wpkh).unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        let nested = script_of(&store, &id, ScriptKind::P2shP2wpkh);
        assert_eq!(
            encode_address(Network::Main, &nested).unwrap(),
            "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
        );
        let p2tr = script_of(&store, &id, ScriptKind::P2tr);
        assert!(p2tr.is_p2tr());
    }

    #[test]
    fn generated_keys_are_distinct_and_owned() {
        let mut store = KeyStore::new();
        let a = store.generate().unwrap();
        let b = store.generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(store.len(), 2);

        for id in [a, b] {
            for (kind, script) in store.script_pubkeys(&id).unwrap().to_vec() {
                assert_eq!(store.is_mine(&script), Some((id, kind)));
            }
        }

        let wif = store.export_wif(&a).unwrap();
        let mut restored = KeyStore::new();
        assert_eq!(restored.import_wif(&wif).unwrap(), a);
    }

    #[test]
    fn is_mine_rejects_foreign_script() {
        let mut store = KeyStore::new();
        store.generate().unwrap();
        let foreign = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x11; 20]));
        assert_eq!(store.is_mine(&foreign), None);
    }

    #[test]
    fn taproot_output_key_matches_tweaked_keypair() {
        let mut store = KeyStore::new();
        let id = store.generate().unwrap();
        let secp = Secp256k1::new();
        let key = *store.private_key(&id).unwrap();

        let p2tr = script_of(&store, &id, ScriptKind::P2tr);
        let (xonly, _) = tweaked_keypair(&secp, &key)
            .to_keypair()
            .x_only_public_key();
        assert_eq!(&p2tr.as_bytes()[2..], &xonly.serialize()[..]);
    }

    #[test]
    fn debug_output_hides_secrets() {
        let mut store = KeyStore::new();
        let id = store.import_wif(KEY_ONE_WIF).unwrap();
        let dump = format!("{store:?}");
        assert!(!dump.contains(KEY_ONE_WIF));
        assert!(store.export_wif(&id).is_some());
    }
}
