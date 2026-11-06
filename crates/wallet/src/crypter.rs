//! Wallet encryption primitives. Port of src/wallet/crypter.cpp: passphrase key derivation
//! (`BytesToKeySHA512AES`), AES-256-CBC with PKCS#7 padding, and the `EncryptSecret` /
//! `DecryptSecret` helpers that wrap individual private keys under the master key.

use aes::Aes256;
use bitcoin::hashes::{sha256d, Hash};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use sha2::{Digest, Sha512};
use thiserror::Error;

pub const SALT_SIZE: usize = 8;
pub const KEY_SIZE: usize = 32;
pub const IV_SIZE: usize = 16;
/// `CMasterKey::DEFAULT_DERIVE_ITERATIONS`.
pub const DEFAULT_DERIVE_ITERATIONS: u32 = 25_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CrypterError {
    #[error("derivation rounds must be at least 1")]
    ZeroRounds,
    #[error("ciphertext is not valid AES-256-CBC with PKCS#7 padding")]
    Decrypt,
}

/// AES-256-CBC with a fixed key and IV (`CCrypter` after `SetKey` or `SetKeyFromPassphrase`).
pub struct Crypter {
    key: [u8; KEY_SIZE],
    iv: [u8; IV_SIZE],
}

impl Crypter {
    /// `SetKeyFromPassphrase` with derivation method 0.
    pub fn from_passphrase(
        passphrase: &[u8],
        salt: &[u8; SALT_SIZE],
        rounds: u32,
    ) -> Result<Self, CrypterError> {
        if rounds == 0 {
            return Err(CrypterError::ZeroRounds);
        }
        let (key, iv) = bytes_to_key_sha512_aes(salt, passphrase, rounds);
        Ok(Self { key, iv })
    }

    /// `SetKey`: the IV is the first 16 bytes of `iv_hash`.
    pub fn from_key(key: [u8; KEY_SIZE], iv_hash: &[u8; 32]) -> Self {
        let mut iv = [0u8; IV_SIZE];
        iv.copy_from_slice(&iv_hash[..IV_SIZE]);
        Self { key, iv }
    }

    /// `CCrypter::Encrypt`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        cbc::Encryptor::<Aes256>::new(&self.key.into(), &self.iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    /// `CCrypter::Decrypt`. Fails on bad length or padding, which is how a wrong key shows up.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CrypterError> {
        cbc::Decryptor::<Aes256>::new(&self.key.into(), &self.iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| CrypterError::Decrypt)
    }
}

/// `EncryptSecret`: wraps a private key under `master_key`, with the IV taken from
/// `Hash(pubkey)` (SHA256D of the serialized public key), as Core does.
pub fn encrypt_secret(master_key: &[u8; KEY_SIZE], secret: &[u8], pubkey: &[u8]) -> Vec<u8> {
    Crypter::from_key(*master_key, &pubkey_hash(pubkey)).encrypt(secret)
}

/// `DecryptSecret`, the inverse of [`encrypt_secret`].
pub fn decrypt_secret(
    master_key: &[u8; KEY_SIZE],
    ciphertext: &[u8],
    pubkey: &[u8],
) -> Result<Vec<u8>, CrypterError> {
    Crypter::from_key(*master_key, &pubkey_hash(pubkey)).decrypt(ciphertext)
}

fn pubkey_hash(pubkey: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(pubkey).to_byte_array()
}

/// `CCrypter::BytesToKeySHA512AES`: an EVP_BytesToKey variant with SHA-512. The digest is
/// `SHA512(data || salt)` followed by `rounds - 1` further SHA-512 iterations of the previous
/// digest. The first 32 bytes are the key and the next 16 the IV.
fn bytes_to_key_sha512_aes(
    salt: &[u8; SALT_SIZE],
    data: &[u8],
    rounds: u32,
) -> ([u8; KEY_SIZE], [u8; IV_SIZE]) {
    let mut buf: [u8; 64] = Sha512::new()
        .chain_update(data)
        .chain_update(salt)
        .finalize()
        .into();
    for _ in 1..rounds {
        buf = Sha512::digest(buf).into();
    }
    let mut key = [0u8; KEY_SIZE];
    let mut iv = [0u8; IV_SIZE];
    key.copy_from_slice(&buf[..KEY_SIZE]);
    iv.copy_from_slice(&buf[KEY_SIZE..KEY_SIZE + IV_SIZE]);
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_SIZE] = *b"\x00\x00\xde\xad\xbe\xef\x00\x00";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Vector from src/wallet/test/wallet_crypto_tests.cpp (passphrase test).
    #[test]
    fn passphrase_derivation_matches_core_vector() {
        let crypter = Crypter::from_passphrase(b"test", &SALT, DEFAULT_DERIVE_ITERATIONS).unwrap();
        assert_eq!(
            crypter.key.to_vec(),
            hex("fc7aba077ad5f4c3a0988d8daa4810d0d4a0e3bcb53af662998898f33df0556a")
        );
        assert_eq!(crypter.iv.to_vec(), hex("cf2f2691526dd1aa220896fb8bf7c369"));
    }

    #[test]
    fn zero_rounds_is_rejected() {
        assert_eq!(
            Crypter::from_passphrase(b"passphrase", &SALT, 0).err(),
            Some(CrypterError::ZeroRounds)
        );
        assert!(Crypter::from_passphrase(b"passphrase", &SALT, 1).is_ok());
    }

    // NIST SP 800-38A, F.2.5 (CBC-AES256.Encrypt). Padding adds one block, so only the
    // first four ciphertext blocks are compared.
    #[test]
    fn aes256_cbc_matches_nist_vector() {
        let key: [u8; 32] = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .try_into()
            .unwrap();
        let iv_hash = {
            let mut h = [0u8; 32];
            h[..16].copy_from_slice(&hex("000102030405060708090a0b0c0d0e0f"));
            h
        };
        let plaintext = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let expected = hex(concat!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            "9cfc4e967edb808d679f777bc6702c7d",
            "39f23369a9d9bacfa530e26304231461",
            "b2eb05e2c39be9fcda6c19078c6a9d1b"
        ));
        let crypter = Crypter::from_key(key, &iv_hash);
        let ciphertext = crypter.encrypt(&plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        assert_eq!(&ciphertext[..64], &expected[..]);
        assert_eq!(crypter.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn secret_roundtrip_and_wrong_key_fails() {
        let master = [0x42u8; 32];
        let other = [0x43u8; 32];
        let pubkey = [0x02u8; 33];
        let secret = [0x7fu8; 32];

        let ciphertext = encrypt_secret(&master, &secret, &pubkey);
        assert_eq!(ciphertext.len(), 48);
        assert_eq!(
            decrypt_secret(&master, &ciphertext, &pubkey).unwrap(),
            secret
        );
        assert!(decrypt_secret(&other, &ciphertext, &pubkey).map_or(true, |plain| plain != secret));
    }

    #[test]
    fn wrong_passphrase_does_not_recover_master() {
        let master = [0x11u8; 32];
        let good = Crypter::from_passphrase(b"correct", &SALT, 100).unwrap();
        let encrypted = good.encrypt(&master);
        let bad = Crypter::from_passphrase(b"wrong", &SALT, 100).unwrap();
        assert!(bad
            .decrypt(&encrypted)
            .map_or(true, |plain| plain != master));
    }
}
