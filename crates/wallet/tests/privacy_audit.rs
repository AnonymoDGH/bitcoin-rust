//! Privacy audit regressions that go through the public wallet API.

use std::fs;
use std::path::PathBuf;

use bitcoin::hashes::Hash as _;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use bitcoin_hashes::sha256;
use btc_wallet::wallet::{CtCoinInfo, NoteCoinInfo};
use btc_wallet::{ScriptKind, Wallet};

struct TestFile(PathBuf);

impl TestFile {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("btc-wallet-audit-{}-{name}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        TestFile(path)
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const CT_BLINDING: [u8; 32] = [0xb1; 32];
const CT_SECRET: [u8; 32] = [0xc2; 32];
const NOTE_RCM: [u8; 32] = [0xd3; 32];
const NOTE_SECRET: [u8; 32] = [0xe4; 32];

fn outpoint(n: u8) -> OutPoint {
    OutPoint::new(Txid::from_slice(&[n; 32]).unwrap(), 0)
}

/// Audit: `encryptwallet` encrypted the transparent keys but the wallet JSON
/// still carried CT blindings, note `rcm` and the one-time spend secrets of
/// privacy coins in cleartext: a stolen wallet file gave away every hidden
/// amount and the keys to spend the coins.
#[test]
fn encrypted_wallet_file_has_no_plaintext_privacy_secrets() {
    let file = TestFile::new("sealed");
    let mut wallet = Wallet::create(&file.0).unwrap();
    wallet
        .record_ct_coin(
            outpoint(1),
            ScriptBuf::from_bytes(vec![0x6a]),
            CtCoinInfo { value: 777, blinding: CT_BLINDING, secret: CT_SECRET, pubkey_hash: [9; 20] },
        )
        .unwrap();
    wallet
        .record_note_coin(
            outpoint(2),
            ScriptBuf::from_bytes(vec![0x6a]),
            NoteCoinInfo { value: 888, rcm: NOTE_RCM, secret: NOTE_SECRET, pubkey_hash: [8; 20] },
        )
        .unwrap();
    let address = wallet.stealth_address().unwrap();
    wallet.encrypt("hunter2").unwrap();

    // Neither the encrypt-time rewrite nor any later save leaks them.
    let text = fs::read_to_string(&file.0).unwrap();
    for (name, secret) in [
        ("ct blinding", CT_BLINDING),
        ("ct secret", CT_SECRET),
        ("note rcm", NOTE_RCM),
        ("note secret", NOTE_SECRET),
    ] {
        assert!(!text.contains(&hex(&secret)), "{name} stored in plaintext");
    }

    // Reopen: locked, then unlock restores everything.
    let mut reopened = Wallet::open(&file.0).unwrap();
    assert!(reopened.stealth_keys().is_err(), "locked wallet must not expose stealth keys");
    reopened.unlock("hunter2", u64::MAX).unwrap();
    let coins = reopened.coins_snapshot();
    let ct = coins[&outpoint(1)].ct.clone().expect("ct coin restored");
    assert_eq!((ct.value, ct.blinding, ct.secret), (777, CT_BLINDING, CT_SECRET));
    let note = coins[&outpoint(2)].note.clone().expect("note coin restored");
    assert_eq!((note.value, note.rcm, note.secret), (888, NOTE_RCM, NOTE_SECRET));
    assert_eq!(reopened.stealth_keys().unwrap().address(), address);

    // Locking forgets the plaintext in memory and the file stays clean.
    reopened.lock().unwrap();
    assert!(reopened.coins_snapshot()[&outpoint(1)].ct.is_none());
    let text = fs::read_to_string(&file.0).unwrap();
    assert!(!text.contains(&hex(&CT_BLINDING)) && !text.contains(&hex(&NOTE_RCM)));
    let mut again = Wallet::open(&file.0).unwrap();
    assert!(again.unlock("wrong", u64::MAX).is_err());
    again.unlock("hunter2", u64::MAX).unwrap();
    assert!(again.coins_snapshot()[&outpoint(2)].note.is_some());
}

/// Audit: the stealth spend and scan secrets were `SHA256(first_key_secret ||
/// label)`. Exporting that first key (`dumpprivkey`, a routine operation)
/// therefore handed over every stealth payment. They now come from an
/// independent random seed.
#[test]
fn stealth_keys_are_independent_of_exported_transparent_keys() {
    let file = TestFile::new("seed-indep");
    let mut wallet = Wallet::create(&file.0).unwrap();
    let script = wallet.new_script(ScriptKind::P2wpkh).unwrap();
    let wif = wallet.dump_wif(&script).unwrap();
    let key = bitcoin::PrivateKey::from_wif(&wif).unwrap();
    let derive = |label: &[u8]| {
        let mut buf = key.inner.secret_bytes().to_vec();
        buf.extend_from_slice(label);
        sha256::Hash::hash(&buf).to_byte_array()
    };
    let attacker_view = btc_wallet::StealthKeys::from_secrets(
        &derive(b"anoncoin-stealth-spending"),
        &derive(b"anoncoin-stealth-scan"),
    )
    .unwrap();
    assert_ne!(
        wallet.stealth_address().unwrap(),
        attacker_view.address(),
        "stealth keys must not derive from an exportable wallet key"
    );
}

#[test]
fn stealth_address_persists_and_is_unique_per_wallet() {
    let (fa, fb) = (TestFile::new("uniq-a"), TestFile::new("uniq-b"));
    let mut a = Wallet::create(&fa.0).unwrap();
    let mut b = Wallet::create(&fb.0).unwrap();
    let addr = a.stealth_address().unwrap();
    assert_ne!(addr, b.stealth_address().unwrap());
    drop(a);
    assert_eq!(Wallet::open(&fa.0).unwrap().stealth_keys().unwrap().address(), addr);
}

#[test]
fn debug_formatting_of_privacy_coin_info_is_redacted() {
    let ct = CtCoinInfo { value: 1, blinding: CT_BLINDING, secret: CT_SECRET, pubkey_hash: [0; 20] };
    let note = NoteCoinInfo { value: 1, rcm: NOTE_RCM, secret: NOTE_SECRET, pubkey_hash: [0; 20] };
    let shown = format!("{ct:?} {note:?}");
    for n in [177u8, 194, 211, 228] {
        assert!(!shown.contains(&n.to_string()), "{shown}");
    }
}

/// Wallets written before the stealth seed existed (no `stealth_seed` field)
/// keep their published invitation address.
#[test]
fn legacy_wallet_without_seed_keeps_first_key_derivation() {
    let file = TestFile::new("legacy");
    let mut wallet = Wallet::create(&file.0).unwrap();
    let script = wallet.new_script(ScriptKind::P2wpkh).unwrap();
    let wif = wallet.dump_wif(&script).unwrap();
    drop(wallet);
    let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&file.0).unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("stealth_seed");
    fs::write(&file.0, serde_json::to_vec(&json).unwrap()).unwrap();

    let wallet = Wallet::open(&file.0).unwrap();
    let key = bitcoin::PrivateKey::from_wif(&wif).unwrap();
    let derive = |label: &[u8]| {
        let mut buf = key.inner.secret_bytes().to_vec();
        buf.extend_from_slice(label);
        sha256::Hash::hash(&buf).to_byte_array()
    };
    let legacy = btc_wallet::StealthKeys::from_secrets(
        &derive(b"anoncoin-stealth-spending"),
        &derive(b"anoncoin-stealth-scan"),
    )
    .unwrap();
    assert_eq!(wallet.stealth_keys().unwrap().address(), legacy.address());
}
