// btc-wallet
// Modular translation of Bitcoin Core wallet logic.
// Reference: D:\bitcoin-core-reference

pub mod address;
pub mod builder;
pub mod coinjoin;
pub mod coinselection;
pub mod crypter;
pub mod keys;
pub mod privpay;
pub mod shielded;
pub mod signer;
pub mod stealth;
pub mod wallet;

pub use builder::{build_transaction, BuildError};
pub use coinjoin::{commit_output, coinjoin_output, CoinJoinError, CoinJoinRound, Participant};
pub use keys::{KeyError, KeyId, KeyStore, ScriptKind};
pub use privpay::{confidential_output, sign_privately, verify_confidential, verify_privately, PrivPayError};
pub use shielded::{authorize, create_note, verify_note_spend, NoteStore, ShieldError};
pub use signer::{sign_transaction, SignError};
pub use stealth::{StealthAddress, StealthError, StealthKeys, StealthPayment, ViewKey};
pub use wallet::{Category, Wallet, WalletError, WalletTxRecord};
