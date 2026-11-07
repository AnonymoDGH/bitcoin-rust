// btc-wallet
// Modular translation of Bitcoin Core wallet logic.
// Reference: D:\bitcoin-core-reference

pub mod address;
pub mod builder;
pub mod coinjoin;
pub mod coinselection;
pub mod crypter;
pub mod keys;
pub mod signer;
pub mod stealth;
pub mod wallet;

pub use builder::{build_transaction, BuildError};
pub use coinjoin::{commit_output, coinjoin_output, CoinJoinError, CoinJoinRound, Participant};
pub use keys::{KeyError, KeyId, KeyStore, ScriptKind};
pub use signer::{sign_transaction, SignError};
pub use stealth::{StealthAddress, StealthError, StealthKeys, StealthPayment};
pub use wallet::{Category, Wallet, WalletError, WalletTxRecord};
