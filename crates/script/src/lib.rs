// btc-script
// Port of Bitcoin Core's script interpreter (src/script/).
// Reference: D:\bitcoin-core-reference\src\script
// Contract for all modules: D:\bitcoin-rust\crates\script\CONTRACT.md

pub mod error;
pub mod flags;
pub mod opcodes;
pub mod script_num;
pub mod context;
pub mod interpreter;
pub mod sig_encoding;
pub mod sighash;
pub mod sighash_taproot;
pub mod checker;
pub mod taproot;
pub mod verify;
pub mod sigops;

pub use context::{ExecData, SigVersion, SignatureChecker, TapscriptExt, NO_CODESEPARATOR};
pub use error::ScriptError;
pub use flags::ScriptVerifyFlags;
pub use verify::verify_script;
