//! Chainstate: block index, contextual checks, ConnectBlock/DisconnectBlock,
//! reorgs and block assembly. Port of `validation.cpp`, `chain.{h,cpp}`,
//! `consensus/tx_verify.cpp` (finality, sequence locks, sigop cost) and
//! `node/miner.cpp`.
//!
//! CONTRACT: public signatures in each module are fixed. Implementers may add
//! private helpers, derives and tests, but must not rename or change them.

pub mod error;
pub mod index;
pub mod finality;
pub mod witness;
pub mod sigops;
pub mod inputs;
pub mod contextual;
pub mod connect;
pub mod chainstate;
pub mod miner;
pub mod mempool_accept;

pub use error::ValidationError;
pub use index::{ActiveChain, BlockIndex, BlockStatus, BlockTree, IndexId};
