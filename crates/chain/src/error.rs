//! Block/transaction validation failures with Core reject reasons.

use btc_script::ScriptError;
use btc_validation::block_verify::BlockError;
use btc_validation::tx_verify::TxCheckError;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("context-free block check: {0}")]
    Block(#[from] BlockError),
    #[error("transaction check: {0}")]
    Tx(#[from] TxCheckError),
    #[error("script verification failed on input {input}: {error:?}")]
    Script { input: usize, error: ScriptError },
    #[error("previous block not found")]
    PrevBlkNotFound,
    #[error("previous block is invalid")]
    BadPrevBlk,
    #[error("incorrect proof of work (nBits)")]
    BadDiffBits,
    #[error("block timestamp too early")]
    TimeTooOld,
    #[error("block timestamp too far in the future")]
    TimeTooNew,
    #[error("rejected nVersion={0} block")]
    BadVersion(i32),
    #[error("block contains a non-final transaction")]
    NonFinalTx,
    #[error("block height mismatch in coinbase")]
    BadCbHeight,
    #[error("witness merkle commitment mismatch")]
    BadWitnessMerkleMatch,
    #[error("witness reserved value size invalid")]
    BadWitnessNonceSize,
    #[error("unexpected witness data")]
    UnexpectedWitness,
    #[error("block weight limit exceeded")]
    BadBlockWeight,
    #[error("too many sigops")]
    BadBlkSigops,
    #[error("contains a non-BIP68-final transaction")]
    NonBip68Final,
    #[error("coinbase pays too much (actual={actual}, limit={limit})")]
    BadCbAmount { actual: i64, limit: i64 },
    #[error("tried to overwrite transaction (BIP30)")]
    BipThirty,
    #[error("accumulated fee out of range")]
    AccumulatedFeeOutOfRange,
    #[error("block is already known to be invalid")]
    Duplicate,
    #[error("undo data mismatch")]
    BadUndo,
    #[error("{0}")]
    Other(&'static str),
}

impl ValidationError {
    /// Core reject reason string.
    pub fn reject_reason(&self) -> &'static str {
        match self {
            Self::Block(e) => e.reject_reason(),
            Self::Tx(e) => e.reject_reason(),
            Self::Script { .. } => "mandatory-script-verify-flag-failed",
            Self::PrevBlkNotFound => "prev-blk-not-found",
            Self::BadPrevBlk => "bad-prevblk",
            Self::BadDiffBits => "bad-diffbits",
            Self::TimeTooOld => "time-too-old",
            Self::TimeTooNew => "time-too-new",
            Self::BadVersion(_) => "bad-version",
            Self::NonFinalTx => "bad-txns-nonfinal",
            Self::BadCbHeight => "bad-cb-height",
            Self::BadWitnessMerkleMatch => "bad-witness-merkle-match",
            Self::BadWitnessNonceSize => "bad-witness-nonce-size",
            Self::UnexpectedWitness => "unexpected-witness",
            Self::BadBlockWeight => "bad-blk-weight",
            Self::BadBlkSigops => "bad-blk-sigops",
            Self::NonBip68Final => "bad-txns-nonfinal",
            Self::BadCbAmount { .. } => "bad-cb-amount",
            Self::BipThirty => "bad-txns-BIP30",
            Self::AccumulatedFeeOutOfRange => "bad-txns-accumulated-fee-outofrange",
            Self::Duplicate => "duplicate",
            Self::BadUndo => "bad-undo",
            Self::Other(r) => r,
        }
    }
}
