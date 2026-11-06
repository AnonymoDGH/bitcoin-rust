//! Undo data. Port of `src/undo.h` (`CTxUndo`, `CBlockUndo`).

use crate::coins::Coin;

/// Coins spent by one transaction, in input order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxUndo {
    pub prevout: Vec<Coin>,
}

/// Undo data for a block: one `TxUndo` per non-coinbase transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockUndo {
    pub vtxundo: Vec<TxUndo>,
}
