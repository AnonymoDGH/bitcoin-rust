//! Sigop cost. Port of `GetLegacySigOpCount`, `GetP2SHSigOpCount` and
//! `GetTransactionSigOpCost` (consensus/tx_verify.cpp).

use btc_primitives::{Tx, TxOut};
use btc_script::ScriptVerifyFlags;

/// `MAX_BLOCK_SIGOPS_COST` (consensus/consensus.h).
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// `GetLegacySigOpCount`: inaccurate count over every scriptSig and scriptPubKey.
pub fn legacy_sigop_count(tx: &Tx) -> u32 {
    todo!()
}

/// `GetP2SHSigOpCount`. `spent[i]` is the output spent by input i. 0 for coinbase.
pub fn p2sh_sigop_count(tx: &Tx, spent: &[TxOut]) -> u32 {
    todo!()
}

/// `GetTransactionSigOpCost`: legacy*4 + (P2SH ? p2sh*4) + witness sigops.
pub fn transaction_sigop_cost(tx: &Tx, spent: &[TxOut], flags: ScriptVerifyFlags) -> u64 {
    todo!()
}
