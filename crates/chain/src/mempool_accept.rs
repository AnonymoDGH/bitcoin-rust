//! Mempool admission. Port of `MemPoolAccept::PreChecks`/`PolicyScriptChecks`/
//! `ConsensusScriptChecks` (validation.cpp `AcceptToMemoryPool`), without
//! RBF and package relay.

use btc_primitives::{Tx, Txid};
use btc_validation::mempool::Mempool;

use crate::chainstate::Chainstate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolReject {
    /// Consensus-invalid (`TX_CONSENSUS`), with Core reject reason.
    Consensus(String),
    /// Policy (`TX_NOT_STANDARD`, fees, …), with Core reject reason.
    Policy(String),
    /// Inputs missing (orphan).
    MissingInputs,
    AlreadyKnown,
}

/// `AcceptToMemoryPool`: check_transaction, coinbase reject, is_standard_tx,
/// finality for next block, inputs from UTXO set + mempool parents,
/// check_tx_inputs-equivalent value checks, BIP68 locks, min relay fee
/// (DEFAULT_MIN_RELAY_TX_FEE 100 sat/kvB), standard script flags
/// (STANDARD_SCRIPT_VERIFY_FLAGS) then consensus flags. Adds to `mempool`.
pub fn accept_to_mempool(chainstate: &Chainstate, mempool: &mut Mempool, tx: Tx) -> Result<Txid, MempoolReject> {
    todo!()
}

/// After a block connects: drop confirmed and conflicting txs
/// (`removeForBlock`). After a disconnect: re-add the block's txs.
pub fn update_mempool_for_events(chainstate: &Chainstate, mempool: &mut Mempool, events: &[crate::chainstate::ChainEvent]) {
    todo!()
}
