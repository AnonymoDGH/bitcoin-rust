//! Transaction verification. Port of `src/consensus/tx_check.cpp`
//! (`CheckTransaction`) and the non-script part of `src/consensus/tx_verify.cpp`
//! (`Consensus::CheckTxInputs`).
//!
//! Scripts and signatures are NOT verified here. `check_tx_inputs` only checks
//! that the spent coins exist, that coinbase outputs have matured, and that
//! value is conserved. Script execution belongs to a separate layer.

use std::collections::HashSet;

use bitcoin::OutPoint;
use btc_consensus::MAX_MONEY;
use btc_primitives::Tx;
use thiserror::Error;

use crate::coins::{Coin, CoinsView};

/// `MAX_BLOCK_WEIGHT` from `consensus/consensus.h`.
const MAX_BLOCK_WEIGHT: usize = 4_000_000;
/// `WITNESS_SCALE_FACTOR` from `consensus/consensus.h`.
const WITNESS_SCALE_FACTOR: usize = 4;
/// `COINBASE_MATURITY` from `consensus/consensus.h`.
const COINBASE_MATURITY: i64 = 100;
/// Allowed coinbase scriptSig length range, in bytes.
const MIN_COINBASE_SCRIPT_LEN: usize = 2;
const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// Validation failures. `reject_reason` gives the Core reject string.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TxCheckError {
    #[error("transaction has no inputs")]
    EmptyInputs,
    #[error("transaction has no outputs")]
    EmptyOutputs,
    #[error("transaction exceeds the block weight limit without witness data")]
    Oversize,
    #[error("output value is negative")]
    NegativeOutput,
    #[error("output value exceeds MAX_MONEY")]
    OutputTooLarge,
    #[error("sum of output values exceeds MAX_MONEY")]
    TotalOutputTooLarge,
    #[error("transaction spends the same outpoint twice")]
    DuplicateInputs,
    #[error("coinbase scriptSig length must be between 2 and 100 bytes")]
    BadCoinbaseLength,
    #[error("non-coinbase transaction has a null prevout")]
    NullPrevout,
    #[error("input coin is missing or already spent")]
    MissingInputs,
    #[error("tried to spend coinbase at depth {depth}")]
    PrematureCoinbaseSpend { depth: i64 },
    #[error("input value is out of range")]
    InputValueOutOfRange,
    #[error("total input value is below total output value")]
    InputsBelowOutputs,
    #[error("transaction fee is out of range")]
    FeeOutOfRange,
}

impl TxCheckError {
    /// The reject reason string used by Bitcoin Core in `TxValidationState`.
    pub fn reject_reason(&self) -> &'static str {
        match self {
            Self::EmptyInputs => "bad-txns-vin-empty",
            Self::EmptyOutputs => "bad-txns-vout-empty",
            Self::Oversize => "bad-txns-oversize",
            Self::NegativeOutput => "bad-txns-vout-negative",
            Self::OutputTooLarge => "bad-txns-vout-toolarge",
            Self::TotalOutputTooLarge => "bad-txns-txouttotal-toolarge",
            Self::DuplicateInputs => "bad-txns-inputs-duplicate",
            Self::BadCoinbaseLength => "bad-cb-length",
            Self::NullPrevout => "bad-txns-prevout-null",
            Self::MissingInputs => "bad-txns-inputs-missingorspent",
            Self::PrematureCoinbaseSpend { .. } => "bad-txns-premature-spend-of-coinbase",
            Self::InputValueOutOfRange => "bad-txns-inputvalues-outofrange",
            Self::InputsBelowOutputs => "bad-txns-in-belowout",
            Self::FeeOutOfRange => "bad-txns-fee-outofrange",
        }
    }
}

/// `MoneyRange()` from `consensus/amount.h`.
fn money_range(value: i64) -> bool {
    (0..=MAX_MONEY).contains(&value)
}

/// Serialized size without witness data (`TX_NO_WITNESS` in Core).
fn non_witness_size(tx: &Tx) -> usize {
    let mut buf = Vec::new();
    // Writing to a Vec cannot fail.
    tx.encode_with(&mut buf, false)
        .expect("in-memory writers cannot fail");
    buf.len()
}

/// Range-checks every output and returns the total output value.
fn check_output_values(tx: &Tx) -> Result<i64, TxCheckError> {
    let mut total: i64 = 0;
    for out in &tx.vout {
        if out.value < 0 {
            return Err(TxCheckError::NegativeOutput);
        }
        if out.value > MAX_MONEY {
            return Err(TxCheckError::OutputTooLarge);
        }
        // `total` is at most MAX_MONEY here (the check below returns otherwise),
        // and `out.value` is at most MAX_MONEY, so this addition cannot overflow.
        total += out.value;
        if !money_range(total) {
            return Err(TxCheckError::TotalOutputTooLarge);
        }
    }
    Ok(total)
}

/// Context-free transaction checks (`CheckTransaction`).
pub fn check_transaction(tx: &Tx) -> Result<(), TxCheckError> {
    if tx.vin.is_empty() {
        return Err(TxCheckError::EmptyInputs);
    }
    if tx.vout.is_empty() {
        return Err(TxCheckError::EmptyOutputs);
    }

    // Size is measured without witness data, because the witness has not been
    // checked for malleability yet.
    if non_witness_size(tx).saturating_mul(WITNESS_SCALE_FACTOR) > MAX_BLOCK_WEIGHT {
        return Err(TxCheckError::Oversize);
    }

    check_output_values(tx)?;

    // CVE-2018-17144: duplicate inputs must be rejected here, because the
    // UTXO layer does not detect them.
    let mut seen: HashSet<OutPoint> = HashSet::with_capacity(tx.vin.len());
    for input in &tx.vin {
        if !seen.insert(input.prevout) {
            return Err(TxCheckError::DuplicateInputs);
        }
    }

    if tx.is_coin_base() {
        let len = tx.vin[0].script_sig.len();
        if !(MIN_COINBASE_SCRIPT_LEN..=MAX_COINBASE_SCRIPT_LEN).contains(&len) {
            return Err(TxCheckError::BadCoinbaseLength);
        }
    } else if tx.vin.iter().any(|input| input.prevout.is_null()) {
        return Err(TxCheckError::NullPrevout);
    }

    Ok(())
}

/// Contextual input checks (`Consensus::CheckTxInputs`). Returns the fee
/// (sum of input values minus sum of output values) on success.
///
/// Does not verify scripts or signatures. Precondition: `tx` is not a coinbase
/// (Core asserts the same). Run `check_transaction` first, as Core does.
pub fn check_tx_inputs<V: CoinsView + ?Sized>(
    tx: &Tx,
    coins: &V,
    spend_height: u32,
) -> Result<i64, TxCheckError> {
    // Fetch every input before applying any other rule, so the first error
    // matches Core's HaveInputs() ordering.
    let mut spent: Vec<Coin> = Vec::with_capacity(tx.vin.len());
    for input in &tx.vin {
        match coins.get_coin(&input.prevout) {
            Some(coin) => spent.push(coin),
            None => return Err(TxCheckError::MissingInputs),
        }
    }

    let mut value_in: i64 = 0;
    for coin in &spent {
        // Signed on purpose: a coin created above the spend height gives a
        // negative depth, which Core also treats as immature.
        let depth = i64::from(spend_height) - i64::from(coin.height);
        if coin.is_coinbase && depth < COINBASE_MATURITY {
            return Err(TxCheckError::PrematureCoinbaseSpend { depth });
        }

        if !money_range(coin.txout.value) {
            return Err(TxCheckError::InputValueOutOfRange);
        }
        // Both operands are at most MAX_MONEY, so this addition cannot overflow.
        value_in += coin.txout.value;
        if !money_range(value_in) {
            return Err(TxCheckError::InputValueOutOfRange);
        }
    }

    let value_out = check_output_values(tx)?;
    if value_in < value_out {
        return Err(TxCheckError::InputsBelowOutputs);
    }

    let fee = value_in - value_out;
    if !money_range(fee) {
        return Err(TxCheckError::FeeOutOfRange);
    }
    Ok(fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{ScriptBuf, Txid};
    use bitcoin_hashes::Hash;
    use btc_consensus::COIN;
    use btc_primitives::{TxIn, TxOut};
    use std::collections::HashMap;

    fn outpoint(n: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout,
        }
    }

    fn txout(value: i64) -> TxOut {
        TxOut::new(value, ScriptBuf::new())
    }

    fn spend(prevout: OutPoint) -> TxIn {
        TxIn::new(prevout)
    }

    fn coinbase_tx(script_len: usize) -> Tx {
        let mut input = TxIn::default();
        input.script_sig = ScriptBuf::from_bytes(vec![0x51; script_len]);
        Tx::new(Tx::CURRENT_VERSION, vec![input], vec![txout(50 * COIN)], 0)
    }

    #[derive(Default)]
    struct MapView(HashMap<OutPoint, Coin>);

    impl CoinsView for MapView {
        fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
            self.0.get(outpoint).map(|c| Coin {
                txout: c.txout.clone(),
                height: c.height,
                is_coinbase: c.is_coinbase,
            })
        }
    }

    #[test]
    fn check_transaction_rejects_structural_errors() {
        let valid = Tx::new(2, vec![spend(outpoint(1, 0))], vec![txout(COIN)], 0);
        assert_eq!(check_transaction(&valid), Ok(()));

        let no_in = Tx::new(2, vec![], vec![txout(COIN)], 0);
        assert_eq!(check_transaction(&no_in), Err(TxCheckError::EmptyInputs));

        let no_out = Tx::new(2, vec![spend(outpoint(1, 0))], vec![], 0);
        assert_eq!(check_transaction(&no_out), Err(TxCheckError::EmptyOutputs));

        let dup = Tx::new(
            2,
            vec![spend(outpoint(1, 0)), spend(outpoint(1, 0))],
            vec![txout(COIN)],
            0,
        );
        assert_eq!(check_transaction(&dup), Err(TxCheckError::DuplicateInputs));

        // A null prevout is only allowed in a single-input coinbase.
        let null_prevout = Tx::new(
            2,
            vec![spend(outpoint(1, 0)), spend(OutPoint::null())],
            vec![txout(COIN)],
            0,
        );
        assert_eq!(check_transaction(&null_prevout), Err(TxCheckError::NullPrevout));

        let negative = Tx::new(2, vec![spend(outpoint(1, 0))], vec![txout(-1)], 0);
        assert_eq!(check_transaction(&negative), Err(TxCheckError::NegativeOutput));

        // Each output is within MAX_MONEY, but their sum is not.
        let total = Tx::new(
            2,
            vec![spend(outpoint(1, 0))],
            vec![txout(MAX_MONEY), txout(MAX_MONEY)],
            0,
        );
        assert_eq!(
            check_transaction(&total),
            Err(TxCheckError::TotalOutputTooLarge)
        );
        assert_eq!(
            TxCheckError::TotalOutputTooLarge.reject_reason(),
            "bad-txns-txouttotal-toolarge"
        );
    }

    #[test]
    fn coinbase_script_sig_length_bounds() {
        assert_eq!(
            check_transaction(&coinbase_tx(1)),
            Err(TxCheckError::BadCoinbaseLength)
        );
        assert_eq!(check_transaction(&coinbase_tx(2)), Ok(()));
        assert_eq!(check_transaction(&coinbase_tx(100)), Ok(()));
        assert_eq!(
            check_transaction(&coinbase_tx(101)),
            Err(TxCheckError::BadCoinbaseLength)
        );
    }

    #[test]
    fn check_tx_inputs_computes_fee_and_rejects_bad_value() {
        let mut view = MapView::default();
        view.0.insert(
            outpoint(1, 0),
            Coin {
                txout: txout(50 * COIN),
                height: 1,
                is_coinbase: false,
            },
        );

        let pays_fee = Tx::new(2, vec![spend(outpoint(1, 0))], vec![txout(49 * COIN)], 0);
        assert_eq!(check_tx_inputs(&pays_fee, &view, 200), Ok(COIN));

        let overspend = Tx::new(2, vec![spend(outpoint(1, 0))], vec![txout(51 * COIN)], 0);
        assert_eq!(
            check_tx_inputs(&overspend, &view, 200),
            Err(TxCheckError::InputsBelowOutputs)
        );

        let missing = Tx::new(2, vec![spend(outpoint(9, 0))], vec![txout(COIN)], 0);
        assert_eq!(
            check_tx_inputs(&missing, &view, 200),
            Err(TxCheckError::MissingInputs)
        );
    }

    #[test]
    fn check_tx_inputs_enforces_coinbase_maturity() {
        let mut view = MapView::default();
        view.0.insert(
            outpoint(2, 0),
            Coin {
                txout: txout(50 * COIN),
                height: 10,
                is_coinbase: true,
            },
        );
        let tx = Tx::new(2, vec![spend(outpoint(2, 0))], vec![txout(COIN)], 0);

        // Depth 99 is one block short of COINBASE_MATURITY.
        assert_eq!(
            check_tx_inputs(&tx, &view, 109),
            Err(TxCheckError::PrematureCoinbaseSpend { depth: 99 })
        );
        assert_eq!(check_tx_inputs(&tx, &view, 110), Ok(49 * COIN));
    }
}
