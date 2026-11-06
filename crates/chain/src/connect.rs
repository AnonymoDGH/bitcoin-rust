//! Applying and undoing a block on the UTXO set. Port of
//! `Chainstate::ConnectBlock`, `DisconnectBlock`, `UpdateCoins`,
//! `ApplyTxInUndo` (validation.cpp).

use bitcoin::OutPoint;
use btc_consensus::{ChainParams, MAX_MONEY};
use btc_primitives::{Block, Tx, TxOut};
use btc_validation::coins::{is_unspendable, Coin, CoinsView, CoinsViewCache};
use btc_validation::tx_verify::{check_tx_inputs, TxCheckError};
use btc_validation::undo::{BlockUndo, TxUndo};

use crate::contextual::block_script_flags;
use crate::finality::{calculate_sequence_locks, evaluate_sequence_locks};
use crate::inputs::check_input_scripts_parallel;
use crate::sigops::{transaction_sigop_cost, MAX_BLOCK_SIGOPS_COST};
use crate::{BlockTree, IndexId, ValidationError};

/// First height where a BIP34 coinbase could repeat an earlier one.
const BIP34_IMPLIES_BIP30_LIMIT: u32 = 1_983_702;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectOptions {
    /// Run script verification (false = assumevalid-style skip).
    pub check_scripts: bool,
    /// Worker threads for script checks (<=1 = serial).
    pub script_threads: usize,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self { check_scripts: true, script_threads: 1 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectSummary {
    pub undo: BlockUndo,
    pub fees: i64,
    pub sigop_cost: u64,
}

/// `ConnectBlock` for the block indexed at `id` (whose prev must be the
/// current tip of `coins`). Genesis (`height == 0`) is a no-op returning empty
/// undo. Runs, in Core order: BIP30 check (skip once BIP34 is active, except
/// Core's two historical exceptions only matter on mainnet), per-tx
/// `check_transaction` is assumed done by `check_block`; for each non-coinbase
/// tx: `check_tx_inputs`, BIP68 sequence locks (CSV active), sigop cost limit,
/// script checks with `block_script_flags`; then coinbase value <= fees +
/// subsidy. Applies all coin changes to `coins` (caller flushes on success).
pub fn connect_block(
    block: &Block,
    tree: &BlockTree,
    id: IndexId,
    coins: &mut CoinsViewCache<'_>,
    params: &ChainParams,
    opts: ConnectOptions,
) -> Result<ConnectSummary, ValidationError> {
    let index = tree.get(id);
    let height = index.height;
    let mut undo = BlockUndo::default();
    if height == 0 {
        return Ok(ConnectSummary { undo, fees: 0, sigop_cost: 0 });
    }

    let deployments = &params.deployments;
    // BIP34 stops duplicate coinbases only until BIP34_IMPLIES_BIP30_LIMIT.
    if height < deployments.bip34_height || height >= BIP34_IMPLIES_BIP30_LIMIT {
        for tx in &block.txdata {
            let txid = tx.txid();
            for vout in 0..tx.vout.len() {
                let outpoint = OutPoint { txid, vout: vout as u32 };
                if coins.have_coin(&outpoint) {
                    return Err(ValidationError::BipThirty);
                }
            }
        }
    }

    let flags = block_script_flags(height, &index.hash, params);
    let enforce_bip68 = height >= deployments.csv_height;
    let mut fees: i64 = 0;
    let mut sigop_cost: u64 = 0;

    for tx in &block.txdata {
        let is_coinbase = tx.is_coin_base();
        let mut spent_outs: Vec<TxOut> = Vec::new();
        if !is_coinbase {
            let fee = check_tx_inputs(tx, coins, height)?;
            fees += fee;
            if !(0..=MAX_MONEY).contains(&fees) {
                return Err(ValidationError::AccumulatedFeeOutOfRange);
            }

            let spent: Vec<Coin> = tx
                .vin
                .iter()
                .map(|input| coins.get_coin(&input.prevout).ok_or(TxCheckError::MissingInputs))
                .collect::<Result<_, _>>()?;
            spent_outs = spent.iter().map(|coin| coin.txout.clone()).collect();

            if enforce_bip68 {
                let mut prev_heights: Vec<i32> = spent.iter().map(|coin| coin.height as i32).collect();
                let lock = calculate_sequence_locks(tx, true, &mut prev_heights, &|h| {
                    let ancestor = tree
                        .get_ancestor(id, h as u32)
                        .expect("ancestor of a connected block exists");
                    tree.median_time_past(ancestor)
                });
                let prev = index.prev.ok_or(ValidationError::PrevBlkNotFound)?;
                if !evaluate_sequence_locks(height as i32, tree.median_time_past(prev), lock) {
                    return Err(ValidationError::NonBip68Final);
                }
            }
        }

        sigop_cost += transaction_sigop_cost(tx, &spent_outs, flags);
        if sigop_cost > MAX_BLOCK_SIGOPS_COST {
            return Err(ValidationError::BadBlkSigops);
        }

        if !is_coinbase && opts.check_scripts {
            check_input_scripts_parallel(tx, &spent_outs, flags, opts.script_threads)?;
        }

        update_coins(tx, coins, &mut undo, height)?;
    }

    let limit = fees + params.block_subsidy(height);
    let coinbase = block
        .txdata
        .first()
        .ok_or(ValidationError::Other("bad-cb-missing"))?;
    let actual = coinbase.value_out();
    if actual > limit {
        return Err(ValidationError::BadCbAmount { actual, limit });
    }

    Ok(ConnectSummary { undo, fees, sigop_cost })
}

/// `UpdateCoins`: spends each input (recording the coin in `undo` for
/// non-coinbase transactions), then adds the outputs at `height`.
fn update_coins(
    tx: &Tx,
    coins: &mut CoinsViewCache<'_>,
    undo: &mut BlockUndo,
    height: u32,
) -> Result<(), ValidationError> {
    let is_coinbase = tx.is_coin_base();
    if !is_coinbase {
        let mut tx_undo = TxUndo { prevout: Vec::with_capacity(tx.vin.len()) };
        for input in &tx.vin {
            let coin = coins
                .spend_coin(&input.prevout)
                .ok_or(TxCheckError::MissingInputs)?;
            tx_undo.prevout.push(coin);
        }
        undo.vtxundo.push(tx_undo);
    }

    let txid = tx.txid();
    for (vout, txout) in tx.vout.iter().enumerate() {
        let outpoint = OutPoint { txid, vout: vout as u32 };
        let coin = Coin { txout: txout.clone(), height, is_coinbase };
        coins
            .add_coin(outpoint, coin, is_coinbase)
            .map_err(|_| ValidationError::BipThirty)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectResult {
    Ok,
    /// Rolled back, but the UTXO set was inconsistent (Core DISCONNECT_UNCLEAN).
    Unclean,
    Failed,
}

/// `DisconnectBlock`: remove outputs created by `block` (at `height`) and
/// restore spent coins from `undo`, processing transactions in reverse.
pub fn disconnect_block(
    block: &Block,
    undo: &BlockUndo,
    height: u32,
    coins: &mut CoinsViewCache<'_>,
) -> DisconnectResult {
    if undo.vtxundo.len() + 1 != block.txdata.len() {
        return DisconnectResult::Failed;
    }

    let mut clean = true;
    for (index, tx) in block.txdata.iter().enumerate().rev() {
        let txid = tx.txid();
        let is_coinbase = tx.is_coin_base();

        for (vout, txout) in tx.vout.iter().enumerate() {
            if is_unspendable(&txout.script_pubkey) {
                continue;
            }
            let outpoint = OutPoint { txid, vout: vout as u32 };
            match coins.spend_coin(&outpoint) {
                Some(coin)
                    if coin.txout == *txout
                        && coin.height == height
                        && coin.is_coinbase == is_coinbase => {}
                _ => clean = false,
            }
        }

        if index > 0 {
            let tx_undo = &undo.vtxundo[index - 1];
            if tx_undo.prevout.len() != tx.vin.len() {
                return DisconnectResult::Failed;
            }
            for (input, coin) in tx.vin.iter().zip(&tx_undo.prevout).rev() {
                if coins.have_coin(&input.prevout) {
                    clean = false;
                }
                if coins.add_coin(input.prevout, coin.clone(), true).is_err() {
                    return DisconnectResult::Failed;
                }
            }
        }
    }

    if clean {
        DisconnectResult::Ok
    } else {
        DisconnectResult::Unclean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{ScriptBuf, Sequence, Txid, TxMerkleNode};
    use bitcoin_hashes::Hash;
    use btc_primitives::{BlockHash, BlockHeader, TxIn};
    use btc_validation::coins::{CoinsView, CoinsViewMemory};

    const BASE_TIME: u32 = 1_600_000_000;
    const FEE: i64 = 1_000;

    fn op_true() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    fn coinbase_tx(height: u32, value: i64) -> Tx {
        let mut script_sig = vec![0x04];
        script_sig.extend_from_slice(&height.to_le_bytes());
        let mut input = TxIn::new(OutPoint::null());
        input.script_sig = ScriptBuf::from_bytes(script_sig);
        Tx::new(1, vec![input], vec![TxOut::new(value, op_true())], 0)
    }

    fn spend_tx(version: u32, prevout: OutPoint, sequence: u32, value: i64) -> Tx {
        let mut input = TxIn::new(prevout);
        input.sequence = Sequence(sequence);
        Tx::new(version, vec![input], vec![TxOut::new(value, op_true())], 0)
    }

    fn genesis(tree: &mut BlockTree) -> IndexId {
        let header = BlockHeader::new(
            1,
            BlockHash::all_zeros(),
            TxMerkleNode::all_zeros(),
            BASE_TIME,
            0x207f_ffff,
            0,
        );
        tree.insert_header(header).unwrap()
    }

    /// Adds a header on top of `prev`. `nonce` keeps alternative blocks at the
    /// same height distinct.
    fn next_block(tree: &mut BlockTree, prev: IndexId, txdata: Vec<Tx>, nonce: u32) -> (IndexId, Block) {
        let parent = tree.get(prev);
        let header = BlockHeader::new(
            0x2000_0000,
            parent.hash,
            TxMerkleNode::all_zeros(),
            BASE_TIME + 600 * (parent.height + 1),
            0x207f_ffff,
            nonce,
        );
        let id = tree.insert_header(header).unwrap();
        (id, Block::new(header, txdata))
    }

    fn connect(
        base: &mut CoinsViewMemory,
        tree: &BlockTree,
        params: &ChainParams,
        id: IndexId,
        block: &Block,
    ) -> Result<ConnectSummary, ValidationError> {
        let mut cache = CoinsViewCache::new(base);
        let summary = connect_block(block, tree, id, &mut cache, params, ConnectOptions::default())?;
        cache.flush();
        Ok(summary)
    }

    /// Regtest chain with blocks 1..=last, each holding only a coinbase.
    struct Fixture {
        tree: BlockTree,
        base: CoinsViewMemory,
        params: ChainParams,
        tip: IndexId,
        first_coinbase: Tx,
    }

    impl Fixture {
        fn new(last: u32) -> Self {
            let params = ChainParams::regtest();
            let mut tree = BlockTree::new();
            let mut base = CoinsViewMemory::new();
            let mut tip = genesis(&mut tree);
            let mut first_coinbase = None;
            for height in 1..=last {
                let cb = coinbase_tx(height, params.block_subsidy(height));
                if height == 1 {
                    first_coinbase = Some(cb.clone());
                }
                let (id, block) = next_block(&mut tree, tip, vec![cb], height);
                connect(&mut base, &tree, &params, id, &block).unwrap();
                tip = id;
            }
            Self { tree, base, params, tip, first_coinbase: first_coinbase.unwrap() }
        }

        /// Output of the block-1 coinbase, the first spendable coin.
        fn first_outpoint(&self) -> OutPoint {
            OutPoint { txid: self.first_coinbase.txid(), vout: 0 }
        }

        fn subsidy(&self, height: u32) -> i64 {
            self.params.block_subsidy(height)
        }
    }

    #[test]
    fn coinbase_creates_coin_with_empty_undo() {
        let mut tree = BlockTree::new();
        let mut base = CoinsViewMemory::new();
        let params = ChainParams::regtest();
        let g = genesis(&mut tree);
        let cb = coinbase_tx(1, params.block_subsidy(1));
        let (id, block) = next_block(&mut tree, g, vec![cb.clone()], 1);

        let summary = connect(&mut base, &tree, &params, id, &block).unwrap();
        assert!(summary.undo.vtxundo.is_empty());
        assert_eq!(summary.fees, 0);
        assert_eq!(summary.sigop_cost, 0);

        let coin = base.get_coin(&OutPoint { txid: cb.txid(), vout: 0 }).unwrap();
        assert_eq!(coin.height, 1);
        assert!(coin.is_coinbase);
        assert_eq!(coin.txout.value, params.block_subsidy(1));
    }

    #[test]
    fn spend_of_matured_coinbase_pays_fee_to_coinbase() {
        let mut f = Fixture::new(100);
        let spend = spend_tx(1, f.first_outpoint(), Sequence::MAX.0, f.subsidy(1) - FEE);
        let cb = coinbase_tx(101, f.subsidy(101) + FEE);
        let spend_outpoint = OutPoint { txid: spend.txid(), vout: 0 };
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, spend], 101);

        let summary = connect(&mut f.base, &f.tree, &f.params, id, &block).unwrap();
        assert_eq!(summary.fees, FEE);
        assert_eq!(summary.undo.vtxundo.len(), 1);
        assert_eq!(summary.undo.vtxundo[0].prevout.len(), 1);
        assert_eq!(summary.undo.vtxundo[0].prevout[0].height, 1);
        assert!(f.base.get_coin(&f.first_outpoint()).is_none());
        assert!(f.base.get_coin(&spend_outpoint).is_some());
    }

    #[test]
    fn overpaying_coinbase_is_rejected() {
        let mut f = Fixture::new(100);
        let spend = spend_tx(1, f.first_outpoint(), Sequence::MAX.0, f.subsidy(1) - FEE);
        let cb = coinbase_tx(101, f.subsidy(101) + FEE + 1);
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, spend], 101);

        let err = connect(&mut f.base, &f.tree, &f.params, id, &block).unwrap_err();
        assert_eq!(
            err,
            ValidationError::BadCbAmount {
                actual: f.subsidy(101) + FEE + 1,
                limit: f.subsidy(101) + FEE,
            }
        );
    }

    #[test]
    fn premature_coinbase_spend_is_rejected() {
        let mut f = Fixture::new(99);
        let spend = spend_tx(1, f.first_outpoint(), Sequence::MAX.0, f.subsidy(1) - FEE);
        let cb = coinbase_tx(100, f.subsidy(100) + FEE);
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, spend], 100);

        let err = connect(&mut f.base, &f.tree, &f.params, id, &block).unwrap_err();
        assert_eq!(err, ValidationError::Tx(TxCheckError::PrematureCoinbaseSpend { depth: 99 }));
    }

    #[test]
    fn missing_input_is_rejected() {
        let mut f = Fixture::new(100);
        let missing = OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 };
        let spend = spend_tx(1, missing, Sequence::MAX.0, 1_000);
        let cb = coinbase_tx(101, f.subsidy(101));
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, spend], 101);

        let err = connect(&mut f.base, &f.tree, &f.params, id, &block).unwrap_err();
        assert_eq!(err, ValidationError::Tx(TxCheckError::MissingInputs));
    }

    #[test]
    fn disconnect_restores_utxo_set_and_second_disconnect_is_unclean() {
        let mut f = Fixture::new(100);
        let spend = spend_tx(1, f.first_outpoint(), Sequence::MAX.0, f.subsidy(1) - FEE);
        let cb = coinbase_tx(101, f.subsidy(101) + FEE);
        let cb_outpoint = OutPoint { txid: cb.txid(), vout: 0 };
        let spend_outpoint = OutPoint { txid: spend.txid(), vout: 0 };
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, spend], 101);

        let outpoints = [f.first_outpoint(), cb_outpoint, spend_outpoint];
        let before: Vec<Option<Coin>> = outpoints.iter().map(|o| f.base.get_coin(o)).collect();

        let undo = connect(&mut f.base, &f.tree, &f.params, id, &block).unwrap().undo;

        let disconnect = |base: &mut CoinsViewMemory| {
            let mut cache = CoinsViewCache::new(base);
            let result = disconnect_block(&block, &undo, 101, &mut cache);
            cache.flush();
            result
        };

        assert_eq!(disconnect(&mut f.base), DisconnectResult::Ok);
        let after: Vec<Option<Coin>> = outpoints.iter().map(|o| f.base.get_coin(o)).collect();
        assert_eq!(before, after);

        assert_eq!(disconnect(&mut f.base), DisconnectResult::Unclean);
    }

    #[test]
    fn bip68_relative_lock_not_yet_satisfied_is_rejected() {
        let mut f = Fixture::new(100);
        // Height-based lock of 200 on a coin created at height 1 needs height 200.
        let spend = spend_tx(2, f.first_outpoint(), 200, f.subsidy(1) - FEE);
        let cb = coinbase_tx(101, f.subsidy(101) + FEE);
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, spend], 101);
        let err = connect(&mut f.base, &f.tree, &f.params, id, &block).unwrap_err();
        assert_eq!(err, ValidationError::NonBip68Final);

        // A lock of 10 blocks is already satisfied at height 101.
        let spend = spend_tx(2, f.first_outpoint(), 10, f.subsidy(1) - FEE);
        let cb = coinbase_tx(101, f.subsidy(101) + FEE);
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, spend], 102);
        assert!(connect(&mut f.base, &f.tree, &f.params, id, &block).is_ok());
    }
}
