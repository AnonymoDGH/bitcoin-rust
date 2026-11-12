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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectOptions {
    /// Run script verification (false = assumevalid-style skip).
    pub check_scripts: bool,
    /// Worker threads for script checks (<=1 = serial).
    pub script_threads: usize,
    /// Pool anchor considered fresh for note spends (chain tip root).
    pub pool_root: Option<[u8; 32]>,
    /// Anti-inflation funding ledger (`cmu -> max spendable sats`)
    /// from the chain being extended. Note spends must claim at most
    /// their cap; `None` disables the cap check (unit tests).
    pub pool_funding: Option<std::collections::HashMap<[u8; 32], u64>>,
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
    mut opts: ConnectOptions,
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
            // Fetch the inputs first so note spends (ledger replaced by
            // note values) and plain spends share the same structure.
            let spent: Vec<Coin> = tx
                .vin
                .iter()
                .map(|input| coins.get_coin(&input.prevout).ok_or(TxCheckError::MissingInputs))
                .collect::<Result<_, _>>()?;
            spent_outs = spent.iter().map(|coin| coin.txout.clone()).collect();

            let has_note_input = spent_outs
                .iter()
                .any(|o| crate::notes::is_pool_script(o.script_pubkey.as_bytes()));
            if has_note_input {
                let fee_note = crate::notes::verify_note_tx_block_with_caps(
                    tx,
                    &spent_outs,
                    opts.pool_root,
                    opts.pool_funding.as_ref(),
                )
                .map_err(|_| ValidationError::BadCt)?;
                fees += fee_note;
                if !(0..=MAX_MONEY).contains(&fees) {
                    return Err(ValidationError::AccumulatedFeeOutOfRange);
                }
            } else {
                // Ledger fee overstates the true fee for note-creating
                // txs by the locked note values: those sats move into
                // the pool (ledger value = funding cap), they are not
                // miner revenue. Subtract the caps so the coinbase can
                // only claim real fees — otherwise the note value is
                // minted twice (fee + later spend).
                let ledger_fee = check_tx_inputs(tx, coins, height)?;
                let pool_locked = if tx.vout.iter().any(|o| {
                    crate::notes::is_pool_script(o.script_pubkey.as_bytes())
                }) {
                    let input_values: Vec<i64> =
                        spent_outs.iter().map(|o| o.value).collect();
                    let caps =
                        crate::notes::funding_caps_for_block(tx, &input_values);
                    caps.iter().map(|(_, cap)| *cap as i64).sum::<i64>()
                } else {
                    0
                };
                // CT txs hide value from the ledger: the only sound
                // miner fee is the balance-proof public fee prefix
                // (proven on chain). The ledger fee would overstate
                // by the hidden amounts and mint them twice.
                let fee = if params.ct_enabled
                    && crate::confidential::is_ct_tx(tx, &spent_outs)
                {
                    crate::confidential::ct_public_fee(tx) as i64
                } else {
                    ledger_fee - pool_locked
                };
                if fee < 0 {
                    return Err(ValidationError::AccumulatedFeeOutOfRange);
                }
                fees += fee;
                if !(0..=MAX_MONEY).contains(&fees) {
                    return Err(ValidationError::AccumulatedFeeOutOfRange);
                }
            }

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

        // Confidential transactions are authorised by owner Schnorr signatures and
        // CT balance/range proofs, not by scriptPubKey execution.
        let mut is_ct = false;
        if params.ct_enabled && !is_coinbase {
            is_ct = tx.vout.iter().any(|o| crate::confidential::is_ct_script(o.script_pubkey.as_bytes()))
                || spent_outs.iter().any(|o| crate::confidential::is_ct_script(o.script_pubkey.as_bytes()));
            if is_ct {
                let check = |tx: &Tx, spent: &[TxOut], indices: &[usize]| {
                    crate::inputs::check_input_indices(tx, spent, flags, indices)
                };
                if crate::confidential::verify_ct_tx_block(tx, &spent_outs, &check).is_err() {
                    return Err(ValidationError::BadCt);
                }
            }
        }

        if !is_coinbase && opts.check_scripts && !is_ct {
            let plain_indices: Vec<usize> = spent_outs
                .iter()
                .enumerate()
                .filter(|(_, o)| !crate::notes::is_pool_script(o.script_pubkey.as_bytes()))
                .map(|(i, _)| i)
                .collect();
            crate::inputs::check_input_indices(tx, &spent_outs, flags, &plain_indices)?;
        }

        // Notes created earlier in this same block become spendable
        // with their funding cap for later txs in the block.
        if let Some(funding) = opts.pool_funding.as_mut() {
            let input_values: Vec<i64> = spent_outs.iter().map(|o| o.value).collect();
            for (cmu, cap) in crate::notes::funding_caps_for_block(tx, &input_values) {
                funding.insert(cmu, cap);
            }
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
    use btc_validation::coins::{CoinsView, CoinsViewMemory, CoinsViewWrite};

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

    #[test]
    fn note_spend_connects() {
        use crate::notes::{
            authorize_spend, decode_pool_note, encode_note, encode_path, encode_pool_note,
            encode_spend_auth, Note, NoteTree, NOTE_DEPTH,
        };
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use bitcoin::Witness;

        let mut f = Fixture::new(100);
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = 42;
        secret[31] = 3;
        let pubkey = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secret).unwrap(),
        )
        .serialize();
        let note = Note {
            spending_pub: pubkey,
            value: 25_00000000,
            rcm: [9u8; 32],
        };
        let cmu = crate::notes::note_commitment(&note);
        let pool_script = encode_pool_note(&cmu);
        assert_eq!(decode_pool_note(&pool_script), Some(cmu));

        let mut tree = NoteTree::new();
        assert_eq!(tree.insert(cmu), 0);
        let root = tree.root();

        // Block 1 spends a mature coinbase and appends the note output.
        let pool_outpoint_input = f.first_outpoint();
        let append_input = TxIn::new(pool_outpoint_input);
        let append_tx = Tx::new(2, vec![append_input], vec![TxOut::new(f.subsidy(101) - FEE, op_true()), TxOut::new(0, ScriptBuf::from_bytes(pool_script.clone()))], 0);
        let height1 = f.tree.get(f.tip).height + 1;
        let cb1 = coinbase_tx(height1, f.params.block_subsidy(height1));
        let (id1, block1) = next_block(&mut f.tree, f.tip, vec![cb1, append_tx.clone()], height1);
        connect(&mut f.base, &f.tree, &f.params, id1, &block1).unwrap();
        assert!(f.base.get_coin(&pool_outpoint_input).is_none());
        let note_outpoint = OutPoint {
            txid: append_tx.txid(),
            vout: 1,
        };

        // Block 2 spends the note.
        let anchor = root;
        let path = tree.path(0);
        let mut tx = Tx::new(2, vec![TxIn::new(note_outpoint)], vec![TxOut::new(24_99000000 / 1000, op_true())], 0);
        let context = crate::confidential::ct_context(&tx);
        let sig = authorize_spend(&note, &secret, &anchor, &context).unwrap();
        tx.vin[0].witness = Witness::from_slice(&[
            encode_note(&note),
            encode_spend_auth(&anchor, 0, &sig),
            encode_path(&path),
        ]);

        let height = f.tree.get(f.tip).height + 1;
        let fee_note: i64 = note.value as i64 - 24_99000000 / 1000;
        let cb = coinbase_tx(height, f.params.block_subsidy(height) + fee_note);
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, tx], 1000);
        let mut opts = ConnectOptions::default();
        opts.pool_root = Some(root);
        match connect_block(&block, &f.tree, id, &mut CoinsViewCache::new(&mut f.base), &f.params, opts) {
            Ok(_) => {}
            Err(e) => panic!("note block rejected: {e:?}"),
        }
    }

    /// Builds a confidential 1-in-1-out transaction spending `prevout`.
    fn ct_tx(
        prevout: OutPoint,
        ring: &[[u8; 33]],
        signer: usize,
        secret: &[u8; 32],
        r_in: [u8; 32],
        r_out: [u8; 32],
        value_in: u64,
        value_out: u64,
        in_script: &ScriptBuf,
        tamper: bool,
    ) -> Tx {
        use crate::confidential::{
            create_balance_proof, create_commitment, ct_context, encode_ct_script,
            serialize_balance_proof, with_fee, CtOutputData,
        };
        use bitcoin::Witness;
        use bitcoin_hashes::Hash as _;
        let _ = value_in;
        let out_c = create_commitment(value_out, r_out).unwrap();
        let out_data = CtOutputData {
            commitment: out_c.commitment,
            pubkey_hash: [7u8; 20],
            proof: out_c.proof,
        };
        let out_script = encode_ct_script(&out_data).unwrap();
        let mut input = TxIn::new(prevout);
        input.sequence = Sequence(Sequence::MAX.0);
        let mut tx = Tx::new(2, vec![input], vec![TxOut::new(0, out_script)], 0);
        let context = ct_context(&tx);
        let (proof, _) = create_balance_proof(&[r_in], &[r_out], 10_000, &context).unwrap();
        let mut proof_bytes = with_fee(serialize_balance_proof(&proof), 10_000);
        if tamper {
            proof_bytes[10] ^= 1;
        }
        // Owner authorisation: Schnorr sig by `ring[signer]` (the owner key)
        // over the per-input CT digest; witness [balance, sig, pubkey].
        let sighash = crate::confidential::ct_input_sighash(&context, 0, in_script.as_bytes());
        let (sig, pubkey) = crate::confidential::sign_ct_input(&sighash, secret).unwrap();
        let witness = Witness::from_slice(&[proof_bytes, sig.to_vec(), pubkey.to_vec()]);
        tx.vin[0].witness = witness;
        tx
    }

    #[test]
    fn ct_tx_connects_with_valid_proofs() {
        use crate::confidential::{create_commitment, encode_ct_script, CtOutputData};
        use btc_validation::coins::Coin;
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let mut f = Fixture::new(1);
        let mut params = f.params.clone();
        params.ct_enabled = true;

        let secp = Secp256k1::new();
        let mut secrets = Vec::new();
        let mut pubs: Vec<[u8; 33]> = Vec::new();
        for i in 1..=16u8 {
            let mut buf = [0u8; 32];
            buf[0] = i;
            buf[31] = 5;
            let sk = SecretKey::from_slice(&buf).unwrap();
            secrets.push(buf);
            pubs.push(PublicKey::from_secret_key(&secp, &sk).serialize());
        }
        let own = 3usize;
        let r_in = [11u8; 32];
        let r_out = [22u8; 32];
        let in_c = create_commitment(5_00000000u64, r_in).unwrap();
        let own_hash = bitcoin_hashes::hash160::Hash::hash(&pubs[own]).to_byte_array();
        let mut own_hash20 = [0u8; 20];
        own_hash20.copy_from_slice(&own_hash[..20]);
        let in_data = CtOutputData {
            commitment: in_c.commitment,
            pubkey_hash: own_hash20,
            proof: in_c.proof,
        };
        let in_script = encode_ct_script(&in_data).unwrap();
        let coin_outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[99u8; 32]).unwrap(),
            vout: 0,
        };
        f.base.batch_write(vec![(
            coin_outpoint,
            Some(Coin {
                txout: TxOut::new(0, in_script.clone()),
                height: 1,
                is_coinbase: false,
            }),
        )]);

        let tx = ct_tx(
            coin_outpoint,
            &pubs,
            own,
            &secrets[own],
            r_in,
            r_out,
            5_00000000,
            4_99990000,
            &in_script,
            false,
        );
        let height = f.tree.get(f.tip).height + 1;
        let cb = coinbase_tx(height, f.params.block_subsidy(height) + 10_000);
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, tx], height);
        let summary = connect(&mut f.base, &f.tree, &params, id, &block).unwrap();
        assert_eq!(summary.fees, 10_000, "miner fee is the balance-proof public fee");
        assert!(f.base.get_coin(&coin_outpoint).is_none());
    }

    #[test]
    fn ct_tx_with_forged_balance_proof_is_rejected() {
        use crate::confidential::{create_commitment, encode_ct_script, CtOutputData};
        use btc_validation::coins::Coin;
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let mut f = Fixture::new(1);
        let mut params = f.params.clone();
        params.ct_enabled = true;

        let secp = Secp256k1::new();
        let mut secrets = Vec::new();
        let mut pubs: Vec<[u8; 33]> = Vec::new();
        for i in 1..=16u8 {
            let mut buf = [0u8; 32];
            buf[0] = i;
            buf[31] = 5;
            let sk = SecretKey::from_slice(&buf).unwrap();
            secrets.push(buf);
            pubs.push(PublicKey::from_secret_key(&secp, &sk).serialize());
        }
        let own = 1usize;
        let r_in = [31u8; 32];
        let in_c = create_commitment(5_00000000u64, r_in).unwrap();
        let own_hash = bitcoin_hashes::hash160::Hash::hash(&pubs[own]).to_byte_array();
        let mut own_hash20 = [0u8; 20];
        own_hash20.copy_from_slice(&own_hash[..20]);
        let in_data = CtOutputData {
            commitment: in_c.commitment,
            pubkey_hash: own_hash20,
            proof: in_c.proof,
        };
        let in_script = encode_ct_script(&in_data).unwrap();
        let coin_outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[88u8; 32]).unwrap(),
            vout: 0,
        };
        f.base.batch_write(vec![(
            coin_outpoint,
            Some(Coin {
                txout: TxOut::new(0, in_script.clone()),
                height: 1,
                is_coinbase: false,
            }),
        )]);

        let tx = ct_tx(
            coin_outpoint,
            &pubs,
            own,
            &secrets[own],
            r_in,
            [44u8; 32],
            5_00000000,
            4_99990000,
            &in_script,
            true,
        );
        let height = f.tree.get(f.tip).height + 1;
        let cb = coinbase_tx(height, f.params.block_subsidy(height));
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, tx], height);
        assert_eq!(
            connect(&mut f.base, &f.tree, &params, id, &block).unwrap_err(),
            ValidationError::BadCt
        );
    }
    #[test]
    fn ct_tx_signed_by_non_owner_is_rejected_in_block() {
        use crate::confidential::{create_commitment, encode_ct_script, CtOutputData};
        use btc_validation::coins::Coin;
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let mut f = Fixture::new(1);
        let mut params = f.params.clone();
        params.ct_enabled = true;
        let secp = Secp256k1::new();
        let key = |i: u8| {
            let mut buf = [0u8; 32];
            buf[0] = i;
            buf[31] = 5;
            let sk = SecretKey::from_slice(&buf).unwrap();
            (buf, PublicKey::from_secret_key(&secp, &sk).serialize())
        };
        let (_vs, victim_pub) = key(1);
        let (attacker_secret, attacker_pub) = key(2);
        let r_in = [31u8; 32];
        let in_c = create_commitment(5_00000000u64, r_in).unwrap();
        let mut victim_hash = [0u8; 20];
        victim_hash.copy_from_slice(&bitcoin_hashes::hash160::Hash::hash(&victim_pub).to_byte_array()[..20]);
        let in_script = encode_ct_script(&CtOutputData {
            commitment: in_c.commitment,
            pubkey_hash: victim_hash,
            proof: in_c.proof,
        })
        .unwrap();
        let coin_outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[77u8; 32]).unwrap(),
            vout: 0,
        };
        f.base.batch_write(vec![(
            coin_outpoint,
            Some(Coin { txout: TxOut::new(0, in_script.clone()), height: 1, is_coinbase: false }),
        )]);
        // Attacker ring = victim + attacker (legacy theft shape); the signer
        // is the attacker, whose pubkey does not hash to the owner hash.
        let ring = vec![victim_pub, attacker_pub];
        let tx = ct_tx(coin_outpoint, &ring, 1, &attacker_secret, r_in, [44u8; 32], 5_00000000, 4_99990000, &in_script, false);
        let height = f.tree.get(f.tip).height + 1;
        let cb = coinbase_tx(height, f.params.block_subsidy(height) + 10_000);
        let (id, block) = next_block(&mut f.tree, f.tip, vec![cb, tx], height);
        assert_eq!(
            connect(&mut f.base, &f.tree, &params, id, &block).unwrap_err(),
            ValidationError::BadCt
        );
        assert!(f.base.get_coin(&coin_outpoint).is_some(), "victim coin untouched");
    }
}
