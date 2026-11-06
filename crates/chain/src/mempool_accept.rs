//! Mempool admission. Port of `MemPoolAccept::PreChecks`/`PolicyScriptChecks`/
//! `ConsensusScriptChecks` (validation.cpp `AcceptToMemoryPool`), without
//! RBF and package relay.

use btc_primitives::{OutPoint, Tx, TxOut, Txid};
use btc_script::ScriptVerifyFlags;
use btc_validation::coins::{Coin, CoinsView};
use btc_validation::mempool::{Mempool, MempoolEntry, MempoolError};
use btc_validation::policy::{fee_for_vsize, get_transaction_weight, get_virtual_transaction_size, is_standard_tx};
use btc_validation::tx_verify::{check_transaction, check_tx_inputs};

use crate::chainstate::{ChainEvent, Chainstate};
use crate::contextual::block_script_flags;
use crate::finality::{calculate_sequence_locks, evaluate_sequence_locks, is_final_tx};
use crate::inputs::check_input_scripts;
use crate::sigops::transaction_sigop_cost;
use crate::ValidationError;

/// `MEMPOOL_HEIGHT`: coin height of an output created by a pool transaction.
const MEMPOOL_HEIGHT: u32 = 0x7FFF_FFFF;
/// `DEFAULT_MIN_RELAY_TX_FEE`, in satoshis per 1000 vbytes.
const MIN_RELAY_FEE_PER_KVB: u32 = 100;
/// `MAX_STANDARD_TX_SIGOPS_COST` = `MAX_BLOCK_SIGOPS_COST / 5`.
const MAX_STANDARD_TX_SIGOPS_COST: u64 = 16_000;
/// `DEFAULT_BYTES_PER_SIGOP`.
const BYTES_PER_SIGOP: i64 = 20;

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

/// `STANDARD_SCRIPT_VERIFY_FLAGS` (policy/policy.h).
fn standard_script_flags() -> ScriptVerifyFlags {
    ScriptVerifyFlags::P2SH
        | ScriptVerifyFlags::DERSIG
        | ScriptVerifyFlags::NULLDUMMY
        | ScriptVerifyFlags::CHECKLOCKTIMEVERIFY
        | ScriptVerifyFlags::CHECKSEQUENCEVERIFY
        | ScriptVerifyFlags::WITNESS
        | ScriptVerifyFlags::TAPROOT
        | ScriptVerifyFlags::STRICTENC
        | ScriptVerifyFlags::MINIMALDATA
        | ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_NOPS
        | ScriptVerifyFlags::CLEANSTACK
        | ScriptVerifyFlags::MINIMALIF
        | ScriptVerifyFlags::NULLFAIL
        | ScriptVerifyFlags::LOW_S
        | ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
        | ScriptVerifyFlags::WITNESS_PUBKEYTYPE
        | ScriptVerifyFlags::CONST_SCRIPTCODE
        | ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
        | ScriptVerifyFlags::DISCOURAGE_OP_SUCCESS
        | ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE
}

/// Chain UTXO set plus outputs of pool transactions (`CCoinsViewMemPool`).
struct PoolView<'a> {
    base: &'a dyn CoinsView,
    pool: &'a Mempool,
}

impl CoinsView for PoolView<'_> {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(entry) = self.pool.get(&outpoint.txid) {
            let txout = entry.tx.vout.get(outpoint.vout as usize)?.clone();
            return Some(Coin { txout, height: MEMPOOL_HEIGHT, is_coinbase: false });
        }
        self.base.get_coin(outpoint)
    }
}

/// Virtual size with the sigop-cost floor (`GetVirtualTransactionSize`).
fn virtual_size(weight: i64, sigop_cost: u64) -> i64 {
    get_virtual_transaction_size(weight.max(sigop_cost as i64 * BYTES_PER_SIGOP))
}

/// BIP68 check against the next block (`CheckSequenceLocks` at tip). Pool coins
/// count as confirmed at the next height.
fn sequence_locks_met(chainstate: &Chainstate, tx: &Tx, coins: &[Coin], next_height: u32) -> bool {
    let mut heights: Vec<i32> = coins
        .iter()
        .map(|coin| if coin.height == MEMPOOL_HEIGHT { next_height } else { coin.height } as i32)
        .collect();
    let ancestor_mtp = |h: i32| {
        chainstate
            .chain
            .get(h as u32)
            .map_or(0, |id| chainstate.tree.median_time_past(id))
    };
    let lock = calculate_sequence_locks(tx, true, &mut heights, &ancestor_mtp);
    evaluate_sequence_locks(next_height as i32, chainstate.median_time_past_tip(), lock)
}

/// True if any output of `tx` is an unspent coin in the chain UTXO set.
fn outputs_in_utxo(chainstate: &Chainstate, tx: &Tx) -> bool {
    let txid = tx.txid();
    (0..tx.vout.len() as u32).any(|vout| chainstate.coins_view().get_coin(&OutPoint { txid, vout }).is_some())
}

/// `AcceptToMemoryPool`: check_transaction, coinbase reject, is_standard_tx,
/// finality for next block, inputs from UTXO set + mempool parents,
/// check_tx_inputs-equivalent value checks, BIP68 locks, min relay fee
/// (DEFAULT_MIN_RELAY_TX_FEE 100 sat/kvB), standard script flags
/// (STANDARD_SCRIPT_VERIFY_FLAGS) then consensus flags. Adds to `mempool`.
pub fn accept_to_mempool(chainstate: &Chainstate, mempool: &mut Mempool, tx: Tx) -> Result<Txid, MempoolReject> {
    let txid = tx.txid();
    if mempool.contains(&txid) {
        return Err(MempoolReject::AlreadyKnown);
    }
    check_transaction(&tx).map_err(|e| MempoolReject::Consensus(e.reject_reason().into()))?;
    if tx.is_coin_base() {
        return Err(MempoolReject::Consensus("coinbase".into()));
    }
    is_standard_tx(&tx).map_err(|e| MempoolReject::Policy(e.reason().into()))?;

    let next_height = chainstate.height() + 1;
    if !is_final_tx(&tx, next_height as i32, chainstate.median_time_past_tip()) {
        return Err(MempoolReject::Policy("non-final".into()));
    }
    if tx.vin.iter().any(|input| mempool.spender_of(&input.prevout).is_some()) {
        return Err(MempoolReject::Policy("txn-mempool-conflict".into()));
    }

    let (spent, fee) = {
        let view = PoolView { base: chainstate.coins_view(), pool: &*mempool };
        let mut spent = Vec::with_capacity(tx.vin.len());
        for input in &tx.vin {
            match view.get_coin(&input.prevout) {
                Some(coin) => spent.push(coin),
                None if outputs_in_utxo(chainstate, &tx) => return Err(MempoolReject::AlreadyKnown),
                None => return Err(MempoolReject::MissingInputs),
            }
        }
        let fee = check_tx_inputs(&tx, &view, next_height)
            .map_err(|e| MempoolReject::Consensus(e.reject_reason().into()))?;
        (spent, fee)
    };

    if !sequence_locks_met(chainstate, &tx, &spent, next_height) {
        return Err(MempoolReject::Policy("non-BIP68-final".into()));
    }

    let spent_outs: Vec<TxOut> = spent.into_iter().map(|coin| coin.txout).collect();
    let sigop_cost = transaction_sigop_cost(&tx, &spent_outs, standard_script_flags());
    if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
        return Err(MempoolReject::Policy("bad-txns-too-many-sigops".into()));
    }
    let vsize = virtual_size(get_transaction_weight(&tx), sigop_cost);
    if fee < fee_for_vsize(MIN_RELAY_FEE_PER_KVB, vsize) {
        return Err(MempoolReject::Policy("min relay fee not met".into()));
    }

    if let Err(err) = check_input_scripts(&tx, &spent_outs, standard_script_flags()) {
        return Err(match err {
            ValidationError::Script { error, .. } => {
                MempoolReject::Policy(format!("mempool-script-verify-flag-failed ({error})"))
            }
            other => MempoolReject::Policy(other.reject_reason().into()),
        });
    }
    let block_flags = block_script_flags(next_height, &chainstate.tip_hash(), &chainstate.params);
    check_input_scripts(&tx, &spent_outs, block_flags)
        .map_err(|_| MempoolReject::Consensus("mandatory-script-verify-flag-failed".into()))?;

    mempool
        .add(MempoolEntry { tx, fee, vsize: vsize as u64 })
        .map_err(|e| match e {
            MempoolError::AlreadyInPool(_) => MempoolReject::AlreadyKnown,
            MempoolError::Conflict { .. } => MempoolReject::Policy("txn-mempool-conflict".into()),
            MempoolError::PoolFull { .. } => MempoolReject::Policy("mempool full".into()),
            other => MempoolReject::Policy(other.to_string()),
        })?;
    Ok(txid)
}

/// Removes `root` and every pool transaction spending its outputs.
fn evict_with_descendants(mempool: &mut Mempool, root: Txid) {
    let mut stack = vec![root];
    while let Some(txid) = stack.pop() {
        let Some(entry) = mempool.remove(&txid) else {
            continue;
        };
        for vout in 0..entry.tx.vout.len() as u32 {
            if let Some(child) = mempool.spender_of(&OutPoint { txid, vout }).copied() {
                stack.push(child);
            }
        }
    }
}

/// `removeForReorg`: drops pool transactions whose inputs are gone or that are
/// no longer final, or whose locks or maturity fail at the new tip.
fn drop_invalid_after_reorg(chainstate: &Chainstate, mempool: &mut Mempool) {
    let txids: Vec<Txid> = mempool.sorted_by_fee_rate().iter().map(|entry| entry.tx.txid()).collect();
    for txid in txids {
        let Some(entry) = mempool.get(&txid) else {
            continue;
        };
        if !still_valid(chainstate, mempool, &entry.tx) {
            evict_with_descendants(mempool, txid);
        }
    }
}

fn still_valid(chainstate: &Chainstate, mempool: &Mempool, tx: &Tx) -> bool {
    let next_height = chainstate.height() + 1;
    if !is_final_tx(tx, next_height as i32, chainstate.median_time_past_tip()) {
        return false;
    }
    let view = PoolView { base: chainstate.coins_view(), pool: mempool };
    let coins: Option<Vec<Coin>> = tx.vin.iter().map(|input| view.get_coin(&input.prevout)).collect();
    match coins {
        Some(coins) => {
            check_tx_inputs(tx, &view, next_height).is_ok() && sequence_locks_met(chainstate, tx, &coins, next_height)
        }
        None => false,
    }
}

/// After a block connects: drop confirmed and conflicting txs
/// (`removeForBlock`). After a disconnect: re-add the block's txs.
pub fn update_mempool_for_events(chainstate: &Chainstate, mempool: &mut Mempool, events: &[ChainEvent]) {
    let mut disconnected: Vec<&[Tx]> = Vec::new();
    for event in events {
        match event {
            ChainEvent::BlockConnected { hash, .. } => {
                let Some(block) = chainstate.get_block(hash) else {
                    continue;
                };
                for tx in &block.txdata {
                    mempool.remove(&tx.txid());
                    mempool.remove_conflicts(tx);
                }
            }
            ChainEvent::BlockDisconnected { txs, .. } => disconnected.push(txs),
        }
    }

    // Lowest block first and in block order, so parents return before children.
    for txs in disconnected.into_iter().rev() {
        for tx in txs.iter().filter(|tx| !tx.is_coin_base()) {
            let _ = accept_to_mempool(chainstate, mempool, tx.clone());
        }
    }
    drop_invalid_after_reorg(chainstate, mempool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{ScriptBuf, TxMerkleNode, WScriptHash};
    use bitcoin_hashes::Hash as _;
    use btc_consensus::ChainParams;
    use btc_primitives::{Block, BlockHash, BlockHeader, TxIn, Witness};
    use btc_validation::block_verify::block_merkle_root;
    use btc_validation::coins::CoinsViewMemory;

    use crate::chainstate::MemBlockStore;
    use crate::contextual::bip34_height_script;

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const NOW: i64 = 2_000_000_000;
    const FEE: i64 = 1_000;

    fn op_true() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    /// P2WSH(OP_TRUE): a standard output, spent with witness `[0x51]`.
    fn p2wsh_true() -> ScriptBuf {
        ScriptBuf::new_p2wsh(&WScriptHash::hash(&[0x51]))
    }

    fn subsidy(height: u32) -> i64 {
        ChainParams::regtest().block_subsidy(height)
    }

    /// Spends `prevout` (bare OP_TRUE, or P2WSH(OP_TRUE) when `segwit`) into one
    /// P2WSH(OP_TRUE) output worth `value`.
    fn spend(prevout: OutPoint, segwit: bool, value: i64) -> Tx {
        let mut input = TxIn::new(prevout);
        if segwit {
            input.witness = Witness::from_slice(&[vec![0x51u8]]);
        }
        Tx::new(2, vec![input], vec![TxOut::new(value, p2wsh_true())], 0)
    }

    /// Increments the nonce until the header meets the regtest target.
    fn grind(mut header: BlockHeader) -> BlockHeader {
        let params = ChainParams::regtest();
        while btc_validation::block_verify::check_block_header(&header, &params).is_err() {
            header.nonce += 1;
        }
        header
    }

    /// Regtest block on top of `parent`: BIP34 coinbase paying OP_TRUE (the
    /// `tag` byte keeps coinbases distinct across branches), then `txs`.
    fn mine(parent: &BlockHeader, parent_height: u32, txs: Vec<Tx>, cb_value: i64, tag: u8) -> Block {
        let height = parent_height + 1;
        let mut script_sig = bip34_height_script(height);
        script_sig.extend_from_slice(&[0x01, tag]);
        let mut input = TxIn::new(OutPoint::null());
        input.script_sig = ScriptBuf::from_bytes(script_sig);
        let mut txdata = vec![Tx::new(1, vec![input], vec![TxOut::new(cb_value, op_true())], 0)];
        txdata.extend(txs);

        let header = BlockHeader::new(
            0x2000_0000,
            parent.block_hash(),
            TxMerkleNode::all_zeros(),
            parent.time + 600,
            REGTEST_BITS,
            0,
        );
        let mut block = Block::new(header, txdata);
        block.header.merkle_root = block_merkle_root(&block).0;
        block.header = grind(block.header);
        block
    }

    /// Builds `count` blocks on `parent` and processes each one as new.
    fn extend(cs: &mut Chainstate, parent: BlockHash, count: u32, tag: u8) -> Vec<Block> {
        let (mut header, mut height) = cs.header_of(&parent).expect("parent is known");
        let mut blocks = Vec::new();
        for _ in 0..count {
            let block = mine(&header, height, vec![], subsidy(height + 1), tag);
            assert_eq!(cs.process_new_block(&block, NOW), Ok(true));
            header = block.header;
            height += 1;
            blocks.push(block);
        }
        blocks
    }

    /// Hard-coded regtest genesis (Core's `CreateGenesisBlock`).
    fn regtest_genesis() -> Block {
        const TIMESTAMP: &[u8] = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        const PUBKEY: &str = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";

        let mut script_sig = vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, TIMESTAMP.len() as u8];
        script_sig.extend_from_slice(TIMESTAMP);
        let mut script_pubkey = vec![0x41];
        script_pubkey.extend((0..PUBKEY.len()).step_by(2).map(|i| u8::from_str_radix(&PUBKEY[i..i + 2], 16).unwrap()));
        script_pubkey.push(0xac);

        let mut input = TxIn::new(OutPoint::null());
        input.script_sig = ScriptBuf::from_bytes(script_sig);
        let coinbase = Tx::new(1, vec![input], vec![TxOut::new(50 * 100_000_000, ScriptBuf::from_bytes(script_pubkey))], 0);
        let mut block = Block::new(
            BlockHeader::new(1, BlockHash::all_zeros(), TxMerkleNode::all_zeros(), 1_296_688_602, REGTEST_BITS, 2),
            vec![coinbase],
        );
        block.header.merkle_root = block_merkle_root(&block).0;
        block
    }

    fn new_chain() -> Chainstate {
        Chainstate::new(
            ChainParams::regtest(),
            regtest_genesis(),
            Box::new(CoinsViewMemory::new()),
            Box::new(MemBlockStore::default()),
        )
        .expect("regtest genesis loads")
    }

    fn genesis_hash() -> BlockHash {
        ChainParams::regtest().genesis_hash
    }

    fn coinbase_outpoint(block: &Block) -> OutPoint {
        OutPoint { txid: block.txdata[0].txid(), vout: 0 }
    }

    /// A chain of 101 blocks, so the height-1 coinbase is mature at tip + 1.
    fn chain_with_mature_coinbases() -> (Chainstate, Vec<Block>) {
        let mut cs = new_chain();
        let main = extend(&mut cs, genesis_hash(), 101, 0);
        cs.take_events();
        (cs, main)
    }

    #[test]
    fn valid_spend_is_accepted_then_already_known() {
        let (cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let tx = spend(coinbase_outpoint(&main[0]), false, subsidy(1) - FEE);
        let txid = tx.txid();

        assert_eq!(accept_to_mempool(&cs, &mut pool, tx.clone()), Ok(txid));
        assert!(pool.contains(&txid));
        assert_eq!(pool.get(&txid).unwrap().fee, FEE);
        assert_eq!(accept_to_mempool(&cs, &mut pool, tx), Err(MempoolReject::AlreadyKnown));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn missing_input_is_orphan() {
        let (cs, _main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let stray = OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 };
        let tx = spend(stray, false, 1_000_000);
        assert_eq!(accept_to_mempool(&cs, &mut pool, tx), Err(MempoolReject::MissingInputs));
        assert!(pool.is_empty());
    }

    #[test]
    fn double_spend_is_rejected_as_mempool_conflict() {
        let (cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let outpoint = coinbase_outpoint(&main[0]);
        accept_to_mempool(&cs, &mut pool, spend(outpoint, false, subsidy(1) - FEE)).unwrap();

        let rival = spend(outpoint, false, subsidy(1) - 2 * FEE);
        assert_eq!(
            accept_to_mempool(&cs, &mut pool, rival),
            Err(MempoolReject::Policy("txn-mempool-conflict".into()))
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn child_spending_mempool_parent_is_accepted() {
        let (cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let parent = spend(coinbase_outpoint(&main[0]), false, subsidy(1) - FEE);
        let parent_id = parent.txid();
        accept_to_mempool(&cs, &mut pool, parent).unwrap();

        let child = spend(OutPoint { txid: parent_id, vout: 0 }, true, subsidy(1) - 2 * FEE);
        let child_id = child.txid();
        assert_eq!(accept_to_mempool(&cs, &mut pool, child), Ok(child_id));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.get(&child_id).unwrap().fee, FEE);
    }

    #[test]
    fn zero_fee_fails_min_relay() {
        let (cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let tx = spend(coinbase_outpoint(&main[0]), false, subsidy(1));
        assert_eq!(
            accept_to_mempool(&cs, &mut pool, tx),
            Err(MempoolReject::Policy("min relay fee not met".into()))
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn non_standard_output_is_rejected() {
        let (cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let mut tx = spend(coinbase_outpoint(&main[0]), false, subsidy(1) - FEE);
        tx.vout[0].script_pubkey = op_true();
        assert_eq!(accept_to_mempool(&cs, &mut pool, tx), Err(MempoolReject::Policy("scriptpubkey".into())));
    }

    #[test]
    fn failing_witness_script_is_policy_reject() {
        let (cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let mut tx = spend(coinbase_outpoint(&main[0]), true, subsidy(1) - FEE);
        tx.vin[0].witness = Witness::from_slice(&[vec![0x00u8]]);
        let result = accept_to_mempool(&cs, &mut pool, tx);
        assert!(
            matches!(&result, Err(MempoolReject::Policy(r)) if r.starts_with("mempool-script-verify-flag-failed")),
            "got {result:?}"
        );
    }

    #[test]
    fn immature_coinbase_spend_is_consensus_reject() {
        let (cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        // Height 50 coinbase at tip 101: depth 52, below COINBASE_MATURITY.
        let tx = spend(coinbase_outpoint(&main[49]), false, subsidy(50) - FEE);
        assert_eq!(
            accept_to_mempool(&cs, &mut pool, tx),
            Err(MempoolReject::Consensus("bad-txns-premature-spend-of-coinbase".into()))
        );
    }

    #[test]
    fn confirmed_tx_leaves_mempool_and_disconnect_restores_it() {
        let (mut cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let tx = spend(coinbase_outpoint(&main[0]), false, subsidy(1) - FEE);
        let txid = tx.txid();
        accept_to_mempool(&cs, &mut pool, tx.clone()).unwrap();

        let (tip_header, tip_height) = cs.header_of(&cs.tip_hash()).unwrap();
        let block = mine(&tip_header, tip_height, vec![tx], subsidy(102) + FEE, 0);
        assert_eq!(cs.process_new_block(&block, NOW), Ok(true));
        let events = cs.take_events();
        update_mempool_for_events(&cs, &mut pool, &events);
        assert!(pool.is_empty());

        cs.invalidate_block(&block.block_hash()).unwrap();
        let events = cs.take_events();
        update_mempool_for_events(&cs, &mut pool, &events);
        assert!(pool.contains(&txid), "disconnected tx returns to the mempool");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn block_spending_same_coin_evicts_pool_conflict() {
        let (mut cs, main) = chain_with_mature_coinbases();
        let mut pool = Mempool::new(100);
        let pool_tx = spend(coinbase_outpoint(&main[0]), false, subsidy(1) - FEE);
        let pool_txid = pool_tx.txid();
        accept_to_mempool(&cs, &mut pool, pool_tx).unwrap();

        let rival = spend(coinbase_outpoint(&main[0]), false, subsidy(1) - 2 * FEE);
        let (tip_header, tip_height) = cs.header_of(&cs.tip_hash()).unwrap();
        let block = mine(&tip_header, tip_height, vec![rival], subsidy(102) + 2 * FEE, 0);
        assert_eq!(cs.process_new_block(&block, NOW), Ok(true));
        let events = cs.take_events();
        update_mempool_for_events(&cs, &mut pool, &events);
        assert!(!pool.contains(&pool_txid));
        assert!(pool.is_empty());
    }
}
