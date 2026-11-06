//! Block assembly. Port of `BlockAssembler::CreateNewBlock`,
//! `addPackageTxs` (ancestor fee-rate selection) and `IncrementExtraNonce` /
//! nonce grinding from `node/miner.cpp` and `rpc/mining.cpp::GenerateBlock`.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

use bitcoin::TxMerkleNode;
use bitcoin_hashes::Hash as _;
use btc_consensus::decode_compact;
use btc_primitives::{Block, BlockHash, BlockHeader, OutPoint, ScriptBuf, Tx, TxIn, TxOut, Txid};
use btc_script::ScriptVerifyFlags;
use btc_validation::block_verify::{block_merkle_root, MAX_BLOCK_WEIGHT};
use btc_validation::coins::CoinsView;
use btc_validation::mempool::Mempool;
use btc_validation::policy::get_transaction_weight;
use primitive_types::U256;

use crate::chainstate::Chainstate;
use crate::contextual::{bip34_height_script, block_script_flags};
use crate::finality::{calculate_sequence_locks, evaluate_sequence_locks, is_final_tx};
use crate::sigops::{transaction_sigop_cost, MAX_BLOCK_SIGOPS_COST};
use crate::witness::generate_coinbase_commitment;
use crate::ValidationError;

const BLOCK_VERSION: i32 = 0x2000_0000;
const COINBASE_RESERVED_WEIGHT: u64 = 4_000;
const COINBASE_RESERVED_SIGOPS: u64 = 400;
const TX_WEIGHT_BUDGET: u64 = MAX_BLOCK_WEIGHT as u64 - COINBASE_RESERVED_WEIGHT;
const TX_SIGOPS_BUDGET: u64 = MAX_BLOCK_SIGOPS_COST - COINBASE_RESERVED_SIGOPS;

#[derive(Clone, Debug)]
pub struct BlockTemplate {
    pub block: Block,
    pub height: u32,
    /// Per-tx fees (coinbase entry = -total fees, as Core).
    pub fees: Vec<i64>,
    pub sigop_costs: Vec<u64>,
}

/// `CreateNewBlock` on top of the current tip: coinbase (BIP34 height push +
/// extra nonce, pays subsidy + fees to `coinbase_script`), mempool txs by
/// ancestor fee rate (parents before children, only txs whose inputs exist in
/// the UTXO set or earlier in the block, final at height/MTP), under weight
/// and sigop limits, witness commitment, merkle root, nBits from
/// `next_work_required`, time = max(MTP+1, now).
pub fn create_new_block(chainstate: &Chainstate, mempool: &Mempool, coinbase_script: ScriptBuf, now: i64) -> BlockTemplate {
    create_new_block_with_extra_nonce(chainstate, mempool, coinbase_script, now, 0)
}

/// `create_new_block` with `extra_nonce` pushed into the coinbase scriptSig,
/// giving a fresh merkle root once the header nonce space is exhausted.
pub fn create_new_block_with_extra_nonce(
    chainstate: &Chainstate,
    mempool: &Mempool,
    coinbase_script: ScriptBuf,
    now: i64,
    extra_nonce: u64,
) -> BlockTemplate {
    let params = &chainstate.params;
    let height = chainstate.height() + 1;
    let mtp = chainstate.median_time_past_tip();
    let time = (mtp + 1).max(now);

    let mut header = BlockHeader::new(BLOCK_VERSION, chainstate.tip_hash(), TxMerkleNode::all_zeros(), time as u32, 0, 0);
    header.bits = chainstate.tree.next_work_required(chainstate.tip(), &header, params);

    let lock_cutoff = if height >= params.deployments.csv_height { mtp } else { time };
    let flags = block_script_flags(height, &BlockHash::all_zeros(), params);
    let assembly = Assembly {
        chainstate,
        mempool,
        height,
        lock_cutoff,
        flags,
        parents: HashMap::new(),
        children: HashMap::new(),
    }
    .with_pool_graph();
    let selected = assembly.select();

    let total_fees: i64 = selected.iter().map(|s| s.fee).sum();
    let coinbase = coinbase_tx(height, extra_nonce, coinbase_script, params.block_subsidy(height) + total_fees);
    let mut fees = vec![-total_fees];
    let mut sigop_costs = vec![transaction_sigop_cost(&coinbase, &[], flags)];
    let mut txdata = vec![coinbase];
    for member in selected {
        fees.push(member.fee);
        sigop_costs.push(member.sigop_cost);
        txdata.push(member.tx);
    }

    let mut block = Block::new(header, txdata);
    if height >= params.deployments.segwit_height || block.txdata.iter().any(Tx::has_witness) {
        generate_coinbase_commitment(&mut block);
    }
    block.header.merkle_root = block_merkle_root(&block).0;
    BlockTemplate { block, height, fees, sigop_costs }
}

/// Grind header nonce (bumping time on wrap is the caller's job). Returns true
/// once `block_hash <= target(bits)`; false after `max_tries`.
pub fn mine_block(block: &mut Block, max_tries: u64) -> bool {
    let Ok(target) = decode_compact(block.header.bits) else {
        return false;
    };
    for nonce in 0..max_tries.min(1 << 32) {
        block.header.nonce = nonce as u32;
        if U256::from_little_endian(&block.block_hash().to_byte_array()) <= target {
            return true;
        }
    }
    false
}

/// `GenerateBlock`: assembles on the tip, grinds the nonce and submits the
/// block with `process_new_block`. When the nonce space runs out the extra
/// nonce and the time are bumped and the search restarts.
pub fn generate_block(
    chainstate: &mut Chainstate,
    mempool: &Mempool,
    coinbase_script: ScriptBuf,
    now: i64,
) -> Result<BlockHash, ValidationError> {
    let mut attempt = 0u64;
    loop {
        let mut template = create_new_block_with_extra_nonce(
            chainstate,
            mempool,
            coinbase_script.clone(),
            now + attempt as i64,
            attempt,
        );
        if mine_block(&mut template.block, 1 << 32) {
            let hash = template.block.block_hash();
            chainstate.process_new_block(&template.block, now)?;
            return Ok(hash);
        }
        attempt += 1;
    }
}

struct Selected {
    tx: Tx,
    fee: i64,
    sigop_cost: u64,
    weight: u64,
}

/// Ancestor-package score: fee and vsize of a transaction plus its
/// not-yet-included ancestors. Ordered by fee rate, then txid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Score {
    fee: i64,
    vsize: u64,
    txid: Txid,
}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> Ordering {
        let lhs = i128::from(self.fee) * i128::from(other.vsize);
        let rhs = i128::from(other.fee) * i128::from(self.vsize);
        lhs.cmp(&rhs).then_with(|| self.txid.cmp(&other.txid))
    }
}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct Assembly<'a> {
    chainstate: &'a Chainstate,
    mempool: &'a Mempool,
    height: u32,
    lock_cutoff: i64,
    flags: ScriptVerifyFlags,
    /// In-pool parents of each pool transaction.
    parents: HashMap<Txid, Vec<Txid>>,
    /// In-pool children of each pool transaction.
    children: HashMap<Txid, Vec<Txid>>,
}

impl<'a> Assembly<'a> {
    fn with_pool_graph(mut self) -> Self {
        for entry in self.mempool.sorted_by_fee_rate() {
            let txid = entry.tx.txid();
            let mut links: Vec<Txid> = Vec::new();
            for input in &entry.tx.vin {
                let parent = input.prevout.txid;
                if self.mempool.contains(&parent) && !links.contains(&parent) {
                    links.push(parent);
                }
            }
            for parent in &links {
                self.children.entry(*parent).or_default().push(txid);
            }
            self.parents.insert(txid, links);
        }
        self
    }

    /// Repeatedly takes the pool transaction whose not-yet-included ancestor
    /// package has the highest fee rate and includes that package. Packages
    /// that do not fit, or contain a non-final or unspendable transaction, are
    /// dropped together with their descendants.
    fn select(&self) -> Vec<Selected> {
        let mut scores: HashMap<Txid, Score> = HashMap::new();
        let mut ordered: BTreeSet<Score> = BTreeSet::new();
        for &txid in self.parents.keys() {
            let Some(own) = self.mempool.get(&txid) else {
                continue;
            };
            let (mut fee, mut vsize) = (own.fee, own.vsize);
            for ancestor in reachable(txid, &self.parents) {
                if let Some(entry) = self.mempool.get(&ancestor) {
                    fee += entry.fee;
                    vsize += entry.vsize;
                }
            }
            let score = Score { fee, vsize, txid };
            scores.insert(txid, score);
            ordered.insert(score);
        }

        let mut included: HashSet<Txid> = HashSet::new();
        let mut selected = Vec::new();
        let (mut weight_used, mut sigops_used) = (0u64, 0u64);

        while let Some(next) = ordered.iter().next_back().copied() {
            ordered.remove(&next);
            scores.remove(&next.txid);
            let package = package_order(next.txid, &self.parents, &included);

            let Some(members) = self.evaluate_package(&package, weight_used, sigops_used) else {
                for descendant in reachable(next.txid, &self.children) {
                    if let Some(score) = scores.remove(&descendant) {
                        ordered.remove(&score);
                    }
                }
                continue;
            };

            for txid in &package {
                included.insert(*txid);
                if let Some(score) = scores.remove(txid) {
                    ordered.remove(&score);
                }
            }
            for txid in &package {
                let Some(own) = self.mempool.get(txid) else {
                    continue;
                };
                for descendant in reachable(*txid, &self.children) {
                    if included.contains(&descendant) {
                        continue;
                    }
                    if let Some(old) = scores.get(&descendant).copied() {
                        ordered.remove(&old);
                        let new = Score {
                            fee: old.fee - own.fee,
                            vsize: old.vsize - own.vsize,
                            txid: descendant,
                        };
                        ordered.insert(new);
                        scores.insert(descendant, new);
                    }
                }
            }
            for member in &members {
                weight_used += member.weight;
                sigops_used += member.sigop_cost;
            }
            selected.extend(members);
        }
        selected
    }

    /// Checks every package member in order and the weight and sigop budgets
    /// with the package added. Returns the members with their costs.
    fn evaluate_package(&self, package: &[Txid], weight_used: u64, sigops_used: u64) -> Option<Vec<Selected>> {
        let (mut weight, mut sigops) = (weight_used, sigops_used);
        let mut members = Vec::with_capacity(package.len());
        for txid in package {
            let entry = self.mempool.get(txid)?;
            let sigop_cost = self.check_tx(&entry.tx)?;
            let tx_weight = get_transaction_weight(&entry.tx) as u64;
            weight += tx_weight;
            sigops += sigop_cost;
            if weight > TX_WEIGHT_BUDGET || sigops > TX_SIGOPS_BUDGET {
                return None;
            }
            members.push(Selected {
                tx: entry.tx.clone(),
                fee: entry.fee,
                sigop_cost,
                weight: tx_weight,
            });
        }
        Some(members)
    }

    /// Final, BIP68-satisfied, with every input available. Returns its sigop cost.
    fn check_tx(&self, tx: &Tx) -> Option<u64> {
        if !is_final_tx(tx, self.height as i32, self.lock_cutoff) {
            return None;
        }
        let coins = self.chainstate.coins_view();
        let mut spent = Vec::with_capacity(tx.vin.len());
        let mut prev_heights = Vec::with_capacity(tx.vin.len());
        for input in &tx.vin {
            let (txout, coin_height) = spent_output(&input.prevout, self.mempool, coins, self.height)?;
            spent.push(txout);
            prev_heights.push(coin_height as i32);
        }
        if self.height >= self.chainstate.params.deployments.csv_height {
            let lock = calculate_sequence_locks(tx, true, &mut prev_heights, &|h| self.mtp_at(h));
            let prev_mtp = self.chainstate.median_time_past_tip();
            if !evaluate_sequence_locks(self.height as i32, prev_mtp, lock) {
                return None;
            }
        }
        Some(transaction_sigop_cost(tx, &spent, self.flags))
    }

    fn mtp_at(&self, height: i32) -> i64 {
        let tree = &self.chainstate.tree;
        let tip = self.chainstate.tip();
        let ancestor = tree.get_ancestor(tip, height as u32).unwrap_or(tip);
        tree.median_time_past(ancestor)
    }
}

/// Output spent by `outpoint` and the height it counts as confirmed at. Pool
/// outputs are unconfirmed and count as being at `next_height`.
fn spent_output(outpoint: &OutPoint, mempool: &Mempool, coins: &dyn CoinsView, next_height: u32) -> Option<(TxOut, u32)> {
    if let Some(entry) = mempool.get(&outpoint.txid) {
        let txout = entry.tx.vout.get(outpoint.vout as usize)?;
        return Some((txout.clone(), next_height));
    }
    coins.get_coin(outpoint).map(|coin| (coin.txout, coin.height))
}

/// Transactions reachable from `start` through `links`, excluding `start`.
fn reachable(start: Txid, links: &HashMap<Txid, Vec<Txid>>) -> Vec<Txid> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack: Vec<Txid> = links.get(&start).cloned().unwrap_or_default();
    while let Some(txid) = stack.pop() {
        if seen.insert(txid) {
            out.push(txid);
            stack.extend(links.get(&txid).into_iter().flatten().copied());
        }
    }
    out
}

/// `start` and its not-yet-included ancestors, parents first.
fn package_order(start: Txid, parents: &HashMap<Txid, Vec<Txid>>, included: &HashSet<Txid>) -> Vec<Txid> {
    let mut order = Vec::new();
    let mut expanded = HashSet::new();
    let mut stack = vec![(start, false)];
    while let Some((txid, done)) = stack.pop() {
        if done {
            order.push(txid);
            continue;
        }
        if included.contains(&txid) || !expanded.insert(txid) {
            continue;
        }
        stack.push((txid, true));
        for parent in parents.get(&txid).into_iter().flatten() {
            if !included.contains(parent) && !expanded.contains(parent) {
                stack.push((*parent, false));
            }
        }
    }
    order
}

fn coinbase_tx(height: u32, extra_nonce: u64, script_pubkey: ScriptBuf, value: i64) -> Tx {
    let mut script_sig = bip34_height_script(height);
    script_sig.push(8);
    script_sig.extend_from_slice(&extra_nonce.to_le_bytes());
    let mut input = TxIn::new(OutPoint::null());
    input.script_sig = ScriptBuf::from_bytes(script_sig);
    Tx::new(1, vec![input], vec![TxOut::new(value, script_pubkey)], 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_consensus::ChainParams;
    use btc_validation::block_verify::{block_merkle_root, check_block_header};
    use btc_validation::coins::CoinsViewMemory;
    use btc_validation::mempool::MempoolEntry;
    use btc_validation::policy::get_virtual_transaction_size;

    use crate::chainstate::MemBlockStore;

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const NOW: i64 = 2_000_000_000;

    fn op_true() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    fn subsidy(height: u32) -> i64 {
        ChainParams::regtest().block_subsidy(height)
    }

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

    fn mine_blocks(cs: &mut Chainstate, pool: &Mempool, count: u32) -> Vec<BlockHash> {
        (0..count)
            .map(|_| generate_block(cs, pool, op_true(), NOW).expect("generated block is accepted"))
            .collect()
    }

    /// Spends `prev` to a single OP_TRUE output of `value`.
    fn spend(prev: OutPoint, value: i64) -> Tx {
        let mut input = TxIn::new(prev);
        input.script_sig = ScriptBuf::new();
        Tx::new(2, vec![input], vec![TxOut::new(value, op_true())], 0)
    }

    fn pool_entry(tx: Tx, fee: i64) -> MempoolEntry {
        let vsize = get_virtual_transaction_size(get_transaction_weight(&tx)) as u64;
        MempoolEntry { tx, fee, vsize }
    }

    fn coinbase_outpoint(cs: &Chainstate, hash: &BlockHash) -> OutPoint {
        let block = cs.get_block(hash).expect("block is stored");
        OutPoint { txid: block.txdata[0].txid(), vout: 0 }
    }

    #[test]
    fn generated_blocks_extend_the_tip_and_pay_the_subsidy() {
        let mut cs = new_chain();
        let pool = Mempool::new(100);
        let hashes = mine_blocks(&mut cs, &pool, 101);

        assert_eq!(cs.height(), 101);
        assert_eq!(cs.tip_hash(), hashes[100]);
        let first = cs.get_block(&hashes[0]).unwrap();
        assert_eq!(first.txdata.len(), 1, "an empty mempool yields a coinbase-only block");
        assert_eq!(first.txdata[0].vout.len(), 2, "payout plus witness commitment");
        assert_eq!(first.txdata[0].vout[0].value, subsidy(1));
        assert!(cs.coins_view().get_coin(&coinbase_outpoint(&cs, &hashes[0])).is_some());
    }

    #[test]
    fn child_pays_for_parent_and_both_are_included_parent_first() {
        let mut cs = new_chain();
        let pool_empty = Mempool::new(100);
        let hashes = mine_blocks(&mut cs, &pool_empty, 101);

        let parent_prev = coinbase_outpoint(&cs, &hashes[0]);
        let parent = spend(parent_prev, subsidy(1) - 1_000);
        let child = spend(OutPoint { txid: parent.txid(), vout: 0 }, subsidy(1) - 1_000 - 200_000);
        let (parent_id, child_id) = (parent.txid(), child.txid());

        let mut pool = Mempool::new(100);
        pool.add(pool_entry(child.clone(), 200_000)).unwrap();
        pool.add(pool_entry(parent.clone(), 1_000)).unwrap();

        let mut template = create_new_block(&cs, &pool, op_true(), NOW);
        assert_eq!(template.height, 102);
        let txdata = &template.block.txdata;
        assert_eq!(txdata.len(), 3);
        assert_eq!(txdata[1].txid(), parent_id);
        assert_eq!(txdata[2].txid(), child_id);
        assert_eq!(txdata[0].vout[0].value, subsidy(102) + 201_000);
        assert_eq!(template.fees, vec![-201_000, 1_000, 200_000]);
        assert_eq!(template.sigop_costs.len(), 3);

        assert!(mine_block(&mut template.block, 1 << 32));
        assert_eq!(cs.process_new_block(&template.block, NOW), Ok(true));
        assert_eq!(cs.height(), 102);
        assert!(cs.coins_view().get_coin(&OutPoint { txid: child_id, vout: 0 }).is_some());
    }

    #[test]
    fn skips_missing_inputs_and_non_final_txs_and_respects_weight() {
        let mut cs = new_chain();
        let pool_empty = Mempool::new(100);
        let hashes = mine_blocks(&mut cs, &pool_empty, 105);

        // Coinbases 1..=4 are mature at height 106. Each spend carries an
        // unspendable 390 kB OP_RETURN output, so only two fit in the weight budget.
        let mut pool = Mempool::new(100);
        let mut big_ids = Vec::new();
        for hash in &hashes[..4] {
            let mut tx = spend(coinbase_outpoint(&cs, hash), subsidy(1) - 1_000);
            tx.vout.push(TxOut::new(0, ScriptBuf::from_bytes(vec![0x6a; 390_000])));
            big_ids.push(tx.txid());
            pool.add(pool_entry(tx, 1_000)).unwrap();
        }
        let missing = spend(OutPoint { txid: Txid::from_byte_array([7; 32]), vout: 0 }, 1_000);
        let missing_id = missing.txid();
        pool.add(pool_entry(missing, 50_000)).unwrap();
        let mut locked = spend(coinbase_outpoint(&cs, &hashes[4]), subsidy(5) - 2_000);
        locked.lock_time = 500;
        locked.vin[0].sequence = bitcoin::Sequence(0);
        let locked_id = locked.txid();
        pool.add(pool_entry(locked, 2_000)).unwrap();

        let template = create_new_block(&cs, &pool, op_true(), NOW);
        let included: Vec<Txid> = template.block.txdata[1..].iter().map(Tx::txid).collect();
        assert_eq!(included.len(), 2);
        assert!(included.iter().all(|id| big_ids.contains(id)));
        assert!(!included.contains(&missing_id));
        assert!(!included.contains(&locked_id));
        let weight: u64 = template.block.txdata[1..].iter().map(|tx| get_transaction_weight(tx) as u64).sum();
        assert!(weight <= TX_WEIGHT_BUDGET);

        let mut block = template.block;
        assert!(mine_block(&mut block, 1 << 32));
        assert_eq!(cs.process_new_block(&block, NOW), Ok(true));
    }

    #[test]
    fn mine_block_finds_nonce_on_regtest_and_gives_up_on_hard_target() {
        let cs = new_chain();
        let pool = Mempool::new(10);
        let mut block = create_new_block(&cs, &pool, op_true(), NOW).block;
        assert!(mine_block(&mut block, 1 << 32));
        assert!(check_block_header(&block.header, &ChainParams::regtest()).is_ok());

        block.header.bits = 0x0300_0001;
        assert!(!mine_block(&mut block, 1_000));
    }
}
