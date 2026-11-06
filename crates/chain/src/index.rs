//! Block tree. Port of `chain.{h,cpp}` (`CBlockIndex`, `CChain`, skip list,
//! `GetMedianTimePast`, `LastCommonAncestor`) and `pow.cpp::GetNextWorkRequired`.

use std::collections::HashMap;

use btc_consensus::{pow, ChainParams};
use btc_primitives::{BlockHash, BlockHeader};
use primitive_types::U256;

/// Arena index of a `BlockIndex` inside a `BlockTree`.
pub type IndexId = usize;

/// `BlockStatus` bit flags (chain.h).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BlockStatus(pub u32);

impl BlockStatus {
    pub const VALID_TREE: u32 = 2;
    pub const VALID_TRANSACTIONS: u32 = 3;
    pub const VALID_CHAIN: u32 = 4;
    pub const VALID_SCRIPTS: u32 = 5;
    pub const VALID_MASK: u32 = 7;
    pub const HAVE_DATA: u32 = 8;
    pub const HAVE_UNDO: u32 = 16;
    pub const FAILED_VALID: u32 = 32;
    pub const FAILED_CHILD: u32 = 64;
    pub const FAILED_MASK: u32 = Self::FAILED_VALID | Self::FAILED_CHILD;

    /// `IsValid(nUpTo)`.
    pub fn is_valid(self, up_to: u32) -> bool {
        debug_assert_eq!(up_to & !Self::VALID_MASK, 0);
        if self.0 & Self::FAILED_MASK != 0 {
            return false;
        }
        (self.0 & Self::VALID_MASK) >= up_to
    }
    /// `RaiseValidity(nUpTo)`: returns true if the level changed.
    pub fn raise_validity(&mut self, up_to: u32) -> bool {
        debug_assert_eq!(up_to & !Self::VALID_MASK, 0);
        if self.0 & Self::FAILED_MASK != 0 {
            return false;
        }
        if (self.0 & Self::VALID_MASK) < up_to {
            self.0 = (self.0 & !Self::VALID_MASK) | up_to;
            return true;
        }
        false
    }
    pub fn is_failed(self) -> bool {
        self.0 & Self::FAILED_MASK != 0
    }
}

#[derive(Clone, Debug)]
pub struct BlockIndex {
    pub hash: BlockHash,
    pub header: BlockHeader,
    pub height: u32,
    pub prev: Option<IndexId>,
    /// Skip-list pointer (`pskip`).
    pub skip: Option<IndexId>,
    /// Total work up to and including this block (`nChainWork`).
    pub chain_work: U256,
    pub status: BlockStatus,
    /// Number of transactions (0 until block data is known).
    pub n_tx: u32,
    /// Insertion order, used as tie-breaker (`nSequenceId`).
    pub sequence_id: u64,
}

/// All known headers (`BlockMap` + `m_block_index`).
#[derive(Clone, Debug, Default)]
pub struct BlockTree {
    entries: Vec<BlockIndex>,
    by_hash: HashMap<BlockHash, IndexId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexError {
    UnknownPrev,
    Duplicate(IndexId),
}

/// `CBlockIndex::nMedianTimeSpan`.
const MEDIAN_TIME_SPAN: usize = 11;

/// `InvertLowestOne`: clear the lowest set bit.
fn invert_lowest_one(n: i64) -> i64 {
    n & (n - 1)
}

/// `GetSkipHeight`: the height the skip pointer of a block at `height` targets.
fn skip_height(height: i64) -> i64 {
    if height < 2 {
        return 0;
    }
    if (height & 1) != 0 {
        invert_lowest_one(invert_lowest_one(height - 1)) + 1
    } else {
        invert_lowest_one(height)
    }
}

impl BlockTree {
    pub fn new() -> Self {
        Self::default()
    }
    /// `AddToBlockIndex`. The first inserted header is the genesis (its prev
    /// must be all zeros). Others need a known prev. Sets height, skip,
    /// chain_work (prev work + `work_from_bits`), status VALID_TREE.
    pub fn insert_header(&mut self, header: BlockHeader) -> Result<IndexId, IndexError> {
        use bitcoin_hashes::Hash as _;

        let hash = header.block_hash();
        if let Some(&existing) = self.by_hash.get(&hash) {
            return Err(IndexError::Duplicate(existing));
        }

        let (prev, height, prev_work) = if self.entries.is_empty() {
            if header.prev_blockhash != BlockHash::all_zeros() {
                return Err(IndexError::UnknownPrev);
            }
            (None, 0, U256::zero())
        } else {
            let prev = self
                .lookup(&header.prev_blockhash)
                .ok_or(IndexError::UnknownPrev)?;
            let parent = &self.entries[prev];
            (Some(prev), parent.height + 1, parent.chain_work)
        };

        // `work_from_bits` only fails on invalid bits; such a header carries no work.
        let work = pow::work_from_bits(header.bits).unwrap_or_else(|_| U256::zero());
        let id = self.entries.len();
        self.entries.push(BlockIndex {
            hash,
            header,
            height,
            prev,
            skip: None,
            chain_work: prev_work.saturating_add(work),
            status: BlockStatus(BlockStatus::VALID_TREE),
            n_tx: 0,
            sequence_id: id as u64,
        });
        // `BuildSkip()`: the skip target is always at or below the parent.
        if let Some(parent) = prev {
            self.entries[id].skip = self.get_ancestor(parent, skip_height(i64::from(height)) as u32);
        }

        self.by_hash.insert(hash, id);
        Ok(id)
    }
    pub fn get(&self, id: IndexId) -> &BlockIndex {
        &self.entries[id]
    }
    pub fn get_mut(&mut self, id: IndexId) -> &mut BlockIndex {
        &mut self.entries[id]
    }
    pub fn lookup(&self, hash: &BlockHash) -> Option<IndexId> {
        self.by_hash.get(hash).copied()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Every id, in insertion order.
    pub fn ids(&self) -> std::ops::Range<IndexId> {
        0..self.entries.len()
    }
    /// `GetAncestor(height)` using the skip list (O(log n)).
    pub fn get_ancestor(&self, id: IndexId, height: u32) -> Option<IndexId> {
        let start = &self.entries[id];
        if height > start.height {
            return None;
        }
        let target = i64::from(height);
        let mut walk = id;
        let mut walk_height = i64::from(start.height);
        while walk_height > target {
            let entry = &self.entries[walk];
            let jump = skip_height(walk_height);
            let jump_prev = skip_height(walk_height - 1);
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            let follow = entry.skip.filter(|_| {
                jump == target
                    || (jump > target && !(jump_prev < jump - 2 && jump_prev >= target))
            });
            match follow {
                Some(skip) => {
                    walk = skip;
                    walk_height = jump;
                }
                None => {
                    walk = entry.prev?;
                    walk_height -= 1;
                }
            }
        }
        Some(walk)
    }
    /// `GetMedianTimePast()`: median of the last 11 block times ending at `id`.
    pub fn median_time_past(&self, id: IndexId) -> i64 {
        let mut times = Vec::with_capacity(MEDIAN_TIME_SPAN);
        let mut cursor = Some(id);
        while let Some(current) = cursor {
            if times.len() == MEDIAN_TIME_SPAN {
                break;
            }
            let entry = &self.entries[current];
            times.push(entry.header.block_time());
            cursor = entry.prev;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }
    /// `LastCommonAncestor(a, b)`.
    pub fn last_common_ancestor(&self, a: IndexId, b: IndexId) -> IndexId {
        let (mut pa, mut pb) = (a, b);
        let (ha, hb) = (self.entries[pa].height, self.entries[pb].height);
        // Rewind the higher block to the lower height first.
        if ha > hb {
            pa = self.get_ancestor(pa, hb).expect("ancestor at lower height exists");
        } else if hb > ha {
            pb = self.get_ancestor(pb, ha).expect("ancestor at lower height exists");
        }
        while pa != pb {
            // Equal-height blocks have equal-height skip pointers.
            while self.entries[pa].skip != self.entries[pb].skip {
                pa = self.entries[pa].skip.expect("non-genesis block has a skip pointer");
                pb = self.entries[pb].skip.expect("non-genesis block has a skip pointer");
            }
            pa = self.entries[pa].prev.expect("blocks share a single genesis");
            pb = self.entries[pb].prev.expect("blocks share a single genesis");
        }
        pa
    }
    /// `GetNextWorkRequired(pindexLast=prev, pblock=header)`, including the
    /// testnet min-difficulty walk-back. Uses `btc_consensus::pow`.
    pub fn next_work_required(&self, prev: IndexId, header: &BlockHeader, params: &ChainParams) -> u32 {
        let parent = &self.entries[prev];
        let height = parent.height + 1;
        let interval = params.difficulty_adjustment_interval();
        let boundary = interval > 0 && i64::from(height) % interval == 0;
        let parent_time = parent.header.block_time();

        let (first_time, first_bits) = if boundary {
            // First block of the window: `pindexLast->GetAncestor(height - interval)`.
            let first_height = u32::try_from(i64::from(height) - interval).ok();
            match first_height.and_then(|h| self.get_ancestor(prev, h)) {
                Some(first) => {
                    let first = &self.entries[first];
                    (first.header.block_time(), first.header.bits)
                }
                None => (parent_time, parent.header.bits),
            }
        } else {
            (parent_time, parent.header.bits)
        };

        // Testnet rule: the last block that was not a minimum-difficulty block.
        let last_non_min_bits = if interval > 0 && !boundary && params.allow_min_difficulty_blocks {
            let pow_limit_bits = params.pow_limit_bits();
            let mut cursor = prev;
            loop {
                let entry = &self.entries[cursor];
                match entry.prev {
                    Some(p)
                        if i64::from(entry.height) % interval != 0
                            && entry.header.bits == pow_limit_bits =>
                    {
                        cursor = p;
                    }
                    _ => break,
                }
            }
            self.entries[cursor].header.bits
        } else {
            parent.header.bits
        };

        let input = pow::RetargetInput {
            height,
            block_time: header.block_time(),
            last_time: parent_time,
            last_bits: parent.header.bits,
            first_time,
            first_bits,
            last_non_min_bits,
        };
        pow::next_work_required(&input, params)
    }
}

/// The active chain (`CChain`): `chain[h]` is the id at height `h`.
#[derive(Clone, Debug, Default)]
pub struct ActiveChain {
    chain: Vec<IndexId>,
}

impl ActiveChain {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn tip(&self) -> Option<IndexId> {
        self.chain.last().copied()
    }
    pub fn genesis(&self) -> Option<IndexId> {
        self.chain.first().copied()
    }
    /// Height of the tip, `None` when empty.
    pub fn height(&self) -> Option<u32> {
        self.chain.len().checked_sub(1).map(|h| h as u32)
    }
    pub fn get(&self, height: u32) -> Option<IndexId> {
        self.chain.get(height as usize).copied()
    }
    pub fn contains(&self, tree: &BlockTree, id: IndexId) -> bool {
        self.chain.get(tree.get(id).height as usize) == Some(&id)
    }
    /// Successor of `id` in this chain, if `id` is in it.
    pub fn next(&self, tree: &BlockTree, id: IndexId) -> Option<IndexId> {
        if !self.contains(tree, id) {
            return None;
        }
        self.chain.get(tree.get(id).height as usize + 1).copied()
    }
    /// `SetTip`: rebuild so `id` is the tip (walk prev pointers).
    pub fn set_tip(&mut self, tree: &BlockTree, id: Option<IndexId>) {
        let Some(tip) = id else {
            self.chain.clear();
            return;
        };
        // Walk back until we reach a block already on this chain; everything
        // below it is shared, everything above it is replaced.
        let mut pending = Vec::new();
        let mut cursor = Some(tip);
        while let Some(current) = cursor {
            let entry = tree.get(current);
            if self.chain.get(entry.height as usize) == Some(&current) {
                break;
            }
            pending.push(current);
            cursor = entry.prev;
        }
        let keep = cursor.map_or(0, |fork| tree.get(fork).height as usize + 1);
        self.chain.truncate(keep);
        self.chain.extend(pending.into_iter().rev());
    }
    /// `FindFork`: last block of this chain that is an ancestor of `id`.
    pub fn find_fork(&self, tree: &BlockTree, id: IndexId) -> Option<IndexId> {
        let tip_height = self.height()?;
        let entry = tree.get(id);
        let mut cursor = if entry.height > tip_height {
            tree.get_ancestor(id, tip_height)
        } else {
            Some(id)
        };
        while let Some(current) = cursor {
            if self.contains(tree, current) {
                return Some(current);
            }
            cursor = tree.get(current).prev;
        }
        None
    }
    /// `GetLocator`: tip, then exponentially spaced back to genesis.
    pub fn locator(&self, tree: &BlockTree) -> Vec<BlockHash> {
        let mut have = Vec::with_capacity(32);
        let mut step: u64 = 1;
        let mut cursor = self.tip();
        while let Some(current) = cursor {
            let entry = tree.get(current);
            have.push(entry.hash);
            if entry.height == 0 {
                break;
            }
            let step32 = u32::try_from(step).unwrap_or(u32::MAX);
            let target = entry.height.saturating_sub(step32);
            cursor = tree.get_ancestor(current, target);
            if have.len() > 10 {
                step = step.saturating_mul(2);
            }
        }
        have
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::TxMerkleNode;
    use bitcoin_hashes::Hash as _;
    use btc_consensus::{calculate_next_work_required, decode_compact, work_from_bits};

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const MAINNET_BITS: u32 = 0x1d00_ffff;

    fn header(prev: BlockHash, time: u32, bits: u32, nonce: u32) -> BlockHeader {
        BlockHeader::new(1, prev, TxMerkleNode::all_zeros(), time, bits, nonce)
    }

    /// Inserts `count` headers on top of `parent` (genesis when `None`).
    /// Header `i` gets `time(i)`; `salt` keeps separate branches distinct.
    fn grow(
        tree: &mut BlockTree,
        parent: Option<IndexId>,
        count: u32,
        bits: u32,
        salt: u32,
        time: impl Fn(u32) -> u32,
    ) -> Vec<IndexId> {
        let mut prev_hash = parent.map_or(BlockHash::all_zeros(), |p| tree.get(p).hash);
        let mut ids = Vec::new();
        for i in 0..count {
            let h = header(prev_hash, time(i), bits, salt + i);
            prev_hash = h.block_hash();
            ids.push(tree.insert_header(h).unwrap());
        }
        ids
    }

    fn regular_time(i: u32) -> u32 {
        1_600_000_000 + i * 600
    }

    #[test]
    fn insert_sets_height_work_status_and_errors() {
        let mut tree = BlockTree::new();
        assert!(tree.is_empty());

        // The first header must be a root.
        let orphan = header(BlockHash::from_byte_array([1; 32]), 1, REGTEST_BITS, 0);
        assert_eq!(tree.insert_header(orphan), Err(IndexError::UnknownPrev));

        let genesis = tree.insert_header(header(BlockHash::all_zeros(), 1, REGTEST_BITS, 0)).unwrap();
        assert_eq!(genesis, 0);
        assert_eq!(
            tree.insert_header(header(BlockHash::all_zeros(), 1, REGTEST_BITS, 0)),
            Err(IndexError::Duplicate(genesis))
        );
        let unknown = header(BlockHash::from_byte_array([9; 32]), 2, REGTEST_BITS, 0);
        assert_eq!(tree.insert_header(unknown), Err(IndexError::UnknownPrev));

        let child_header = header(tree.get(genesis).hash, 2, REGTEST_BITS, 1);
        let child = tree.insert_header(child_header).unwrap();
        let entry = tree.get(child);
        assert_eq!(entry.height, 1);
        assert_eq!(entry.prev, Some(genesis));
        assert_eq!(entry.skip, Some(genesis));
        assert_eq!(entry.sequence_id, 1);
        assert_eq!(entry.status, BlockStatus(BlockStatus::VALID_TREE));
        assert_eq!(tree.lookup(&entry.hash), Some(child));
        assert_eq!(tree.len(), 2);
        assert_eq!(tree.ids(), 0..2);

        let work = work_from_bits(REGTEST_BITS).unwrap();
        assert_eq!(tree.get(genesis).chain_work, work);
        assert_eq!(tree.get(child).chain_work, work + work);
    }

    #[test]
    fn get_ancestor_matches_prev_walk() {
        let mut tree = BlockTree::new();
        let ids = grow(&mut tree, None, 3000, REGTEST_BITS, 0, regular_time);
        let tip = *ids.last().unwrap();

        // Every height from a few starting points, checked against a prev walk.
        for start in [tip, ids[2047], ids[1000], ids[1]] {
            let start_height = tree.get(start).height;
            let mut walk = Some(start);
            for height in (0..=start_height).rev() {
                assert_eq!(tree.get_ancestor(start, height), walk, "height {height}");
                walk = walk.and_then(|w| tree.get(w).prev);
            }
            assert_eq!(tree.get_ancestor(start, start_height + 1), None);
        }

        // Spot-check that the skip list is actually used (fewer hops than a walk).
        assert_eq!(tree.get_ancestor(tip, 0), Some(ids[0]));
        assert_eq!(tree.get_ancestor(tip, 1234), Some(ids[1234]));
        assert_eq!(tree.get_ancestor(tip, 2999), Some(tip));
    }

    #[test]
    fn median_time_past_uses_last_eleven_sorted_times() {
        let times = [10u32, 20, 5, 40, 30, 60, 50, 70, 15, 90, 80, 100, 110];
        let mut tree = BlockTree::new();
        let ids = grow(&mut tree, None, times.len() as u32, REGTEST_BITS, 0, |i| times[i as usize]);

        // Fewer than 11 blocks: median of what exists, upper-middle for even counts.
        assert_eq!(tree.median_time_past(ids[0]), 10);
        assert_eq!(tree.median_time_past(ids[1]), 20);
        // Heights 0..=5: sorted [5,10,20,30,40,60], index 3.
        assert_eq!(tree.median_time_past(ids[5]), 30);
        // Heights 2..=12: sorted [5,15,30,40,50,60,70,80,90,100,110], index 5.
        assert_eq!(tree.median_time_past(ids[12]), 60);
    }

    #[test]
    fn fork_last_common_ancestor_and_find_fork() {
        let mut tree = BlockTree::new();
        let main = grow(&mut tree, None, 3000, REGTEST_BITS, 0, regular_time);
        // Branch off at height 1000 with different times and nonces.
        let fork = grow(&mut tree, Some(main[1000]), 500, REGTEST_BITS, 100_000, |i| {
            regular_time(1001 + i) + 1
        });
        let main_tip = *main.last().unwrap();
        let fork_tip = *fork.last().unwrap();
        assert_eq!(tree.get(fork_tip).height, 1500);

        assert_eq!(tree.last_common_ancestor(main_tip, fork_tip), main[1000]);
        assert_eq!(tree.last_common_ancestor(fork_tip, main_tip), main[1000]);
        assert_eq!(tree.last_common_ancestor(main_tip, main_tip), main_tip);
        assert_eq!(tree.last_common_ancestor(main[500], main[1200]), main[500]);
        assert_eq!(tree.last_common_ancestor(main[1200], fork[10]), main[1000]);

        let mut active = ActiveChain::new();
        assert_eq!(active.find_fork(&tree, fork_tip), None);
        active.set_tip(&tree, Some(main_tip));
        assert_eq!(active.find_fork(&tree, fork_tip), Some(main[1000]));
        assert_eq!(active.find_fork(&tree, main[500]), Some(main[500]));
        assert_eq!(active.find_fork(&tree, main_tip), Some(main_tip));

        // Fork tip is above the main chain's height at 1500: still resolves.
        active.set_tip(&tree, Some(main[1500]));
        assert_eq!(active.find_fork(&tree, main_tip), Some(main[1500]));
        assert_eq!(active.find_fork(&tree, fork_tip), Some(main[1000]));
    }

    #[test]
    fn set_tip_switches_branches() {
        let mut tree = BlockTree::new();
        let main = grow(&mut tree, None, 3000, REGTEST_BITS, 0, regular_time);
        let fork = grow(&mut tree, Some(main[1000]), 500, REGTEST_BITS, 100_000, |i| {
            regular_time(1001 + i) + 1
        });
        let main_tip = *main.last().unwrap();
        let fork_tip = *fork.last().unwrap();

        let mut active = ActiveChain::new();
        assert_eq!(active.tip(), None);
        assert_eq!(active.height(), None);
        assert_eq!(active.genesis(), None);

        active.set_tip(&tree, Some(main_tip));
        assert_eq!(active.tip(), Some(main_tip));
        assert_eq!(active.height(), Some(2999));
        assert_eq!(active.genesis(), Some(main[0]));
        assert_eq!(active.get(1000), Some(main[1000]));
        assert!(active.contains(&tree, main[1000]));
        assert_eq!(active.next(&tree, main[1000]), Some(main[1001]));
        assert_eq!(active.next(&tree, main_tip), None);

        active.set_tip(&tree, Some(fork_tip));
        assert_eq!(active.tip(), Some(fork_tip));
        assert_eq!(active.height(), Some(1500));
        assert_eq!(active.get(1000), Some(main[1000]));
        assert_eq!(active.get(1001), Some(fork[0]));
        assert_eq!(active.get(1500), Some(fork_tip));
        assert_eq!(active.get(1501), None);
        assert!(!active.contains(&tree, main[1500]));
        assert!(!active.contains(&tree, main_tip));
        assert_eq!(active.next(&tree, main[1000]), Some(fork[0]));

        active.set_tip(&tree, Some(main_tip));
        assert_eq!(active.height(), Some(2999));
        assert!(!active.contains(&tree, fork[0]));
        assert_eq!(active.next(&tree, main[1000]), Some(main[1001]));

        // A lower tip on the same branch truncates the chain.
        active.set_tip(&tree, Some(main[10]));
        assert_eq!(active.height(), Some(10));
        assert_eq!(active.get(11), None);

        active.set_tip(&tree, None);
        assert_eq!(active.tip(), None);
        assert_eq!(active.height(), None);
    }

    #[test]
    fn locator_shape_and_contents() {
        let mut tree = BlockTree::new();
        let ids = grow(&mut tree, None, 3000, REGTEST_BITS, 0, regular_time);
        let mut active = ActiveChain::new();
        assert!(active.locator(&tree).is_empty());

        active.set_tip(&tree, Some(ids[2999]));
        let heights: Vec<u32> = active
            .locator(&tree)
            .iter()
            .map(|hash| tree.get(tree.lookup(hash).unwrap()).height)
            .collect();

        assert_eq!(heights[0], 2999);
        assert_eq!(*heights.last().unwrap(), 0, "locator ends at genesis");
        assert_eq!(active.locator(&tree)[0], tree.get(ids[2999]).hash);
        assert_eq!(*active.locator(&tree).last().unwrap(), tree.get(ids[0]).hash);

        // The first 11 steps are consecutive, then the step doubles.
        let steps: Vec<u32> = heights.windows(2).map(|w| w[0] - w[1]).collect();
        assert!(steps[..11].iter().all(|&s| s == 1), "steps {steps:?}");
        for k in 12..steps.len() - 1 {
            assert_eq!(steps[k], steps[k - 1] * 2, "step {k} in {steps:?}");
        }
        assert!((12..=30).contains(&heights.len()), "len {}", heights.len());

        active.set_tip(&tree, Some(ids[0]));
        assert_eq!(active.locator(&tree), vec![tree.get(ids[0]).hash]);
    }

    #[test]
    fn regtest_next_work_required_returns_previous_bits() {
        let regtest = ChainParams::regtest();
        let mut tree = BlockTree::new();
        let ids = grow(&mut tree, None, 300, REGTEST_BITS, 0, regular_time);

        for prev in [ids[0], ids[142], ids[143], ids[200], ids[299]] {
            let prev_hash = tree.get(prev).hash;
            let prev_time = tree.get(prev).header.block_time() as u32;
            // Normal spacing, and a >20 minute gap that triggers the min-difficulty rule.
            for time in [prev_time + 600, prev_time + 10_000] {
                let next = header(prev_hash, time, REGTEST_BITS, 7);
                assert_eq!(tree.next_work_required(prev, &next, &regtest), REGTEST_BITS);
            }
        }
    }

    #[test]
    fn mainnet_retarget_halves_target_for_half_timespan() {
        let mainnet = ChainParams::mainnet();
        let t0: u32 = 1_500_000_000;
        let week: u32 = 604_800;
        // Heights 0..=2015 form the retarget window. Genesis is at t0 and the
        // last block is exactly 7 days later: half of the 14-day target.
        let mut tree = BlockTree::new();
        let ids = grow(&mut tree, None, 2016, MAINNET_BITS, 0, |i| {
            if i == 2015 {
                t0 + week
            } else {
                t0 + i * 300
            }
        });
        let prev = ids[2015];
        let next = header(tree.get(prev).hash, t0 + week + 600, MAINNET_BITS, 1);
        let bits = tree.next_work_required(prev, &next, &mainnet);

        let expected = calculate_next_work_required(MAINNET_BITS, i64::from(t0), i64::from(t0 + week), MAINNET_BITS, &mainnet);
        assert_eq!(bits, expected);
        assert_eq!(bits, 0x1c7f_ff80);
        let old_target = decode_compact(MAINNET_BITS).unwrap();
        assert_eq!(decode_compact(bits).unwrap(), old_target / 2);

        // Between retargets the previous bits carry over.
        let mid = header(tree.get(ids[2014]).hash, t0 + week, MAINNET_BITS, 2);
        assert_eq!(tree.next_work_required(ids[2014], &mid, &mainnet), MAINNET_BITS);
    }
}
