//! Coin selection. Port of src/wallet/coinselection.h and src/wallet/coinselection.cpp.
//!
//! Covers Branch and Bound (`select_coins_bnb`) and the Knapsack fallback (`knapsack_solver`).
//! Amounts are i64 satoshis. Fee rates are sat per 1000 vbytes (Core's CFeeRate convention).
//! Each `Utxo` is its own OutputGroup: address grouping and subtract-fee-from-outputs are not
//! modelled. Nothing in this module uses randomness.

use std::cmp::Ordering;

/// Maximum number of selections Branch and Bound evaluates (Core: TOTAL_TRIES).
pub const TOTAL_TRIES: usize = 100_000;
/// Core's MAX_MONEY: 21e6 BTC in satoshis.
pub const MAX_MONEY: i64 = 2_100_000_000_000_000;
/// Core's WITNESS_SCALE_FACTOR: weight = 4 * vbytes for input bytes.
const WITNESS_SCALE_FACTOR: i64 = 4;

/// An unspent output to choose from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utxo {
    /// Output value in satoshis.
    pub value: i64,
    /// Estimated vbytes to spend this output as a fully signed input. Negative means unknown:
    /// the input then carries no fee and no weight (Core's `input_bytes = -1`).
    pub input_bytes: i64,
}

impl Utxo {
    /// Fee to spend this output at `fee_rate` (sat per 1000 vbytes), rounded up.
    pub fn fee(&self, fee_rate: i64) -> i64 {
        if self.input_bytes < 0 {
            0
        } else {
            fee_for(self.input_bytes, fee_rate)
        }
    }

    /// `value - fee(fee_rate)`. Can be negative for dust outputs.
    pub fn effective_value(&self, fee_rate: i64) -> i64 {
        self.value - self.fee(fee_rate)
    }

    /// Weight units this input adds to a transaction.
    pub fn weight(&self) -> i64 {
        if self.input_bytes > 0 {
            self.input_bytes * WITNESS_SCALE_FACTOR
        } else {
            0
        }
    }
}

/// Core's CFeeRate::GetFee: ceil(fee_rate * vbytes / 1000).
fn fee_for(vbytes: i64, fee_rate: i64) -> i64 {
    debug_assert!(fee_rate >= 0);
    (fee_rate * vbytes + 999) / 1000
}

/// One candidate for selection, derived from a single `Utxo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputGroup {
    /// Index of the source UTXO in the caller's slice.
    pub index: usize,
    /// Output value, not effective.
    pub value: i64,
    /// Fee to spend at the target fee rate.
    pub fee: i64,
    /// Fee to spend at the long-term fee rate.
    pub long_term_fee: i64,
    /// `value - fee`. The algorithms compare this against the target.
    pub effective_value: i64,
    /// Weight units of this input.
    pub weight: i64,
}

impl OutputGroup {
    pub fn new(index: usize, utxo: &Utxo, fee_rate: i64, long_term_fee_rate: i64) -> Self {
        let fee = utxo.fee(fee_rate);
        Self {
            index,
            value: utxo.value,
            fee,
            long_term_fee: utxo.fee(long_term_fee_rate),
            effective_value: utxo.value - fee,
            weight: utxo.weight(),
        }
    }

    /// The amount the algorithms add up (Core's GetSelectionAmount with subtract-fee off).
    pub fn amount(&self) -> i64 {
        self.effective_value
    }

    /// Cost of spending this input now rather than at the long-term rate.
    pub fn input_waste(&self) -> i64 {
        self.fee - self.long_term_fee
    }
}

/// Result of a successful selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionResult {
    /// Indices into the caller's `utxos` slice.
    pub inputs: Vec<usize>,
    /// Sum of effective values of `inputs`.
    pub total: i64,
    /// `sum(fee - long_term_fee) + (total - target)`. This is the changeless form of Core's
    /// waste: the excess is what goes to fees when no change output is created.
    pub waste: i64,
}

/// Core's `descending`: effective value high to low; on ties, lower waste first.
fn descending(a: &OutputGroup, b: &OutputGroup) -> Ordering {
    b.amount()
        .cmp(&a.amount())
        .then_with(|| a.input_waste().cmp(&b.input_waste()))
}

/// Builds groups for every UTXO with positive effective value. Core filters these out before
/// calling the algorithms (OutputGroupTypeMap::Push), and the algorithms assume it.
fn build_groups(utxos: &[Utxo], fee_rate: i64, long_term_fee_rate: i64) -> Vec<OutputGroup> {
    utxos
        .iter()
        .enumerate()
        .map(|(i, u)| OutputGroup::new(i, u, fee_rate, long_term_fee_rate))
        .filter(|g| g.amount() > 0)
        .collect()
}

fn weight_of(groups: &[OutputGroup]) -> i64 {
    groups.iter().map(|g| g.weight).sum()
}

/// Builds a result from chosen groups. Returns None if the set is empty or does not reach target.
fn make_result(groups: &[OutputGroup], target: i64) -> Option<SelectionResult> {
    if groups.is_empty() {
        return None;
    }
    let total: i64 = groups.iter().map(OutputGroup::amount).sum();
    if total < target {
        return None;
    }
    let input_waste: i64 = groups.iter().map(OutputGroup::input_waste).sum();
    Some(SelectionResult {
        inputs: groups.iter().map(|g| g.index).collect(),
        total,
        waste: input_waste + (total - target),
    })
}

/// The current selection as a stack of positions into the sorted pool, with running totals.
#[derive(Default)]
struct Selection {
    positions: Vec<usize>,
    amount: i64,
    weight: i64,
    waste: i64,
}

impl Selection {
    fn push(&mut self, pos: usize, g: &OutputGroup) {
        self.positions.push(pos);
        self.amount += g.amount();
        self.weight += g.weight;
        self.waste += g.input_waste();
    }

    fn pop(&mut self, pool: &[OutputGroup]) {
        if let Some(pos) = self.positions.pop() {
            let g = &pool[pos];
            self.amount -= g.amount();
            self.weight -= g.weight;
            self.waste -= g.input_waste();
        }
    }

    fn last(&self) -> usize {
        *self.positions.last().expect("selection is non-empty here")
    }
}

/// Branch and Bound (Murch). Searches for an input set whose effective value lies in
/// `[target, target + cost_of_change]` with minimal waste. Port of SelectCoinsBnB.
///
/// Returns None if no such set is found, including when the search hits `TOTAL_TRIES`
/// without finding one. If the search hits the limit after finding a set, that best set is
/// returned (Core returns it as non-optimal; this port does not carry that flag).
pub fn select_coins_bnb(
    utxos: &[Utxo],
    target: i64,
    cost_of_change: i64,
    fee_rate: i64,
    long_term_fee_rate: i64,
    max_selection_weight: i64,
) -> Option<SelectionResult> {
    let mut pool = build_groups(utxos, fee_rate, long_term_fee_rate);
    pool.sort_by(descending);
    let n = pool.len();
    if n == 0 {
        return None;
    }

    // lookahead[i] = sum of amounts of pool[i+1..]. Lets the search CUT when even taking every
    // remaining UTXO cannot reach the target.
    let mut lookahead = vec![0i64; n];
    let mut total_available = 0i64;
    for i in (0..n).rev() {
        lookahead[i] = total_available;
        total_available += pool[i].amount();
    }
    if total_available < target {
        return None;
    }

    let mut sel = Selection::default();
    let mut best_selection: Vec<usize> = Vec::new();
    let mut best_waste = MAX_MONEY;
    let mut next_utxo = 0usize;
    let mut curr_try = 0usize;

    // Core has no feerate here. It uses the first group's fee vs its long-term fee as a proxy
    // for "current feerate above long-term feerate".
    let is_feerate_high = pool[0].fee > pool[0].long_term_fee;

    let mut is_done = false;
    while !is_done {
        let mut should_shift = false;
        let mut should_cut = false;

        // Include next_utxo.
        let tail = next_utxo;
        sel.push(tail, &pool[tail]);
        next_utxo += 1;
        curr_try += 1;

        // Evaluate the current selection. Decide whether to CUT, SHIFT, or keep EXPLORING.
        if sel.amount + lookahead[tail] < target {
            // Cannot reach target even with everything left: CUT.
            should_cut = true;
        } else if sel.weight > max_selection_weight {
            should_shift = true;
        } else if sel.amount > target + cost_of_change {
            // Overshot the window. Supersets only add amount: SHIFT.
            should_shift = true;
        } else if is_feerate_high && sel.waste > best_waste {
            // At high feerates more inputs only add waste, and we are still short of the window:
            // no superset can beat the best. At low feerates this cut would skip useful sets.
            should_shift = true;
        } else if sel.amount >= target {
            // In the window: a candidate. Supersets only add fees: SHIFT.
            should_shift = true;
            let waste = sel.waste + (sel.amount - target);
            if waste <= best_waste {
                best_selection = sel.positions.clone();
                best_waste = waste;
            }
        }

        if curr_try >= TOTAL_TRIES {
            break;
        }

        if next_utxo == n {
            // Nothing left to include or omit beyond this point: CUT.
            should_cut = true;
        }

        if should_cut {
            // Drop the tail. The shift loop below then drops the penultimate and moves on.
            sel.pop(&pool);
            should_shift = true;
        }

        while should_shift {
            if sel.positions.is_empty() {
                is_done = true;
                break;
            }
            // Omit the last selected UTXO and continue with the one after it.
            next_utxo = sel.last() + 1;
            sel.pop(&pool);
            should_shift = false;

            // Clone skipping. Pool is sorted by (amount desc, waste asc), so a UTXO with the same
            // amount as its predecessor has equal or higher waste. Omitting the predecessor
            // already covered an equivalent or better set, so skip forward past the clones.
            while pool[next_utxo - 1].amount() == pool[next_utxo].amount() {
                if next_utxo >= n - 1 {
                    should_shift = true;
                    break;
                }
                next_utxo += 1;
            }
        }
    }

    if best_selection.is_empty() {
        return None;
    }
    let groups: Vec<OutputGroup> = best_selection.iter().map(|&p| pool[p]).collect();
    make_result(&groups, target)
}

/// Deterministic fallback to Core's KnapsackSolver.
///
/// SIMPLIFICATION: Core shuffles the groups and runs randomized subset-sum passes
/// (ApproximateBestSubset). This port keeps Core's control flow (exact match, lowest-larger
/// fallback, weight limit) but replaces the randomized search with one greedy pass over the
/// applicable groups in descending order. The result can be further from target than Core's
/// best randomized subset. Ties are broken by input order.
///
/// `change_target` is the minimum change Core aims for (CoinSelectionParams::m_min_change_target).
/// Returns None if the funds are insufficient or no set fits within `max_selection_weight`.
pub fn knapsack_solver(
    utxos: &[Utxo],
    target: i64,
    change_target: i64,
    fee_rate: i64,
    long_term_fee_rate: i64,
    max_selection_weight: i64,
) -> Option<SelectionResult> {
    let groups = build_groups(utxos, fee_rate, long_term_fee_rate);

    // Smallest group at or above target + change_target. Used only when nothing smaller works.
    let mut lowest_larger: Option<OutputGroup> = None;
    // Groups below target + change_target. Larger ones would only overshoot.
    let mut applicable: Vec<OutputGroup> = Vec::new();
    let mut total_lower = 0i64;

    for g in groups {
        if g.weight > max_selection_weight {
            continue;
        }
        if g.amount() == target {
            return make_result(&[g], target);
        }
        if g.amount() < target + change_target {
            total_lower += g.amount();
            applicable.push(g);
        } else if lowest_larger.map_or(true, |l| g.amount() < l.amount()) {
            lowest_larger = Some(g);
        }
    }

    if total_lower == target {
        if weight_of(&applicable) <= max_selection_weight {
            return make_result(&applicable, target);
        }
        // Too heavy: fall through to the subset search, as Core does.
    }

    if total_lower < target {
        return lowest_larger.and_then(|g| make_result(&[g], target));
    }

    applicable.sort_by(descending);

    // Core's worst-case best is "take everything". Greedy passes replace it only when they
    // land closer to the goal.
    let mut best_set: Vec<usize> = (0..applicable.len()).collect();
    let mut best_total = total_lower;
    if let Some((set, total)) = greedy_subset(&applicable, target, max_selection_weight) {
        if total < best_total {
            best_set = set;
            best_total = total;
        }
    }
    if best_total != target && total_lower >= target + change_target {
        if let Some((set, total)) =
            greedy_subset(&applicable, target + change_target, max_selection_weight)
        {
            if total < best_total {
                best_set = set;
                best_total = total;
            }
        }
    }

    // Same condition as Core: prefer the lowest larger group when the subset search did not land
    // on the target exactly but stayed inside the change window, or when the larger group is no
    // farther above the target than the subset is.
    if let Some(larger) = lowest_larger {
        if (best_total != target && best_total < target + change_target)
            || larger.amount() <= best_total
        {
            return make_result(&[larger], target);
        }
    }

    let chosen: Vec<OutputGroup> = best_set.iter().map(|&p| applicable[p]).collect();
    if weight_of(&chosen) > max_selection_weight {
        // Too heavy: Core returns the closest group above target instead.
        return lowest_larger.and_then(|g| make_result(&[g], target));
    }
    make_result(&chosen, target)
}

/// Walks `groups` (sorted descending) and takes each group while the running total is below
/// `goal`, skipping groups that would exceed `max_weight`. Returns the chosen positions and total
/// if `goal` was reached.
fn greedy_subset(groups: &[OutputGroup], goal: i64, max_weight: i64) -> Option<(Vec<usize>, i64)> {
    let mut chosen = Vec::new();
    let mut total = 0i64;
    let mut weight = 0i64;
    for (pos, g) in groups.iter().enumerate() {
        if total >= goal {
            break;
        }
        if weight + g.weight > max_weight {
            continue;
        }
        chosen.push(pos);
        total += g.amount();
        weight += g.weight;
    }
    (total >= goal).then_some((chosen, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_WEIGHT: i64 = 400_000;

    /// A single-input UTXO with a typical P2WPKH input size (68 vbytes).
    fn utxo(value: i64) -> Utxo {
        Utxo {
            value,
            input_bytes: 68,
        }
    }

    #[test]
    fn bnb_finds_exact_match() {
        // Zero fee rate, so effective value equals value. 7_000 + 4_000 hits 11_000 exactly.
        let utxos = [utxo(10_000), utxo(7_000), utxo(5_000), utxo(4_000)];
        let r = select_coins_bnb(&utxos, 11_000, 0, 0, 0, MAX_WEIGHT)
            .expect("an exact subset exists");
        assert_eq!(r.inputs, vec![1, 3]);
        assert_eq!(r.total, 11_000);
        assert_eq!(r.waste, 0);
    }

    #[test]
    fn no_solution_returns_none() {
        let utxos = [utxo(10_000), utxo(10_000)];
        // Total funds short of the target.
        assert!(select_coins_bnb(&utxos, 30_000, 0, 0, 0, MAX_WEIGHT).is_none());
        assert!(knapsack_solver(&utxos, 30_000, 0, 0, 0, MAX_WEIGHT).is_none());
        // Funds suffice, but no subset falls in [15_000, 16_000]: one UTXO is short and two overshoot.
        assert!(select_coins_bnb(&utxos, 15_000, 1_000, 0, 0, MAX_WEIGHT).is_none());
    }

    #[test]
    fn knapsack_covers_target() {
        let utxos = [utxo(20_000), utxo(9_000), utxo(1_000)];
        let r = knapsack_solver(&utxos, 25_000, 5_000, 0, 0, MAX_WEIGHT)
            .expect("funds cover the target");
        assert!(r.total >= 25_000);
        let sum: i64 = r.inputs.iter().map(|&i| utxos[i].value).sum();
        assert_eq!(sum, r.total);
        assert_eq!(r.inputs, vec![0, 1]);
        assert_eq!(r.total, 29_000);
    }

    #[test]
    fn waste_is_input_waste_plus_excess() {
        // 1 sat/vB on a 68 vB input: fee 68 per input. Long-term rate 0, so input waste is 68.
        let utxos = [utxo(100_000), utxo(100_000)];
        assert_eq!(utxos[0].effective_value(1_000), 99_932);

        let r = select_coins_bnb(&utxos, 50_000, 100_000, 1_000, 0, MAX_WEIGHT)
            .expect("one input suffices");
        assert_eq!(r.inputs, vec![0]);
        assert_eq!(r.total, 99_932);
        // waste = (fee - long_term_fee) + excess = 68 + (99_932 - 50_000)
        assert_eq!(r.waste, 50_000);
    }
}
