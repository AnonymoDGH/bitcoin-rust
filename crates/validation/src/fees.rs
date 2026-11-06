//! Block policy fee estimator. Port of `src/policy/fees/block_policy_estimator.{h,cpp}`.
//!
//! Transactions are bucketed by feerate when they enter the mempool. When a block
//! arrives, the number of blocks each confirmed transaction waited is recorded in
//! three exponentially decaying horizons (short, medium, long). An estimate scans
//! buckets from the highest feerate down and reports the median feerate of the
//! cheapest bucket range that still meets the success threshold.
//!
//! Not ported: file persistence, `FeeFilterRounder`, and the caller-side
//! eligibility checks (no mempool parents, not a package, chainstate current,
//! mempool limit not bypassed). Callers must pass only eligible transactions to
//! `process_transaction`. The type is not synchronized; wrap it in a `Mutex` to share.

use bitcoin::Txid;
use std::collections::HashMap;

const SHORT_BLOCK_PERIODS: usize = 12;
const SHORT_SCALE: u32 = 1;
const MED_BLOCK_PERIODS: usize = 24;
const MED_SCALE: u32 = 2;
const LONG_BLOCK_PERIODS: usize = 42;
const LONG_SCALE: u32 = 24;

const SHORT_DECAY: f64 = 0.962;
const MED_DECAY: f64 = 0.9952;
const LONG_DECAY: f64 = 0.99931;

const HALF_SUCCESS_PCT: f64 = 0.6;
const SUCCESS_PCT: f64 = 0.85;
const DOUBLE_SUCCESS_PCT: f64 = 0.95;

const SUFFICIENT_FEETXS: f64 = 0.1;
const SUFFICIENT_TXS_SHORT: f64 = 0.5;

const MIN_BUCKET_FEERATE: f64 = 100.0;
const MAX_BUCKET_FEERATE: f64 = 1e7;
const FEE_SPACING: f64 = 1.05;
const INF_FEERATE: f64 = 1e99;

/// Feerate range and counts gathered while searching for an estimate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EstimatorBucket {
    pub start: f64,
    pub end: f64,
    pub within_target: f64,
    pub total_confirmed: f64,
    pub in_mempool: f64,
    pub left_mempool: f64,
}

impl Default for EstimatorBucket {
    fn default() -> Self {
        Self {
            start: -1.0,
            end: -1.0,
            within_target: 0.0,
            total_confirmed: 0.0,
            in_mempool: 0.0,
            left_mempool: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EstimationResult {
    pub pass: EstimatorBucket,
    pub fail: EstimatorBucket,
    pub decay: f64,
    pub scale: u32,
}

/// Which sub-estimate produced the returned feerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimateReason {
    HalfEstimate,
    FullEstimate,
    DoubleEstimate,
    Conservative,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeeCalculation {
    pub est: EstimationResult,
    pub reason: EstimateReason,
    pub desired_target: u32,
    pub returned_target: u32,
    pub best_height: u32,
}

fn make_buckets() -> Vec<f64> {
    let mut buckets = Vec::new();
    let mut boundary = MIN_BUCKET_FEERATE;
    while boundary <= MAX_BUCKET_FEERATE {
        buckets.push(boundary);
        boundary *= FEE_SPACING;
    }
    buckets.push(INF_FEERATE);
    buckets
}

/// Index of the first bucket whose upper bound is >= `feerate`.
fn bucket_index(buckets: &[f64], feerate: f64) -> usize {
    buckets
        .partition_point(|&b| b < feerate)
        .min(buckets.len() - 1)
}

/// Inclusive feerate range covered by buckets `near..=far`.
fn bucket_range(buckets: &[f64], near: usize, far: usize) -> (f64, f64) {
    let lo = near.min(far);
    let hi = near.max(far);
    let start = if lo > 0 { buckets[lo - 1] } else { 0.0 };
    (start, buckets[hi])
}

/// Port of `TxConfirmStats`: per-bucket decaying counts for one horizon.
struct TxConfirmStats {
    buckets: Vec<f64>,
    decay: f64,
    scale: u32,
    tx_ct_avg: Vec<f64>,
    feerate_avg: Vec<f64>,
    conf_avg: Vec<Vec<f64>>,
    fail_avg: Vec<Vec<f64>>,
    unconf_txs: Vec<Vec<i32>>,
    old_unconf_txs: Vec<i32>,
}

impl TxConfirmStats {
    fn new(buckets: Vec<f64>, max_periods: usize, decay: f64, scale: u32) -> Self {
        let n = buckets.len();
        let max_confirms = scale as usize * max_periods;
        Self {
            buckets,
            decay,
            scale,
            tx_ct_avg: vec![0.0; n],
            feerate_avg: vec![0.0; n],
            conf_avg: vec![vec![0.0; n]; max_periods],
            fail_avg: vec![vec![0.0; n]; max_periods],
            unconf_txs: vec![vec![0; n]; max_confirms],
            old_unconf_txs: vec![0; n],
        }
    }

    fn max_confirms(&self) -> u32 {
        self.scale * self.conf_avg.len() as u32
    }

    fn clear_current(&mut self, height: u32) {
        let row_index = height as usize % self.unconf_txs.len();
        let row = &mut self.unconf_txs[row_index];
        for (old, cur) in self.old_unconf_txs.iter_mut().zip(row.iter_mut()) {
            *old += *cur;
            *cur = 0;
        }
    }

    fn record(&mut self, blocks_to_confirm: i64, feerate: f64) {
        if blocks_to_confirm < 1 {
            return;
        }
        let scale = i64::from(self.scale);
        let periods = ((blocks_to_confirm + scale - 1) / scale) as usize;
        let bucket = bucket_index(&self.buckets, feerate);
        for conf in self.conf_avg.iter_mut().skip(periods - 1) {
            conf[bucket] += 1.0;
        }
        self.tx_ct_avg[bucket] += 1.0;
        self.feerate_avg[bucket] += feerate;
    }

    fn new_tx(&mut self, height: u32, feerate: f64) -> usize {
        let bucket = bucket_index(&self.buckets, feerate);
        let row_index = height as usize % self.unconf_txs.len();
        self.unconf_txs[row_index][bucket] += 1;
        bucket
    }

    fn remove_tx(&mut self, entry_height: u32, best_height: u32, bucket: usize, in_block: bool) {
        let blocks_ago = if best_height == 0 {
            0
        } else {
            i64::from(best_height) - i64::from(entry_height)
        };
        if blocks_ago < 0 {
            return;
        }
        let len = self.unconf_txs.len() as i64;
        if blocks_ago >= len {
            let old = &mut self.old_unconf_txs[bucket];
            if *old > 0 {
                *old -= 1;
            }
        } else {
            let row_index = entry_height as usize % len as usize;
            let cell = &mut self.unconf_txs[row_index][bucket];
            if *cell > 0 {
                *cell -= 1;
            }
        }
        let scale = i64::from(self.scale);
        if !in_block && blocks_ago >= scale {
            let periods_ago = ((blocks_ago / scale) as usize).min(self.fail_avg.len());
            for fail in self.fail_avg.iter_mut().take(periods_ago) {
                fail[bucket] += 1.0;
            }
        }
    }

    fn update_moving_averages(&mut self) {
        let decay = self.decay;
        for x in self.tx_ct_avg.iter_mut().chain(self.feerate_avg.iter_mut()) {
            *x *= decay;
        }
        for row in self.conf_avg.iter_mut().chain(self.fail_avg.iter_mut()) {
            for x in row.iter_mut() {
                *x *= decay;
            }
        }
    }

    /// Returns the median feerate, or -1 when no bucket range meets `success_break_point`.
    fn estimate_median_val(
        &self,
        conf_target: u32,
        sufficient_tx_val: f64,
        success_break_point: f64,
        best_height: u32,
    ) -> (f64, EstimationResult) {
        let period_target = conf_target.div_ceil(self.scale) as usize;
        let max_bucket = self.buckets.len() - 1;
        let max_confirms = self.max_confirms();
        let bins = self.unconf_txs.len();

        let mut n_conf = 0.0;
        let mut total_num = 0.0;
        let mut extra_num: i32 = 0;
        let mut fail_num = 0.0;
        let mut partial_num = 0.0;

        let mut cur_near = max_bucket;
        let mut best_near = max_bucket;
        let mut cur_far = max_bucket;
        let mut best_far = max_bucket;
        let mut new_bucket_range = true;
        let mut found_answer = false;
        let mut passing = true;
        let mut pass_bucket = EstimatorBucket::default();
        let mut fail_bucket = EstimatorBucket::default();

        for bucket in (0..=max_bucket).rev() {
            if new_bucket_range {
                cur_near = bucket;
                new_bucket_range = false;
            }
            cur_far = bucket;
            n_conf += self.conf_avg[period_target - 1][bucket];
            partial_num += self.tx_ct_avg[bucket];
            total_num += self.tx_ct_avg[bucket];
            fail_num += self.fail_avg[period_target - 1][bucket];
            for confct in conf_target..max_confirms {
                let height = best_height.wrapping_sub(confct) as usize % bins;
                extra_num += self.unconf_txs[height][bucket];
            }
            extra_num += self.old_unconf_txs[bucket];

            if partial_num < sufficient_tx_val / (1.0 - self.decay) {
                continue;
            }
            partial_num = 0.0;

            let cur_pct = n_conf / (total_num + fail_num + f64::from(extra_num));
            if cur_pct < success_break_point {
                if passing {
                    let (start, end) = bucket_range(&self.buckets, cur_near, cur_far);
                    fail_bucket = EstimatorBucket {
                        start,
                        end,
                        within_target: n_conf,
                        total_confirmed: total_num,
                        in_mempool: f64::from(extra_num),
                        left_mempool: fail_num,
                    };
                    passing = false;
                }
                continue;
            }
            fail_bucket = EstimatorBucket::default();
            found_answer = true;
            passing = true;
            pass_bucket.within_target = n_conf;
            pass_bucket.total_confirmed = total_num;
            pass_bucket.in_mempool = f64::from(extra_num);
            pass_bucket.left_mempool = fail_num;
            n_conf = 0.0;
            total_num = 0.0;
            fail_num = 0.0;
            extra_num = 0;
            best_near = cur_near;
            best_far = cur_far;
            new_bucket_range = true;
        }

        let mut median = -1.0;
        let (min_b, max_b) = (best_near.min(best_far), best_near.max(best_far));
        let mut tx_sum: f64 = self.tx_ct_avg[min_b..=max_b].iter().sum();
        if found_answer && tx_sum != 0.0 {
            tx_sum /= 2.0;
            let counts = self.tx_ct_avg[min_b..=max_b].iter();
            let avgs = self.feerate_avg[min_b..=max_b].iter();
            for (ct, total_feerate) in counts.zip(avgs) {
                if *ct < tx_sum {
                    tx_sum -= ct;
                } else {
                    median = total_feerate / ct;
                    break;
                }
            }
            (pass_bucket.start, pass_bucket.end) = bucket_range(&self.buckets, best_near, best_far);
        }

        if passing && !new_bucket_range {
            let (start, end) = bucket_range(&self.buckets, cur_near, cur_far);
            fail_bucket = EstimatorBucket {
                start,
                end,
                within_target: n_conf,
                total_confirmed: total_num,
                in_mempool: f64::from(extra_num),
                left_mempool: fail_num,
            };
        }

        let result = EstimationResult {
            pass: pass_bucket,
            fail: fail_bucket,
            decay: self.decay,
            scale: self.scale,
        };
        (median, result)
    }
}

#[derive(Debug, Clone, Copy)]
struct TxStatsInfo {
    block_height: u32,
    bucket_index: usize,
    fee_rate: f64,
}

pub struct FeeEstimator {
    best_seen_height: u32,
    first_recorded_height: u32,
    mempool_txs: HashMap<Txid, TxStatsInfo>,
    med_stats: TxConfirmStats,
    short_stats: TxConfirmStats,
    long_stats: TxConfirmStats,
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl FeeEstimator {
    pub fn new() -> Self {
        let buckets = make_buckets();
        Self {
            best_seen_height: 0,
            first_recorded_height: 0,
            mempool_txs: HashMap::new(),
            med_stats: TxConfirmStats::new(
                buckets.clone(),
                MED_BLOCK_PERIODS,
                MED_DECAY,
                MED_SCALE,
            ),
            short_stats: TxConfirmStats::new(
                buckets.clone(),
                SHORT_BLOCK_PERIODS,
                SHORT_DECAY,
                SHORT_SCALE,
            ),
            long_stats: TxConfirmStats::new(buckets, LONG_BLOCK_PERIODS, LONG_DECAY, LONG_SCALE),
        }
    }

    /// Track a transaction that entered the mempool at chain height `height`.
    /// `fee_rate_sat_per_kvb` is the whole-satoshi feerate, as `CFeeRate::GetFeePerK` reports it.
    /// Ignored unless `height` is the current best seen height.
    pub fn process_transaction(&mut self, txid: Txid, height: u32, fee_rate_sat_per_kvb: f64) {
        if self.mempool_txs.contains_key(&txid) || height != self.best_seen_height {
            return;
        }
        let bucket_index = self.med_stats.new_tx(height, fee_rate_sat_per_kvb);
        self.short_stats.new_tx(height, fee_rate_sat_per_kvb);
        self.long_stats.new_tx(height, fee_rate_sat_per_kvb);
        self.mempool_txs.insert(
            txid,
            TxStatsInfo {
                block_height: height,
                bucket_index,
                fee_rate: fee_rate_sat_per_kvb,
            },
        );
    }

    /// Stop tracking a transaction that left the mempool without being mined.
    pub fn remove_tx(&mut self, txid: Txid) -> bool {
        self.remove_inner(&txid, false).is_some()
    }

    /// Record the transactions confirmed in the block at `height`. Blocks at or below
    /// the best seen height are ignored.
    pub fn process_block(&mut self, height: u32, confirmed: &[Txid]) {
        if height <= self.best_seen_height {
            return;
        }
        self.best_seen_height = height;
        for stats in [
            &mut self.med_stats,
            &mut self.short_stats,
            &mut self.long_stats,
        ] {
            stats.clear_current(height);
            stats.update_moving_averages();
        }

        let mut counted = 0;
        for txid in confirmed {
            if self.process_block_tx(height, txid) {
                counted += 1;
            }
        }
        if self.first_recorded_height == 0 && counted > 0 {
            self.first_recorded_height = self.best_seen_height;
        }
    }

    /// Feerate (sat/kvB) expected to confirm within `conf_target` blocks at the 95% level.
    /// `None` for targets at or below 1, and when there is not enough data.
    pub fn estimate_fee(&self, conf_target: u32) -> Option<f64> {
        if conf_target <= 1 {
            return None;
        }
        self.estimate_raw_fee(
            &self.med_stats,
            SUFFICIENT_FEETXS,
            conf_target,
            DOUBLE_SUCCESS_PCT,
        )
    }

    /// Feerate (sat/kvB) for `conf_target` blocks, with the target it was computed for.
    /// A target below 2 is raised to 2, and a target above the usable history is lowered.
    pub fn estimate_smart_fee(&self, conf_target: u32, conservative: bool) -> Option<(f64, u32)> {
        self.estimate_smart_fee_detail(conf_target, conservative)
            .map(|(rate, calc)| (rate, calc.returned_target))
    }

    /// Same as `estimate_smart_fee`, also returning how the estimate was chosen.
    pub fn estimate_smart_fee_detail(
        &self,
        conf_target: u32,
        conservative: bool,
    ) -> Option<(f64, FeeCalculation)> {
        if conf_target == 0 || conf_target > self.long_stats.max_confirms() {
            return None;
        }
        let requested = if conf_target == 1 { 2 } else { conf_target };
        let target = requested.min(self.max_usable_estimate());
        if target <= 1 {
            return None;
        }

        let mut calc = FeeCalculation {
            est: EstimationResult::default(),
            reason: EstimateReason::HalfEstimate,
            desired_target: conf_target,
            returned_target: target,
            best_height: self.best_seen_height,
        };

        let (half, est) = self.estimate_combined_fee(target / 2, HALF_SUCCESS_PCT, true);
        calc.est = est;
        let mut median = half;

        let (full, est) = self.estimate_combined_fee(target, SUCCESS_PCT, true);
        if full > median {
            median = full;
            calc.est = est;
            calc.reason = EstimateReason::FullEstimate;
        }

        let (double, est) =
            self.estimate_combined_fee(2 * target, DOUBLE_SUCCESS_PCT, !conservative);
        if double > median {
            median = double;
            calc.est = est;
            calc.reason = EstimateReason::DoubleEstimate;
        }

        if conservative || median == -1.0 {
            let (conservative_est, est) = self.estimate_conservative_fee(2 * target);
            if conservative_est > median {
                median = conservative_est;
                calc.est = est;
                calc.reason = EstimateReason::Conservative;
            }
        }

        let rate = median.round();
        (rate > 0.0).then_some((rate, calc))
    }

    /// Highest confirmation target for which estimates are tracked.
    pub fn highest_target_tracked(&self) -> u32 {
        self.long_stats.max_confirms()
    }

    fn remove_inner(&mut self, txid: &Txid, in_block: bool) -> Option<TxStatsInfo> {
        let info = self.mempool_txs.remove(txid)?;
        let best = self.best_seen_height;
        for stats in [
            &mut self.med_stats,
            &mut self.short_stats,
            &mut self.long_stats,
        ] {
            stats.remove_tx(info.block_height, best, info.bucket_index, in_block);
        }
        Some(info)
    }

    fn process_block_tx(&mut self, height: u32, txid: &Txid) -> bool {
        let Some(info) = self.remove_inner(txid, true) else {
            return false;
        };
        let blocks_to_confirm = i64::from(height) - i64::from(info.block_height);
        if blocks_to_confirm <= 0 {
            return false;
        }
        self.med_stats.record(blocks_to_confirm, info.fee_rate);
        self.short_stats.record(blocks_to_confirm, info.fee_rate);
        self.long_stats.record(blocks_to_confirm, info.fee_rate);
        true
    }

    fn estimate_raw_fee(
        &self,
        stats: &TxConfirmStats,
        sufficient_txs: f64,
        conf_target: u32,
        success: f64,
    ) -> Option<f64> {
        if conf_target == 0 || conf_target > stats.max_confirms() || success > 1.0 {
            return None;
        }
        let (median, _) =
            stats.estimate_median_val(conf_target, sufficient_txs, success, self.best_seen_height);
        let rate = median.round();
        (rate > 0.0).then_some(rate)
    }

    /// Estimate from the shortest horizon that tracks `conf_target`. With `check_shorter`,
    /// a lower target from a more recent horizon may lower the answer.
    fn estimate_combined_fee(
        &self,
        conf_target: u32,
        success: f64,
        check_shorter: bool,
    ) -> (f64, EstimationResult) {
        let best = self.best_seen_height;
        let mut est = -1.0;
        let mut result = EstimationResult::default();
        if conf_target < 1 || conf_target > self.long_stats.max_confirms() {
            return (est, result);
        }
        let short_max = self.short_stats.max_confirms();
        let med_max = self.med_stats.max_confirms();

        (est, result) = if conf_target <= short_max {
            self.short_stats
                .estimate_median_val(conf_target, SUFFICIENT_TXS_SHORT, success, best)
        } else if conf_target <= med_max {
            self.med_stats
                .estimate_median_val(conf_target, SUFFICIENT_FEETXS, success, best)
        } else {
            self.long_stats
                .estimate_median_val(conf_target, SUFFICIENT_FEETXS, success, best)
        };

        if check_shorter {
            if conf_target > med_max {
                let (med_val, med_result) =
                    self.med_stats
                        .estimate_median_val(med_max, SUFFICIENT_FEETXS, success, best);
                if med_val > 0.0 && (est == -1.0 || med_val < est) {
                    est = med_val;
                    result = med_result;
                }
            }
            if conf_target > short_max {
                let (short_val, short_result) = self.short_stats.estimate_median_val(
                    short_max,
                    SUFFICIENT_TXS_SHORT,
                    success,
                    best,
                );
                if short_val > 0.0 && (est == -1.0 || short_val < est) {
                    est = short_val;
                    result = short_result;
                }
            }
        }
        (est, result)
    }

    /// Requires the 95% threshold to also hold at `double_target` over longer horizons.
    fn estimate_conservative_fee(&self, double_target: u32) -> (f64, EstimationResult) {
        let best = self.best_seen_height;
        let mut est = -1.0;
        let mut result = EstimationResult::default();
        if double_target <= self.short_stats.max_confirms() {
            (est, result) = self.med_stats.estimate_median_val(
                double_target,
                SUFFICIENT_FEETXS,
                DOUBLE_SUCCESS_PCT,
                best,
            );
        }
        if double_target <= self.med_stats.max_confirms() {
            let (long_est, long_result) = self.long_stats.estimate_median_val(
                double_target,
                SUFFICIENT_FEETXS,
                DOUBLE_SUCCESS_PCT,
                best,
            );
            if long_est > est {
                est = long_est;
                result = long_result;
            }
        }
        (est, result)
    }

    fn block_span(&self) -> u32 {
        if self.first_recorded_height == 0 {
            0
        } else {
            self.best_seen_height
                .saturating_sub(self.first_recorded_height)
        }
    }

    /// Half the observed block span, so that enough failing data points exist.
    fn max_usable_estimate(&self) -> u32 {
        self.long_stats.max_confirms().min(self.block_span() / 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::Hash;

    fn txid(n: u64) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        Txid::from_byte_array(bytes)
    }

    /// (feerate sat/kvB, blocks until confirmed; `None` = never confirmed, evicted from mempool)
    const TIERS: [(f64, Option<u32>); 5] = [
        (50_000.0, Some(1)),
        (20_000.0, Some(2)),
        (10_000.0, Some(4)),
        (5_000.0, Some(8)),
        (2_000.0, None),
    ];
    const EVICT_AFTER: u32 = 12;
    const TXS_PER_TIER_PER_BLOCK: usize = 2;

    /// Each block confirms the txs of every tier after that tier's delay, so higher
    /// feerates confirm sooner. The low tier never confirms and is evicted.
    fn simulate(blocks: u32) -> FeeEstimator {
        let mut est = FeeEstimator::new();
        let mut next_id = 0u64;
        let mut pending: Vec<(u32, usize, Txid)> = Vec::new();
        for height in 1..=blocks {
            let created = height - 1;
            for (tier, &(rate, _)) in TIERS.iter().enumerate() {
                for _ in 0..TXS_PER_TIER_PER_BLOCK {
                    let id = txid(next_id);
                    next_id += 1;
                    est.process_transaction(id, created, rate);
                    pending.push((created, tier, id));
                }
            }

            let mut confirmed = Vec::new();
            let mut evicted = Vec::new();
            let mut still_pending = Vec::new();
            for (created_at, tier, id) in pending.drain(..) {
                match TIERS[tier].1 {
                    Some(delay) if created_at + delay == height => confirmed.push(id),
                    None if created_at + EVICT_AFTER == height => evicted.push(id),
                    _ => still_pending.push((created_at, tier, id)),
                }
            }
            pending = still_pending;

            est.process_block(height, &confirmed);
            for id in evicted {
                assert!(est.remove_tx(id));
            }
        }
        est
    }

    /// Feerates that the simulated txs of tiers confirming within `target` blocks have.
    fn passing_rates(target: u32) -> Vec<f64> {
        TIERS
            .iter()
            .filter(|(_, delay)| matches!(delay, Some(d) if *d <= target))
            .map(|(rate, _)| *rate)
            .collect()
    }

    #[test]
    fn buckets_span_min_to_max_with_infinite_top() {
        let buckets = make_buckets();
        assert_eq!(buckets[0], MIN_BUCKET_FEERATE);
        assert_eq!(*buckets.last().unwrap(), INF_FEERATE);
        assert_eq!(buckets.len(), 237);
        assert!(buckets[buckets.len() - 2] <= MAX_BUCKET_FEERATE);
        assert_eq!(bucket_index(&buckets, 0.0), 0);
        assert_eq!(bucket_index(&buckets, 1e20), buckets.len() - 1);
    }

    #[test]
    fn no_data_gives_no_estimate() {
        let est = FeeEstimator::new();
        assert_eq!(est.estimate_fee(2), None);
        assert_eq!(est.estimate_smart_fee(2, false), None);
        assert_eq!(est.estimate_smart_fee(2, true), None);
        assert_eq!(est.estimate_smart_fee(0, false), None);
        assert_eq!(est.estimate_smart_fee(1009, false), None);
        assert_eq!(est.highest_target_tracked(), 1008);
    }

    #[test]
    fn unconfirmed_txs_alone_give_no_estimate() {
        let mut est = FeeEstimator::new();
        est.process_transaction(txid(1), 0, 50_000.0);
        est.process_block(1, &[]);
        est.process_transaction(txid(2), 1, 50_000.0);
        assert_eq!(est.estimate_smart_fee(2, false), None);
    }

    #[test]
    fn transactions_at_stale_height_are_ignored() {
        let mut est = FeeEstimator::new();
        est.process_block(5, &[]);
        est.process_transaction(txid(1), 4, 50_000.0);
        assert!(!est.remove_tx(txid(1)));
        est.process_transaction(txid(2), 5, 50_000.0);
        assert!(est.remove_tx(txid(2)));
        assert!(!est.remove_tx(txid(2)));
    }

    #[test]
    fn higher_feerates_confirm_faster_and_estimates_are_monotonic() {
        let est = simulate(400);
        let mut prev = f64::INFINITY;
        for target in 2..=48 {
            let (rate, returned) = est
                .estimate_smart_fee(target, false)
                .unwrap_or_else(|| panic!("no estimate for target {target}"));
            assert!(rate <= prev, "target {target}: {rate} > previous {prev}");
            assert!(returned <= target && returned >= 2);
            let rates = passing_rates(returned);
            let lo = rates.iter().copied().fold(f64::INFINITY, f64::min);
            let hi = rates.iter().copied().fold(0.0, f64::max);
            assert!(
                rate >= lo - 1.0 && rate <= hi + 1.0,
                "target {target}: {rate} outside [{lo}, {hi}]"
            );
            prev = rate;
        }
    }

    #[test]
    fn estimates_step_down_as_target_grows() {
        let est = simulate(400);
        assert_eq!(est.estimate_smart_fee(2, false), Some((50_000.0, 2)));
        assert_eq!(est.estimate_smart_fee(5, false), Some((20_000.0, 5)));
        assert_eq!(est.estimate_smart_fee(10, false), Some((10_000.0, 10)));
        assert_eq!(est.estimate_smart_fee(20, false), Some((5_000.0, 20)));
        assert_eq!(est.estimate_fee(2), Some(20_000.0));
        assert_eq!(est.estimate_fee(4), Some(10_000.0));
        assert_eq!(est.estimate_fee(1), None);
    }

    #[test]
    fn conservative_is_never_lower_than_default() {
        let est = simulate(400);
        for target in 2..=48 {
            let plain = est.estimate_smart_fee(target, false).unwrap().0;
            let conservative = est.estimate_smart_fee(target, true).unwrap().0;
            assert!(
                conservative >= plain,
                "target {target}: {conservative} < {plain}"
            );
        }
    }

    #[test]
    fn detail_reports_how_the_estimate_was_chosen() {
        let est = simulate(400);
        let (rate, calc) = est.estimate_smart_fee_detail(2, false).unwrap();
        assert_eq!(rate, 50_000.0);
        assert_eq!(calc.desired_target, 2);
        assert_eq!(calc.returned_target, 2);
        assert_eq!(calc.best_height, 400);
        assert_eq!(calc.reason, EstimateReason::HalfEstimate);
    }
}
