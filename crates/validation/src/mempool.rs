//! Transaction memory pool. Minimal port of src/txmempool.h and src/txmempool.cpp.
//!
//! Scope: entry storage, a spent-outpoint index for conflict detection, a size
//! limit, and fee-rate ordering. Ancestor/descendant package limits and
//! persistence (mempool.dat) are not implemented.

use std::collections::{HashMap, HashSet};

use btc_primitives::{OutPoint, Tx, Txid};
use thiserror::Error;

/// A transaction accepted into the pool together with its fee and virtual size.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Tx,
    /// Fee paid by the transaction, in satoshis. Validated by the caller.
    pub fee: i64,
    /// Virtual size in vbytes (weight / 4, rounded up). Must be non-zero.
    pub vsize: u64,
}

impl MempoolEntry {
    /// Fee rate in satoshis per vbyte. Use `cmp_fee_rate` for exact ordering.
    pub fn fee_rate(&self) -> f64 {
        self.fee as f64 / self.vsize as f64
    }
}

/// Exact comparison of `a.fee / a.vsize` against `b.fee / b.vsize`.
///
/// Cross-multiplies in i128 so ordering does not depend on float rounding,
/// which matches how Core compares CFeeRate values.
fn cmp_fee_rate(a: &MempoolEntry, b: &MempoolEntry) -> std::cmp::Ordering {
    let lhs = a.fee as i128 * b.vsize as i128;
    let rhs = b.fee as i128 * a.vsize as i128;
    lhs.cmp(&rhs)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MempoolError {
    #[error("transaction {0} is already in the mempool")]
    AlreadyInPool(Txid),
    #[error("transaction {0} has zero vsize")]
    ZeroVsize(Txid),
    #[error("transaction spends outpoint {outpoint} twice")]
    DuplicateInput { outpoint: OutPoint },
    #[error("outpoint {outpoint} is already spent by mempool transaction {spender}")]
    Conflict { outpoint: OutPoint, spender: Txid },
    #[error("mempool is full (max {max} entries)")]
    PoolFull { max: usize },
}

/// In-memory transaction pool.
#[derive(Debug)]
pub struct Mempool {
    entries: HashMap<Txid, MempoolEntry>,
    /// Maps each outpoint spent by a pool transaction to that transaction.
    /// Used to reject double-spends and to find conflicts with new blocks.
    spent: HashMap<OutPoint, Txid>,
    max_entries: usize,
}

impl Mempool {
    /// Creates an empty pool that holds at most `max_entries` transactions.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            spent: HashMap::new(),
            max_entries,
        }
    }

    /// Inserts an entry. Rejects duplicates, zero-vsize entries, duplicate
    /// inputs, double-spends of outpoints already spent in the pool, and
    /// inserts beyond `max_entries`. On error the pool is left unchanged.
    pub fn add(&mut self, entry: MempoolEntry) -> Result<(), MempoolError> {
        let txid = entry.tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyInPool(txid));
        }
        if entry.vsize == 0 {
            return Err(MempoolError::ZeroVsize(txid));
        }
        if self.entries.len() >= self.max_entries {
            return Err(MempoolError::PoolFull {
                max: self.max_entries,
            });
        }

        // Check every input before touching `spent`, so a failure leaves no
        // partial index entries behind. The local set catches a tx that lists
        // the same outpoint twice, which would otherwise overwrite itself.
        let mut seen = HashSet::with_capacity(entry.tx.vin.len());
        for input in &entry.tx.vin {
            if !seen.insert(input.prevout) {
                return Err(MempoolError::DuplicateInput {
                    outpoint: input.prevout,
                });
            }
            if let Some(spender) = self.spent.get(&input.prevout) {
                return Err(MempoolError::Conflict {
                    outpoint: input.prevout,
                    spender: *spender,
                });
            }
        }

        for input in &entry.tx.vin {
            self.spent.insert(input.prevout, txid);
        }
        self.entries.insert(txid, entry);
        Ok(())
    }

    /// Removes a transaction and clears its entries in the spent index.
    pub fn remove(&mut self, txid: &Txid) -> Option<MempoolEntry> {
        let entry = self.entries.remove(txid)?;
        for input in &entry.tx.vin {
            // Only clear outpoints that still point at this transaction.
            if self.spent.get(&input.prevout) == Some(txid) {
                self.spent.remove(&input.prevout);
            }
        }
        Some(entry)
    }

    /// Removes every pool transaction that conflicts with `tx` (for example,
    /// one confirmed in a block), along with their in-pool descendants, as
    /// Core's `removeConflicts` + `removeRecursive` does. Returns the removed
    /// txids. A transaction that is itself in the pool is not treated as a
    /// conflict of itself.
    pub fn remove_conflicts(&mut self, tx: &Tx) -> Vec<Txid> {
        let own = tx.txid();
        let roots: Vec<Txid> = tx
            .vin
            .iter()
            .filter_map(|input| self.spent.get(&input.prevout).copied())
            .filter(|spender| *spender != own)
            .collect();

        let mut removed = Vec::new();
        for root in roots {
            // A root may already have been removed as a descendant of an
            // earlier root; `remove_with_descendants` then returns nothing.
            removed.extend(self.remove_with_descendants(root));
        }
        removed
    }

    /// Removes `root` and every in-pool transaction that spends one of its
    /// outputs, transitively. Iterative to avoid deep recursion.
    fn remove_with_descendants(&mut self, root: Txid) -> Vec<Txid> {
        let mut removed = Vec::new();
        let mut stack = vec![root];
        while let Some(txid) = stack.pop() {
            let Some(entry) = self.remove(&txid) else {
                continue;
            };
            for vout in 0..entry.tx.vout.len() as u32 {
                let outpoint = OutPoint { txid, vout };
                if let Some(child) = self.spent.get(&outpoint).copied() {
                    stack.push(child);
                }
            }
            removed.push(txid);
        }
        removed
    }

    /// Returns the pool transaction that spends `outpoint`, if any.
    pub fn spender_of(&self, outpoint: &OutPoint) -> Option<&Txid> {
        self.spent.get(outpoint)
    }

    pub fn contains(&self, txid: &Txid) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn get(&self, txid: &Txid) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries sorted by fee rate, highest first. Ties are broken by txid
    /// so the order is deterministic.
    pub fn sorted_by_fee_rate(&self) -> Vec<&MempoolEntry> {
        let mut items: Vec<(&Txid, &MempoolEntry)> = self.entries.iter().collect();
        items.sort_by(|(ta, a), (tb, b)| cmp_fee_rate(b, a).then_with(|| ta.cmp(tb)));
        items.into_iter().map(|(_, entry)| entry).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use btc_primitives::{ScriptBuf, TxIn, TxOut};

    /// Outpoint whose txid is distinct for each `n`.
    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        }
    }

    /// Transaction spending `inputs` and creating `outputs` dummy outputs.
    fn make_tx(inputs: &[OutPoint], outputs: u32) -> Tx {
        let vin = inputs.iter().map(|op| TxIn::new(*op)).collect();
        let vout = (0..outputs)
            .map(|_| TxOut::new(1_000, ScriptBuf::new()))
            .collect();
        Tx::new(2, vin, vout, 0)
    }

    #[test]
    fn add_get_and_sort_by_fee_rate() {
        let mut pool = Mempool::new(10);
        let a = make_tx(&[outpoint(1)], 1);
        let b = make_tx(&[outpoint(2)], 1);
        let c = make_tx(&[outpoint(3)], 1);
        let (a_id, b_id, c_id) = (a.txid(), b.txid(), c.txid());

        pool.add(MempoolEntry { tx: a, fee: 1_000, vsize: 200 }).unwrap(); // 5 sat/vB
        pool.add(MempoolEntry { tx: b, fee: 3_000, vsize: 200 }).unwrap(); // 15 sat/vB
        pool.add(MempoolEntry { tx: c, fee: 500, vsize: 100 }).unwrap(); // 5 sat/vB

        assert_eq!(pool.len(), 3);
        assert!(!pool.is_empty());
        assert!(pool.contains(&a_id));
        assert_eq!(pool.get(&a_id).unwrap().fee, 1_000);

        let sorted = pool.sorted_by_fee_rate();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].tx.txid(), b_id);
        assert!(sorted.windows(2).all(|w| w[0].fee_rate() >= w[1].fee_rate()));
        assert!(sorted.iter().any(|e| e.tx.txid() == c_id));
    }

    #[test]
    fn rejects_duplicates_and_enforces_limit() {
        let mut pool = Mempool::new(1);
        let a = make_tx(&[outpoint(1)], 1);
        let a_id = a.txid();
        pool.add(MempoolEntry { tx: a.clone(), fee: 1_000, vsize: 200 }).unwrap();

        assert_eq!(
            pool.add(MempoolEntry { tx: a, fee: 1_000, vsize: 200 }),
            Err(MempoolError::AlreadyInPool(a_id))
        );

        let b = make_tx(&[outpoint(2)], 1);
        assert_eq!(
            pool.add(MempoolEntry { tx: b, fee: 1_000, vsize: 200 }),
            Err(MempoolError::PoolFull { max: 1 })
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_double_spend_until_spender_removed() {
        let mut pool = Mempool::new(10);
        let a = make_tx(&[outpoint(1)], 1);
        let b = make_tx(&[outpoint(1)], 2); // spends the same outpoint as `a`
        let (a_id, b_id) = (a.txid(), b.txid());

        pool.add(MempoolEntry { tx: a, fee: 1_000, vsize: 200 }).unwrap();
        assert_eq!(
            pool.add(MempoolEntry { tx: b.clone(), fee: 2_000, vsize: 200 }),
            Err(MempoolError::Conflict {
                outpoint: outpoint(1),
                spender: a_id,
            })
        );
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&b_id));
        assert_eq!(pool.spender_of(&outpoint(1)), Some(&a_id));

        // Removing the spender frees the outpoint for the replacement.
        assert!(pool.remove(&a_id).is_some());
        assert!(pool.spender_of(&outpoint(1)).is_none());
        pool.add(MempoolEntry { tx: b, fee: 2_000, vsize: 200 }).unwrap();
        assert_eq!(pool.spender_of(&outpoint(1)), Some(&b_id));
    }

    #[test]
    fn remove_conflicts_drops_conflict_and_descendants() {
        let mut pool = Mempool::new(10);

        // parent spends outpoint(1); child spends parent's output; unrelated
        // tx spends outpoint(9).
        let parent = make_tx(&[outpoint(1)], 1);
        let parent_id = parent.txid();
        let child = make_tx(&[OutPoint { txid: parent_id, vout: 0 }], 1);
        let child_id = child.txid();
        let unrelated = make_tx(&[outpoint(9)], 1);
        let unrelated_id = unrelated.txid();

        pool.add(MempoolEntry { tx: parent, fee: 1_000, vsize: 200 }).unwrap();
        pool.add(MempoolEntry { tx: child, fee: 1_000, vsize: 200 }).unwrap();
        pool.add(MempoolEntry { tx: unrelated, fee: 1_000, vsize: 200 }).unwrap();

        // A block transaction that spends outpoint(1) conflicts with `parent`.
        let block_tx = make_tx(&[outpoint(1)], 3);
        let mut removed = pool.remove_conflicts(&block_tx);
        removed.sort();
        let mut expected = vec![parent_id, child_id];
        expected.sort();

        assert_eq!(removed, expected);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&unrelated_id));
        assert!(pool.spender_of(&outpoint(1)).is_none());
        assert!(pool.spender_of(&OutPoint { txid: parent_id, vout: 0 }).is_none());
    }
}
