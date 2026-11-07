//! UTXO set. Port of src/coins.h / src/coins.cpp.
//!
//! PUBLIC CONTRACT: other modules depend on these exact names and signatures.
//! The owning agent may add fields/methods/derives but must not rename or
//! change the signatures below.
//!
//! Scope: in-memory backend and the cache overlay only. LevelDB persistence,
//! cursors, FRESH-aware batch merging between cache layers, and cache-to-cache
//! stacking are not ported yet.

use std::collections::HashMap;
use std::fmt;

use bitcoin::{BlockHash, OutPoint, Script};
use btc_primitives::TxOut;

/// Core `MAX_SCRIPT_SIZE`. Larger scriptPubKeys are unspendable.
const MAX_SCRIPT_SIZE: usize = 10_000;

/// `OP_RETURN` opcode byte.
const OP_RETURN: u8 = 0x6a;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub txout: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
}

pub trait CoinsView {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin>;
}

/// A view that accepts bulk writes. `CoinsViewCache` flushes into one of these.
pub trait CoinsViewWrite: CoinsView {
    /// Applies changes in order. `Some(coin)` inserts or replaces the entry,
    /// `None` removes it (the coin was spent).
    fn batch_write(&mut self, changes: Vec<(OutPoint, Option<Coin>)>);

    /// Same as `batch_write`, also recording `best` (`hashBestBlock`) in the
    /// same atomic batch. The default ignores `best`.
    fn batch_write_best(&mut self, changes: Vec<(OutPoint, Option<Coin>)>, best: BlockHash) {
        let _ = best;
        self.batch_write(changes);
    }

    /// Block whose state this view reflects (`GetBestBlock`), if persisted.
    fn best_block(&self) -> Option<BlockHash> {
        None
    }
}

/// Errors returned by cache mutations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoinsError {
    /// `add_coin` was called with `possible_overwrite == false`, but the cache
    /// already holds an unspent coin for that outpoint.
    OverwriteUnspent,
}

impl fmt::Display for CoinsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoinsError::OverwriteUnspent => write!(f, "attempted to overwrite an unspent coin"),
        }
    }
}

impl std::error::Error for CoinsError {}

/// True if a scriptPubKey can never be spent (Core `CScript::IsUnspendable`).
/// Confidential outputs (`OP_RETURN 0x01 ...`) are spendable by ring proofs,
/// and pool note scripts (`OP_RETURN OP_PUSHDATA1(32) ...`) by note spend
/// proofs, so they are not unspendable even though they start with OP_RETURN.
pub fn is_unspendable(script_pubkey: &Script) -> bool {
    if script_pubkey.len() > MAX_SCRIPT_SIZE {
        return true;
    }
    let bytes = script_pubkey.as_bytes();
    if bytes.first() != Some(&OP_RETURN) {
        return false;
    }
    if bytes.get(1) == Some(&btc_consensus::CT_SCRIPT_VERSION) {
        return false;
    }
    // Pool note: OP_RETURN OP_PUSHDATA1(32) <cmu> (legacy),
    // OP_RETURN OP_PUSHDATA1(65) <cmu || value commitment> (committed),
    // or OP_RETURN OP_PUSHDATA1(97) <cmu || poseidon || commitment> (v3).
    !((bytes.len() == 35 && bytes[1] == 0x4c && bytes[2] == 32)
        || (bytes.len() == 68 && bytes[1] == 0x4c && bytes[2] == 65)
        || (bytes.len() == 100 && bytes[1] == 0x4c && bytes[2] == 97))
}

/// In-memory UTXO set backed by a `HashMap`.
#[derive(Clone, Debug, Default)]
pub struct CoinsViewMemory {
    coins: HashMap<OutPoint, Coin>,
    best: Option<BlockHash>,
}

impl CoinsViewMemory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces a coin directly, bypassing any cache.
    pub fn insert(&mut self, outpoint: OutPoint, coin: Coin) {
        self.coins.insert(outpoint, coin);
    }

    pub fn len(&self) -> usize {
        self.coins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }
}

impl CoinsView for CoinsViewMemory {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins.get(outpoint).cloned()
    }
}

impl CoinsViewWrite for CoinsViewMemory {
    fn batch_write(&mut self, changes: Vec<(OutPoint, Option<Coin>)>) {
        for (outpoint, coin) in changes {
            match coin {
                Some(coin) => {
                    self.coins.insert(outpoint, coin);
                }
                None => {
                    self.coins.remove(&outpoint);
                }
            }
        }
    }

    fn batch_write_best(&mut self, changes: Vec<(OutPoint, Option<Coin>)>, best: BlockHash) {
        self.batch_write(changes);
        self.best = Some(best);
    }

    fn best_block(&self) -> Option<BlockHash> {
        self.best
    }
}

/// One overlay entry. Only outpoints touched by a mutation are stored, so every
/// entry is dirty and must reach the base on flush.
struct Entry {
    /// `None` is a spend that has not been flushed yet (Core's spent-but-DIRTY).
    coin: Option<Coin>,
    /// The base has no unspent coin for this outpoint (Core's FRESH). A spend of
    /// a fresh entry removes it outright instead of recording a tombstone.
    fresh: bool,
}

/// Write-back cache over a writable base view.
///
/// Reads check the overlay first and fall through to the base. Mutations touch
/// only the overlay until `flush` pushes them into the base. Dropping the cache
/// without calling `flush` discards the changes.
pub struct CoinsViewCache<'a> {
    base: &'a mut dyn CoinsViewWrite,
    entries: HashMap<OutPoint, Entry>,
}

impl<'a> CoinsViewCache<'a> {
    pub fn new(base: &'a mut dyn CoinsViewWrite) -> Self {
        Self {
            base,
            entries: HashMap::new(),
        }
    }

    /// Adds a coin. Unspendable outputs are silently skipped, as in Core.
    ///
    /// With `possible_overwrite == false` the caller promises no unspent coin
    /// exists in the base. Only the overlay is checked for an existing unspent
    /// coin, so passing `false` for a base coin breaks the contract.
    pub fn add_coin(
        &mut self,
        outpoint: OutPoint,
        coin: Coin,
        possible_overwrite: bool,
    ) -> Result<(), CoinsError> {
        debug_assert!(!coin.txout.is_null());
        if is_unspendable(&coin.txout.script_pubkey) {
            return Ok(());
        }
        match self.entries.get_mut(&outpoint) {
            Some(entry) => {
                if !possible_overwrite && entry.coin.is_some() {
                    return Err(CoinsError::OverwriteUnspent);
                }
                // An existing entry keeps its FRESH flag, as in Core. A FRESH
                // entry is always unspent, so the check above covers it.
                entry.coin = Some(coin);
            }
            None => {
                self.entries.insert(
                    outpoint,
                    Entry {
                        coin: Some(coin),
                        fresh: !possible_overwrite,
                    },
                );
            }
        }
        Ok(())
    }

    /// Spends an outpoint and returns the coin that was spent. Returns `None`
    /// if no unspent coin exists in the overlay or the base.
    pub fn spend_coin(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        match self.entries.get_mut(outpoint) {
            Some(entry) => {
                let fresh = entry.fresh;
                let coin = entry.coin.take()?;
                if fresh {
                    // Created and spent without reaching the base: nothing to record.
                    self.entries.remove(outpoint);
                }
                Some(coin)
            }
            None => {
                let coin = self.base.get_coin(outpoint)?;
                // Record the spend as a non-fresh tombstone so the flush deletes it from the base.
                self.entries.insert(
                    *outpoint,
                    Entry {
                        coin: None,
                        fresh: false,
                    },
                );
                Some(coin)
            }
        }
    }

    /// True if an unspent coin exists in the overlay or the base.
    pub fn have_coin(&self, outpoint: &OutPoint) -> bool {
        match self.entries.get(outpoint) {
            Some(entry) => entry.coin.is_some(),
            None => self.base.get_coin(outpoint).is_some(),
        }
    }

    /// Writes all overlay changes into the base and clears the overlay.
    pub fn flush(&mut self) {
        let changes: Vec<(OutPoint, Option<Coin>)> = self
            .entries
            .drain()
            .map(|(outpoint, entry)| (outpoint, entry.coin))
            .collect();
        self.base.batch_write(changes);
    }

    /// `Flush` that also moves the base's best block to `best`, atomically.
    pub fn flush_with_best(&mut self, best: BlockHash) {
        let changes: Vec<(OutPoint, Option<Coin>)> = self
            .entries
            .drain()
            .map(|(outpoint, entry)| (outpoint, entry.coin))
            .collect();
        self.base.batch_write_best(changes, best);
    }
}

impl CoinsView for CoinsViewCache<'_> {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        match self.entries.get(outpoint) {
            Some(entry) => entry.coin.clone(),
            None => self.base.get_coin(outpoint),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{ScriptBuf, Txid};
    use bitcoin_hashes::Hash;

    fn op(vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::all_zeros(),
            vout,
        }
    }

    fn coin(value: i64, height: u32) -> Coin {
        Coin {
            txout: TxOut::new(value, ScriptBuf::from_bytes(vec![0x51])),
            height,
            is_coinbase: false,
        }
    }

    #[test]
    fn add_spend_and_flush_update_base() {
        let mut base = CoinsViewMemory::new();
        base.insert(op(0), coin(50, 1));
        {
            let mut cache = CoinsViewCache::new(&mut base);
            assert!(cache.have_coin(&op(0)));
            assert_eq!(cache.get_coin(&op(0)), Some(coin(50, 1)));

            cache.add_coin(op(1), coin(10, 2), false).unwrap();
            assert!(cache.have_coin(&op(1)));

            assert_eq!(cache.spend_coin(&op(0)), Some(coin(50, 1)));
            assert!(!cache.have_coin(&op(0)));
            assert_eq!(cache.get_coin(&op(0)), None);
            // Double spend finds nothing.
            assert_eq!(cache.spend_coin(&op(0)), None);

            cache.flush();
            assert!(cache.entries.is_empty());
        }
        assert_eq!(base.len(), 1);
        assert_eq!(base.get_coin(&op(0)), None);
        assert_eq!(base.get_coin(&op(1)), Some(coin(10, 2)));
    }

    #[test]
    fn fresh_coin_spent_before_flush_leaves_no_trace() {
        let mut base = CoinsViewMemory::new();
        {
            let mut cache = CoinsViewCache::new(&mut base);
            cache.add_coin(op(5), coin(7, 3), false).unwrap();
            assert_eq!(cache.spend_coin(&op(5)), Some(coin(7, 3)));
            // A FRESH coin that is spent is removed from the overlay entirely.
            assert!(cache.entries.is_empty());
            cache.flush();
        }
        assert!(base.is_empty());
    }

    #[test]
    fn add_coin_rules_for_unspendable_and_overwrite() {
        let mut base = CoinsViewMemory::new();
        let mut cache = CoinsViewCache::new(&mut base);

        // Plain OP_RETURN outputs are skipped and never become visible
        // (except CT scripts `OP_RETURN 0x01 ...` and pool scripts
        // `OP_RETURN 0x02 ...`, which are spendable).
        let op_return = Coin {
            txout: TxOut::new(0, ScriptBuf::from_bytes(vec![0x6a, 0x03, 0x00])),
            height: 1,
            is_coinbase: false,
        };
        cache.add_coin(op(0), op_return, false).unwrap();
        assert!(!cache.have_coin(&op(0)));
        // CT script prefix: spendable ring-signature output.
        assert!(!is_unspendable(&ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00])));
        // Pool note scripts: legacy (PUSHDATA1(32)) and value-committed
        // (PUSHDATA1(65)) forms are spendable by note spends.
        let mut legacy = vec![0x6a, 0x4c, 32];
        legacy.extend_from_slice(&[0u8; 32]);
        assert!(!is_unspendable(&ScriptBuf::from_bytes(legacy)));
        let mut committed = vec![0x6a, 0x4c, 65];
        committed.extend_from_slice(&[0u8; 65]);
        assert!(!is_unspendable(&ScriptBuf::from_bytes(committed)));
        assert!(is_unspendable(&ScriptBuf::from_bytes(vec![0x6a, 0x02, 0x00])));

        // Oversized scripts are unspendable; a script of exactly MAX_SCRIPT_SIZE is not.
        assert!(is_unspendable(&ScriptBuf::from_bytes(vec![0x51; MAX_SCRIPT_SIZE + 1])));
        assert!(!is_unspendable(&ScriptBuf::from_bytes(vec![0x51; MAX_SCRIPT_SIZE])));
        assert!(!is_unspendable(&ScriptBuf::new()));

        // Overwriting an unspent coin without permission is an error.
        cache.add_coin(op(1), coin(1, 1), false).unwrap();
        assert_eq!(
            cache.add_coin(op(1), coin(2, 2), false),
            Err(CoinsError::OverwriteUnspent)
        );
        assert_eq!(cache.get_coin(&op(1)), Some(coin(1, 1)));

        // With permission it replaces the coin.
        cache.add_coin(op(1), coin(2, 2), true).unwrap();
        assert_eq!(cache.get_coin(&op(1)), Some(coin(2, 2)));
    }

    #[test]
    fn respend_then_readd_overwrites_base_coin_on_flush() {
        let mut base = CoinsViewMemory::new();
        base.insert(op(0), coin(50, 1));
        {
            let mut cache = CoinsViewCache::new(&mut base);
            assert_eq!(cache.spend_coin(&op(0)), Some(coin(50, 1)));
            // The overlay holds a non-fresh spend, so re-adding is allowed
            // without overwrite permission (Core's re-org path).
            cache.add_coin(op(0), coin(60, 5), false).unwrap();
            assert_eq!(cache.get_coin(&op(0)), Some(coin(60, 5)));
            cache.flush();
        }
        assert_eq!(base.get_coin(&op(0)), Some(coin(60, 5)));
    }
}
