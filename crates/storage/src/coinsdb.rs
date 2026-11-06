//! Persistent UTXO set. An append-only log of batches, replayed on open.
//!
//! Each batch is a run of insert/erase/best-block records ended by a commit
//! record. Records after the last commit (a torn or unfinished batch) are
//! discarded on open. `compact` rewrites the log as a snapshot.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use bitcoin::{OutPoint, Txid};
use bitcoin_hashes::Hash;
use btc_primitives::BlockHash;
use btc_validation::coins::{Coin, CoinsView, CoinsViewWrite};

use crate::coin_ser::{read_coin, write_coin};
use crate::serialize::invalid;
use crate::StorageError;

const LOG_NAME: &str = "coins.log";
const TMP_NAME: &str = "coins.tmp";
const OP_INSERT: u8 = 1;
const OP_ERASE: u8 = 2;
const OP_BEST_BLOCK: u8 = 3;
const OP_COMMIT: u8 = 4;
const OUTPOINT_LEN: usize = 36;

enum Record {
    Insert(OutPoint, Coin),
    Erase(OutPoint),
    BestBlock(BlockHash),
    Commit,
}

pub struct CoinsDb {
    dir: PathBuf,
    coins: HashMap<OutPoint, Coin>,
    best_block: Option<BlockHash>,
    log: File,
    log_len: u64,
}

impl CoinsDb {
    /// Opens the database in `dir`, creating it if needed and replaying the log.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        // A leftover temporary file is an interrupted compaction; the log is still authoritative.
        let _ = fs::remove_file(dir.join(TMP_NAME));

        let path = dir.join(LOG_NAME);
        let mut coins = HashMap::new();
        let mut best_block = None;
        let committed = if path.exists() {
            replay(&path, &mut coins, &mut best_block)?
        } else {
            0
        };

        let log = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        if log.metadata()?.len() != committed {
            log.set_len(committed)?;
            log.sync_all()?;
        }
        Ok(Self {
            dir,
            coins,
            best_block,
            log,
            log_len: committed,
        })
    }

    pub fn best_block(&self) -> Option<BlockHash> {
        self.best_block
    }

    pub fn len(&self) -> usize {
        self.coins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    pub fn set_best_block(&mut self, hash: BlockHash) -> Result<(), StorageError> {
        let mut buf = Vec::with_capacity(OUTPOINT_LEN);
        buf.push(OP_BEST_BLOCK);
        buf.extend_from_slice(&hash.to_byte_array());
        buf.push(OP_COMMIT);
        self.append(&buf)?;
        self.best_block = Some(hash);
        Ok(())
    }

    /// Applies `changes` as one durable batch: `Some` inserts or replaces, `None` erases.
    pub fn try_batch_write(
        &mut self,
        changes: Vec<(OutPoint, Option<Coin>)>,
    ) -> Result<(), StorageError> {
        let mut buf = Vec::new();
        for (outpoint, coin) in &changes {
            match coin {
                Some(coin) => write_insert(&mut buf, outpoint, coin)?,
                None => write_erase(&mut buf, outpoint),
            }
        }
        buf.push(OP_COMMIT);
        self.append(&buf)?;
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
        Ok(())
    }

    /// Rewrites the log as a snapshot of the current state. The new log is
    /// written to a temporary file, synced, and renamed over the old one.
    pub fn compact(&mut self) -> Result<(), StorageError> {
        let mut buf = Vec::new();
        for (outpoint, coin) in &self.coins {
            write_insert(&mut buf, outpoint, coin)?;
        }
        if let Some(hash) = self.best_block {
            buf.push(OP_BEST_BLOCK);
            buf.extend_from_slice(&hash.to_byte_array());
        }
        buf.push(OP_COMMIT);

        let tmp = self.dir.join(TMP_NAME);
        let result = (|| -> Result<File, StorageError> {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(&buf)?;
            file.sync_all()?;
            let handle = OpenOptions::new().append(true).open(&tmp)?;
            fs::rename(&tmp, self.dir.join(LOG_NAME))?;
            Ok(handle)
        })();
        let handle = match result {
            Ok(handle) => handle,
            Err(err) => {
                let _ = fs::remove_file(&tmp);
                return Err(err);
            }
        };
        self.log = handle;
        self.log_len = buf.len() as u64;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        let written = self
            .log
            .write_all(bytes)
            .and_then(|()| self.log.sync_data());
        if let Err(err) = written {
            // Drop any partial batch so later appends do not follow garbage.
            let _ = self.log.set_len(self.log_len);
            return Err(err.into());
        }
        self.log_len += bytes.len() as u64;
        Ok(())
    }
}

impl CoinsView for CoinsDb {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coins.get(outpoint).cloned()
    }
}

impl CoinsViewWrite for CoinsDb {
    fn batch_write(&mut self, changes: Vec<(OutPoint, Option<Coin>)>) {
        self.try_batch_write(changes)
            .unwrap_or_else(|err| panic!("coins database write failed: {err}"));
    }
}

fn write_insert(buf: &mut Vec<u8>, outpoint: &OutPoint, coin: &Coin) -> Result<(), StorageError> {
    buf.push(OP_INSERT);
    write_outpoint(buf, outpoint);
    write_coin(buf, coin)?;
    Ok(())
}

fn write_erase(buf: &mut Vec<u8>, outpoint: &OutPoint) {
    buf.push(OP_ERASE);
    write_outpoint(buf, outpoint);
}

fn write_outpoint(buf: &mut Vec<u8>, outpoint: &OutPoint) {
    buf.extend_from_slice(&outpoint.txid.to_byte_array());
    buf.extend_from_slice(&outpoint.vout.to_le_bytes());
}

fn read_outpoint<R: Read>(r: &mut R) -> io::Result<OutPoint> {
    let mut txid = [0u8; 32];
    r.read_exact(&mut txid)?;
    let mut vout = [0u8; 4];
    r.read_exact(&mut vout)?;
    Ok(OutPoint {
        txid: Txid::from_byte_array(txid),
        vout: u32::from_le_bytes(vout),
    })
}

fn read_record<R: Read>(r: &mut R) -> io::Result<Option<Record>> {
    let mut op = [0u8; 1];
    if r.read(&mut op)? == 0 {
        return Ok(None);
    }
    let record = match op[0] {
        OP_INSERT => {
            let outpoint = read_outpoint(r)?;
            Record::Insert(outpoint, read_coin(r)?)
        }
        OP_ERASE => Record::Erase(read_outpoint(r)?),
        OP_BEST_BLOCK => {
            let mut hash = [0u8; 32];
            r.read_exact(&mut hash)?;
            Record::BestBlock(BlockHash::from_byte_array(hash))
        }
        OP_COMMIT => Record::Commit,
        other => return Err(invalid(&format!("unknown coins log opcode {other:#04x}"))),
    };
    Ok(Some(record))
}

struct CountingReader<R> {
    inner: R,
    pos: u64,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Replays the log into `coins` and `best_block`. Returns the length up to and
/// including the last commit record.
fn replay(
    path: &Path,
    coins: &mut HashMap<OutPoint, Coin>,
    best_block: &mut Option<BlockHash>,
) -> Result<u64, StorageError> {
    let mut reader = CountingReader {
        inner: BufReader::new(File::open(path)?),
        pos: 0,
    };
    let mut pending: Vec<Record> = Vec::new();
    let mut committed = 0u64;
    loop {
        match read_record(&mut reader) {
            Ok(None) => break,
            Ok(Some(Record::Commit)) => {
                for record in pending.drain(..) {
                    match record {
                        Record::Insert(outpoint, coin) => {
                            coins.insert(outpoint, coin);
                        }
                        Record::Erase(outpoint) => {
                            coins.remove(&outpoint);
                        }
                        Record::BestBlock(hash) => *best_block = Some(hash),
                        Record::Commit => {}
                    }
                }
                committed = reader.pos;
            }
            Ok(Some(record)) => pending.push(record),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(committed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    use btc_primitives::TxOut;

    fn op(vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([vout as u8; 32]),
            vout,
        }
    }

    fn coin(value: i64, height: u32) -> Coin {
        Coin {
            txout: TxOut::new(value, ScriptBuf::from_bytes(vec![0x51, 0x14, value as u8])),
            height,
            is_coinbase: height.is_multiple_of(2),
        }
    }

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    #[test]
    fn persists_across_reopen_with_spends() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut db = CoinsDb::open(dir.path()).unwrap();
            assert_eq!(db.best_block(), None);
            db.batch_write(vec![(op(0), Some(coin(10, 1))), (op(1), Some(coin(20, 2)))]);
            db.batch_write(vec![(op(0), None), (op(2), Some(coin(30, 3)))]);
            db.set_best_block(hash(7)).unwrap();
        }
        let db = CoinsDb::open(dir.path()).unwrap();
        assert_eq!(db.best_block(), Some(hash(7)));
        assert_eq!(db.len(), 2);
        assert_eq!(db.get_coin(&op(0)), None);
        assert_eq!(db.get_coin(&op(1)), Some(coin(20, 2)));
        assert_eq!(db.get_coin(&op(2)), Some(coin(30, 3)));
    }

    #[test]
    fn compact_preserves_state_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = CoinsDb::open(dir.path()).unwrap();
        let mut changes = Vec::new();
        for i in 0..50u32 {
            changes.push((op(i), Some(coin(i64::from(i) + 1, i + 1))));
        }
        db.batch_write(changes);
        db.batch_write((0..25u32).map(|i| (op(i), None)).collect());
        db.set_best_block(hash(9)).unwrap();
        let before_len = fs::metadata(dir.path().join(LOG_NAME)).unwrap().len();

        db.compact().unwrap();
        assert!(!dir.path().join(TMP_NAME).exists());
        assert!(fs::metadata(dir.path().join(LOG_NAME)).unwrap().len() < before_len);

        db.batch_write(vec![(op(60), Some(coin(600, 60)))]);
        drop(db);

        let db = CoinsDb::open(dir.path()).unwrap();
        assert_eq!(db.best_block(), Some(hash(9)));
        assert_eq!(db.len(), 26);
        assert_eq!(db.get_coin(&op(0)), None);
        assert_eq!(db.get_coin(&op(49)), Some(coin(50, 50)));
        assert_eq!(db.get_coin(&op(60)), Some(coin(600, 60)));
    }

    #[test]
    fn uncommitted_tail_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut db = CoinsDb::open(dir.path()).unwrap();
            db.batch_write(vec![(op(1), Some(coin(5, 1)))]);
        }
        let log = dir.path().join(LOG_NAME);
        let committed = fs::metadata(&log).unwrap().len();
        let mut tail = Vec::new();
        write_insert(&mut tail, &op(2), &coin(6, 2)).unwrap();
        let mut bytes = fs::read(&log).unwrap();
        bytes.extend_from_slice(&tail);
        fs::write(&log, bytes).unwrap();

        let mut db = CoinsDb::open(dir.path()).unwrap();
        assert_eq!(db.get_coin(&op(2)), None);
        assert_eq!(db.get_coin(&op(1)), Some(coin(5, 1)));
        assert_eq!(fs::metadata(&log).unwrap().len(), committed);

        db.batch_write(vec![(op(3), Some(coin(7, 3)))]);
        drop(db);
        let db = CoinsDb::open(dir.path()).unwrap();
        assert_eq!(db.get_coin(&op(3)), Some(coin(7, 3)));
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn torn_record_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut db = CoinsDb::open(dir.path()).unwrap();
            db.batch_write(vec![(op(1), Some(coin(5, 1)))]);
        }
        let log = dir.path().join(LOG_NAME);
        let committed = fs::metadata(&log).unwrap().len();
        let mut bytes = fs::read(&log).unwrap();
        bytes.extend_from_slice(&[OP_INSERT, 0x01, 0x02]);
        fs::write(&log, bytes).unwrap();

        let db = CoinsDb::open(dir.path()).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(fs::metadata(&log).unwrap().len(), committed);
    }

    #[test]
    fn unknown_opcode_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(LOG_NAME), [0x7f, OP_COMMIT]).unwrap();
        assert!(matches!(
            CoinsDb::open(dir.path()),
            Err(StorageError::Corrupt(_))
        ));
    }
}
