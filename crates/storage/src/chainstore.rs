//! Disk-backed `BlockStore`: flat block files plus an append-only hash index.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use bitcoin_hashes::Hash;
use btc_chain::chainstate::BlockStore;
use btc_primitives::{Block, BlockHash};
use btc_validation::undo::BlockUndo;

use crate::blockstore::{FlatBlockStore, FlatFilePos, DEFAULT_MAX_BLOCKFILE_SIZE};
use crate::StorageError;

const INDEX_NAME: &str = "index.dat";
/// hash | prev hash | block file | block pos | undo file | undo pos (0 = no undo)
const INDEX_RECORD_LEN: usize = 32 + 32 + 4 * 4;

#[derive(Clone, Copy, Debug)]
struct IndexEntry {
    prev: BlockHash,
    block: FlatFilePos,
    undo: Option<FlatFilePos>,
}

/// Block and undo storage keyed by block hash. Each put appends a full index
/// record, and the index is replayed on open with later records winning.
///
/// The `BlockStore` trait returns no errors, so a failed write panics (as Core
/// aborts on a failed disk write) and a failed read returns `None`. The
/// `try_*` methods expose the errors.
pub struct DiskBlockStore {
    files: FlatBlockStore,
    index: File,
    entries: HashMap<BlockHash, IndexEntry>,
}

impl DiskBlockStore {
    pub fn open(dir: impl AsRef<Path>, magic: [u8; 4]) -> Result<Self, StorageError> {
        Self::open_with_max_file_size(dir, magic, DEFAULT_MAX_BLOCKFILE_SIZE)
    }

    pub fn open_with_max_file_size(
        dir: impl AsRef<Path>,
        magic: [u8; 4],
        max_file_size: u64,
    ) -> Result<Self, StorageError> {
        let dir = dir.as_ref();
        let files = FlatBlockStore::open(dir, magic)?.with_max_file_size(max_file_size);
        let mut index = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(dir.join(INDEX_NAME))?;
        let entries = replay_index(&mut index)?;
        Ok(Self {
            files,
            index,
            entries,
        })
    }

    pub fn try_put_block(&mut self, hash: &BlockHash, block: &Block) -> Result<(), StorageError> {
        if self.entries.contains_key(hash) {
            return Ok(());
        }
        let block_pos = self.files.write_block(block)?;
        let entry = IndexEntry {
            prev: block.header.prev_blockhash,
            block: block_pos,
            undo: None,
        };
        self.append_index(hash, &entry)?;
        self.entries.insert(*hash, entry);
        Ok(())
    }

    /// Stores undo data for a block whose block data is already stored.
    pub fn try_put_undo(&mut self, hash: &BlockHash, undo: &BlockUndo) -> Result<(), StorageError> {
        let mut entry = *self
            .entries
            .get(hash)
            .ok_or_else(|| StorageError::Corrupt("undo written for an unknown block".into()))?;
        let undo_pos = self.files.write_undo(undo, &entry.prev)?;
        entry.undo = Some(undo_pos);
        self.append_index(hash, &entry)?;
        self.entries.insert(*hash, entry);
        Ok(())
    }

    pub fn try_get_block(&self, hash: &BlockHash) -> Result<Option<Block>, StorageError> {
        let Some(entry) = self.entries.get(hash) else {
            return Ok(None);
        };
        let block = self.files.read_block(entry.block)?;
        if block.block_hash() != *hash {
            return Err(StorageError::Corrupt(
                "block at indexed position has a different hash".into(),
            ));
        }
        Ok(Some(block))
    }

    pub fn try_get_undo(&self, hash: &BlockHash) -> Result<Option<BlockUndo>, StorageError> {
        let Some(entry) = self.entries.get(hash) else {
            return Ok(None);
        };
        match entry.undo {
            Some(pos) => self.files.read_undo(pos, &entry.prev).map(Some),
            None => Ok(None),
        }
    }

    /// Flushes block files and the index to stable storage.
    pub fn sync(&self) -> Result<(), StorageError> {
        self.index.sync_data()?;
        self.files.sync()
    }

    fn append_index(&mut self, hash: &BlockHash, entry: &IndexEntry) -> Result<(), StorageError> {
        let mut record = Vec::with_capacity(INDEX_RECORD_LEN);
        record.extend_from_slice(&hash.to_byte_array());
        record.extend_from_slice(&entry.prev.to_byte_array());
        record.extend_from_slice(&entry.block.file.to_le_bytes());
        record.extend_from_slice(&entry.block.pos.to_le_bytes());
        let undo = entry.undo.unwrap_or(FlatFilePos { file: 0, pos: 0 });
        record.extend_from_slice(&undo.file.to_le_bytes());
        record.extend_from_slice(&undo.pos.to_le_bytes());
        self.index.write_all(&record)?;
        Ok(())
    }
}

impl BlockStore for DiskBlockStore {
    fn put_block(&mut self, hash: &BlockHash, block: &Block) {
        self.try_put_block(hash, block)
            .unwrap_or_else(|err| panic!("block store write failed: {err}"));
    }

    fn get_block(&self, hash: &BlockHash) -> Option<Block> {
        self.try_get_block(hash).ok().flatten()
    }

    fn put_undo(&mut self, hash: &BlockHash, undo: &BlockUndo) {
        self.try_put_undo(hash, undo)
            .unwrap_or_else(|err| panic!("undo store write failed: {err}"));
    }

    fn get_undo(&self, hash: &BlockHash) -> Option<BlockUndo> {
        self.try_get_undo(hash).ok().flatten()
    }
}

/// Rebuilds the index from disk. A trailing partial record (torn write) is cut off.
fn replay_index(index: &mut File) -> Result<HashMap<BlockHash, IndexEntry>, StorageError> {
    let len = index.metadata()?.len();
    let usable = len - len % INDEX_RECORD_LEN as u64;
    if usable != len {
        index.set_len(usable)?;
    }
    index.seek(SeekFrom::Start(0))?;

    let mut entries = HashMap::new();
    let mut reader = BufReader::new(&mut *index);
    let mut record = [0u8; INDEX_RECORD_LEN];
    for _ in 0..usable / INDEX_RECORD_LEN as u64 {
        reader.read_exact(&mut record)?;
        let (hash, entry) = parse_index_record(&record);
        entries.insert(hash, entry);
    }
    Ok(entries)
}

fn parse_index_record(record: &[u8; INDEX_RECORD_LEN]) -> (BlockHash, IndexEntry) {
    let word = |at: usize| {
        u32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
    };
    let hash = BlockHash::from_byte_array(record[0..32].try_into().expect("32 bytes"));
    let prev = BlockHash::from_byte_array(record[32..64].try_into().expect("32 bytes"));
    let block = FlatFilePos {
        file: word(64),
        pos: word(68),
    };
    let undo_pos = word(76);
    let undo = (undo_pos != 0).then(|| FlatFilePos {
        file: word(72),
        pos: undo_pos,
    });
    (hash, IndexEntry { prev, block, undo })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::tests::{sample_block, sample_undo};

    const MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

    fn assert_send<T: Send>() {}

    #[test]
    fn disk_block_store_is_send() {
        assert_send::<DiskBlockStore>();
    }

    #[test]
    fn blocks_and_undo_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let blocks: Vec<Block> = (0..5).map(sample_block).collect();
        let undos: Vec<BlockUndo> = (0..5).map(sample_undo).collect();
        {
            let mut store =
                DiskBlockStore::open_with_max_file_size(dir.path(), MAGIC, 400).unwrap();
            for (block, undo) in blocks.iter().zip(&undos) {
                store.put_block(&block.block_hash(), block);
                store.put_undo(&block.block_hash(), undo);
            }
            store.put_block(&blocks[0].block_hash(), &blocks[0]);
            store.sync().unwrap();
        }

        let store = DiskBlockStore::open_with_max_file_size(dir.path(), MAGIC, 400).unwrap();
        for (block, undo) in blocks.iter().zip(&undos) {
            let hash = block.block_hash();
            assert_eq!(store.get_block(&hash).as_ref(), Some(block));
            assert_eq!(store.get_undo(&hash).as_ref(), Some(undo));
        }
        assert_eq!(
            store.get_block(&BlockHash::from_byte_array([0xee; 32])),
            None
        );
    }

    #[test]
    fn block_without_undo_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let block = sample_block(7);
        let mut store = DiskBlockStore::open(dir.path(), MAGIC).unwrap();
        store.put_block(&block.block_hash(), &block);
        drop(store);
        let store = DiskBlockStore::open(dir.path(), MAGIC).unwrap();
        assert_eq!(store.get_block(&block.block_hash()), Some(block.clone()));
        assert_eq!(store.get_undo(&block.block_hash()), None);
    }

    #[test]
    fn undo_for_unknown_block_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = DiskBlockStore::open(dir.path(), MAGIC).unwrap();
        let err = store.try_put_undo(&BlockHash::from_byte_array([1; 32]), &sample_undo(0));
        assert!(matches!(err, Err(StorageError::Corrupt(_))));
    }

    #[test]
    fn torn_index_record_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let block = sample_block(2);
        let mut store = DiskBlockStore::open(dir.path(), MAGIC).unwrap();
        store.put_block(&block.block_hash(), &block);
        drop(store);

        let index = dir.path().join(INDEX_NAME);
        let mut bytes = std::fs::read(&index).unwrap();
        bytes.extend_from_slice(&[0xab; 17]);
        std::fs::write(&index, bytes).unwrap();

        let store = DiskBlockStore::open(dir.path(), MAGIC).unwrap();
        assert_eq!(store.get_block(&block.block_hash()), Some(block));
        assert_eq!(
            std::fs::metadata(&index).unwrap().len(),
            INDEX_RECORD_LEN as u64
        );
    }
}
