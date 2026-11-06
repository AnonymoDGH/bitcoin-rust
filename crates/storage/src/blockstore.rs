//! Flat block and undo files. Port of the file layer in `node/blockstorage.cpp`.
//!
//! A record is `magic (4) | payload length (u32 LE) | payload`. Undo payloads end
//! with a 32-byte checksum, SHA256D(prev block hash || undo bytes). A position
//! points at the payload, so the header sits 8 bytes before it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bitcoin::consensus;
use bitcoin_hashes::{sha256d, Hash, HashEngine};
use btc_primitives::{Block, BlockHash};
use btc_validation::undo::BlockUndo;

use crate::coin_ser::{decode_block_undo, encode_block_undo};
use crate::StorageError;

/// Core `MAX_BLOCKFILE_SIZE`.
pub const DEFAULT_MAX_BLOCKFILE_SIZE: u64 = 128 * 1024 * 1024;
pub(crate) const RECORD_HEADER_LEN: u64 = 8;
pub(crate) const UNDO_CHECKSUM_LEN: usize = 32;

/// Location of a record payload: file number and byte offset of the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlatFilePos {
    pub file: u32,
    pub pos: u32,
}

/// One numbered file sequence (`blkNNNNN.dat` or `revNNNNN.dat`).
#[derive(Clone, Copy, Debug)]
struct FileSeq {
    prefix: &'static str,
    current: u32,
    size: u64,
}

impl FileSeq {
    fn scan(dir: &Path, prefix: &'static str) -> io::Result<Self> {
        let mut current: Option<u32> = None;
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name();
            if let Some(n) = name.to_str().and_then(|name| parse_file_name(name, prefix)) {
                current = current.max(Some(n));
            }
        }
        let current = current.unwrap_or(0);
        let size = match fs::metadata(file_path(dir, prefix, current)) {
            Ok(meta) => meta.len(),
            Err(err) if err.kind() == io::ErrorKind::NotFound => 0,
            Err(err) => return Err(err),
        };
        Ok(Self {
            prefix,
            current,
            size,
        })
    }
}

fn parse_file_name(name: &str, prefix: &str) -> Option<u32> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(".dat")?;
    if digits.len() >= 5 && digits.bytes().all(|b| b.is_ascii_digit()) {
        digits.parse().ok()
    } else {
        None
    }
}

fn file_path(dir: &Path, prefix: &str, file: u32) -> PathBuf {
    dir.join(format!("{prefix}{file:05}.dat"))
}

/// Double-SHA256 over the previous block hash followed by the serialized undo data.
pub(crate) fn undo_checksum(prev_hash: &BlockHash, undo: &[u8]) -> [u8; UNDO_CHECKSUM_LEN] {
    let mut engine = sha256d::Hash::engine();
    engine.input(&prev_hash.to_byte_array());
    engine.input(undo);
    sha256d::Hash::from_engine(engine).to_byte_array()
}

/// Append-only block and undo files in one directory.
pub struct FlatBlockStore {
    dir: PathBuf,
    magic: [u8; 4],
    max_file_size: u64,
    blocks: FileSeq,
    undo: FileSeq,
}

impl FlatBlockStore {
    /// Opens (creating if needed) the store in `dir`, resuming the newest files.
    pub fn open(dir: impl AsRef<Path>, magic: [u8; 4]) -> Result<Self, StorageError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let blocks = FileSeq::scan(&dir, "blk")?;
        let undo = FileSeq::scan(&dir, "rev")?;
        Ok(Self {
            dir,
            magic,
            max_file_size: DEFAULT_MAX_BLOCKFILE_SIZE,
            blocks,
            undo,
        })
    }

    /// Sets the size past which a new file is started. A record larger than the
    /// limit still goes into an empty file.
    pub fn with_max_file_size(mut self, max_file_size: u64) -> Self {
        self.max_file_size = max_file_size;
        self
    }

    pub fn write_block(&mut self, block: &Block) -> Result<FlatFilePos, StorageError> {
        let payload = consensus::serialize(block);
        append_record(
            &self.dir,
            self.magic,
            self.max_file_size,
            &mut self.blocks,
            &payload,
        )
    }

    pub fn read_block(&self, pos: FlatFilePos) -> Result<Block, StorageError> {
        let payload = self.read_payload("blk", pos)?;
        consensus::deserialize(&payload).map_err(|err| StorageError::Corrupt(err.to_string()))
    }

    /// Writes undo data followed by its checksum, keyed to `prev_hash`.
    pub fn write_undo(
        &mut self,
        undo: &BlockUndo,
        prev_hash: &BlockHash,
    ) -> Result<FlatFilePos, StorageError> {
        let mut payload = encode_block_undo(undo);
        let checksum = undo_checksum(prev_hash, &payload);
        payload.extend_from_slice(&checksum);
        append_record(
            &self.dir,
            self.magic,
            self.max_file_size,
            &mut self.undo,
            &payload,
        )
    }

    pub fn read_undo(
        &self,
        pos: FlatFilePos,
        prev_hash: &BlockHash,
    ) -> Result<BlockUndo, StorageError> {
        let payload = self.read_payload("rev", pos)?;
        if payload.len() < UNDO_CHECKSUM_LEN {
            return Err(StorageError::Corrupt(
                "undo record shorter than its checksum".into(),
            ));
        }
        let (data, stored) = payload.split_at(payload.len() - UNDO_CHECKSUM_LEN);
        if undo_checksum(prev_hash, data) != *stored {
            return Err(StorageError::Checksum);
        }
        Ok(decode_block_undo(data)?)
    }

    /// Flushes every block and undo file to stable storage.
    pub fn sync(&self) -> Result<(), StorageError> {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if parse_file_name(&name, "blk").is_some() || parse_file_name(&name, "rev").is_some() {
                File::open(entry.path())?.sync_data()?;
            }
        }
        Ok(())
    }

    fn read_payload(&self, prefix: &str, pos: FlatFilePos) -> Result<Vec<u8>, StorageError> {
        let mut file = File::open(file_path(&self.dir, prefix, pos.file))?;
        let file_len = file.metadata()?.len();
        let payload_pos = u64::from(pos.pos);
        if payload_pos < RECORD_HEADER_LEN || payload_pos > file_len {
            return Err(StorageError::Corrupt(
                "record position outside its file".into(),
            ));
        }
        file.seek(SeekFrom::Start(payload_pos - RECORD_HEADER_LEN))?;
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        if header[..4] != self.magic {
            return Err(StorageError::Corrupt(
                "record magic does not match network".into(),
            ));
        }
        let size = u64::from(u32::from_le_bytes([
            header[4], header[5], header[6], header[7],
        ]));
        if payload_pos + size > file_len {
            return Err(StorageError::Corrupt(
                "record extends past end of file".into(),
            ));
        }
        let mut payload = vec![0u8; size as usize];
        file.read_exact(&mut payload)?;
        Ok(payload)
    }
}

fn append_record(
    dir: &Path,
    magic: [u8; 4],
    max_file_size: u64,
    seq: &mut FileSeq,
    payload: &[u8],
) -> Result<FlatFilePos, StorageError> {
    let total = RECORD_HEADER_LEN + payload.len() as u64;
    if seq.size > 0 && seq.size + total > max_file_size {
        seq.current += 1;
        seq.size = 0;
    }
    let size = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record exceeds 4 GiB"))?;
    let pos = u32::try_from(seq.size + RECORD_HEADER_LEN)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block file exceeds 4 GiB"))?;

    let mut record = Vec::with_capacity(total as usize);
    record.extend_from_slice(&magic);
    record.extend_from_slice(&size.to_le_bytes());
    record.extend_from_slice(payload);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path(dir, seq.prefix, seq.current))?;
    file.write_all(&record)?;

    let result = FlatFilePos {
        file: seq.current,
        pos,
    };
    seq.size += total;
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::{OutPoint, ScriptBuf, Txid};
    use btc_primitives::{BlockHeader, Tx, TxIn, TxOut};
    use btc_validation::coins::Coin;
    use btc_validation::undo::TxUndo;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

    pub(crate) fn sample_block(seed: u32) -> Block {
        let mut header = BlockHeader::new(
            2,
            BlockHash::all_zeros(),
            bitcoin::TxMerkleNode::all_zeros(),
            1_700_000_000 + seed,
            0x207f_ffff,
            seed,
        );
        header.prev_blockhash = BlockHash::from_byte_array([seed as u8; 32]);
        let input = TxIn::new(OutPoint {
            txid: Txid::from_byte_array([seed as u8; 32]),
            vout: seed,
        });
        let tx = Tx::new(
            2,
            vec![input],
            vec![TxOut::new(
                1_000 + i64::from(seed),
                ScriptBuf::from_bytes(vec![0x51; 30]),
            )],
            0,
        );
        Block::new(header, vec![tx])
    }

    pub(crate) fn sample_undo(seed: u32) -> BlockUndo {
        BlockUndo {
            vtxundo: vec![TxUndo {
                prevout: vec![Coin {
                    txout: TxOut::new(
                        5_000 + i64::from(seed),
                        ScriptBuf::from_bytes(vec![0x76, 0xa9]),
                    ),
                    height: seed + 1,
                    is_coinbase: seed.is_multiple_of(2),
                }],
            }],
        }
    }

    #[test]
    fn block_roundtrip_across_file_rollover() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FlatBlockStore::open(dir.path(), MAGIC)
            .unwrap()
            .with_max_file_size(300);
        let blocks: Vec<Block> = (0..6).map(sample_block).collect();
        let positions: Vec<FlatFilePos> = blocks
            .iter()
            .map(|b| store.write_block(b).unwrap())
            .collect();

        assert!(
            positions.iter().any(|p| p.file > 0),
            "expected rollover to a second file"
        );
        assert!(dir.path().join("blk00001.dat").exists());
        for (block, pos) in blocks.iter().zip(&positions) {
            assert_eq!(&store.read_block(*pos).unwrap(), block);
        }

        drop(store);
        let reopened = FlatBlockStore::open(dir.path(), MAGIC).unwrap();
        for (block, pos) in blocks.iter().zip(&positions) {
            assert_eq!(&reopened.read_block(*pos).unwrap(), block);
        }
    }

    #[test]
    fn oversized_record_still_written_to_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FlatBlockStore::open(dir.path(), MAGIC)
            .unwrap()
            .with_max_file_size(10);
        let first = store.write_block(&sample_block(1)).unwrap();
        let second = store.write_block(&sample_block(2)).unwrap();
        assert_eq!(first.file, 0);
        assert_eq!(second.file, 1);
        assert_eq!(store.read_block(second).unwrap(), sample_block(2));
    }

    #[test]
    fn wrong_magic_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FlatBlockStore::open(dir.path(), MAGIC).unwrap();
        let pos = store.write_block(&sample_block(3)).unwrap();
        let other = FlatBlockStore::open(dir.path(), [0, 0, 0, 0]).unwrap();
        assert!(matches!(
            other.read_block(pos),
            Err(StorageError::Corrupt(_))
        ));
    }

    #[test]
    fn undo_roundtrip_and_checksum_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FlatBlockStore::open(dir.path(), MAGIC).unwrap();
        let prev = BlockHash::from_byte_array([9; 32]);
        let undo = sample_undo(4);
        let pos = store.write_undo(&undo, &prev).unwrap();

        assert_eq!(store.read_undo(pos, &prev).unwrap(), undo);
        let other_prev = BlockHash::from_byte_array([8; 32]);
        assert!(matches!(
            store.read_undo(pos, &other_prev),
            Err(StorageError::Checksum)
        ));
    }

    #[test]
    fn corrupted_undo_checksum_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FlatBlockStore::open(dir.path(), MAGIC).unwrap();
        let prev = BlockHash::from_byte_array([1; 32]);
        let pos = store.write_undo(&sample_undo(6), &prev).unwrap();

        let path = dir.path().join("rev00000.dat");
        let mut bytes = fs::read(&path).unwrap();
        let last_checksum_byte = bytes.len() - 1;
        bytes[last_checksum_byte] ^= 0xff;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            store.read_undo(pos, &prev),
            Err(StorageError::Checksum)
        ));
    }
}
