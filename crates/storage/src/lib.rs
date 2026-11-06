//! On-disk block files and UTXO persistence.

pub mod blockstore;
pub mod chainstore;
pub mod coin_ser;
pub mod coinsdb;
pub mod compressor;
pub mod serialize;

pub use blockstore::{FlatBlockStore, FlatFilePos};
pub use chainstore::DiskBlockStore;
pub use coinsdb::CoinsDb;

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(io::Error),
    #[error("corrupt storage: {0}")]
    Corrupt(String),
    #[error("undo data checksum mismatch")]
    Checksum,
}

impl From<io::Error> for StorageError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                StorageError::Corrupt(err.to_string())
            }
            _ => StorageError::Io(err),
        }
    }
}
