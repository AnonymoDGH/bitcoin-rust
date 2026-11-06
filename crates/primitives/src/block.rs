//! Block primitives, ported from Bitcoin Core `primitives/block.h`.
//!
//! Hashing is delegated to `bitcoin_hashes` (SHA256D) and hash types come from
//! `rust-bitcoin`.

use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::io::{self, Read, Write};
use bitcoin::{BlockHash, TxMerkleNode};
use bitcoin_hashes::{sha256d, Hash};

use crate::transaction::{decode_vec, encode_vec, Tx};

/// The 80-byte block header.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: TxMerkleNode,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub fn new(
        version: i32,
        prev_blockhash: BlockHash,
        merkle_root: TxMerkleNode,
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> Self {
        Self {
            version,
            prev_blockhash,
            merkle_root,
            time,
            bits,
            nonce,
        }
    }

    /// Mirrors `CBlockHeader::SetNull()`.
    pub fn set_null(&mut self) {
        *self = Self::null();
    }

    pub fn null() -> Self {
        Self {
            version: 0,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: 0,
            nonce: 0,
        }
    }

    /// Mirrors `CBlockHeader::IsNull()`.
    pub fn is_null(&self) -> bool {
        self.bits == 0
    }

    /// Mirrors `CBlockHeader::GetBlockTime()`.
    pub fn block_time(&self) -> i64 {
        i64::from(self.time)
    }

    /// Block hash: SHA256D of the serialized 80-byte header.
    pub fn block_hash(&self) -> BlockHash {
        let mut buf = Vec::with_capacity(80);
        self.consensus_encode(&mut buf)
            .expect("in-memory writers cannot fail");
        BlockHash::from_byte_array(sha256d::Hash::hash(&buf).to_byte_array())
    }
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self::null()
    }
}

impl Encodable for BlockHeader {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.version.consensus_encode(w)?;
        len += self.prev_blockhash.consensus_encode(w)?;
        len += self.merkle_root.consensus_encode(w)?;
        len += self.time.consensus_encode(w)?;
        len += self.bits.consensus_encode(w)?;
        len += self.nonce.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for BlockHeader {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            version: i32::consensus_decode(r)?,
            prev_blockhash: BlockHash::consensus_decode(r)?,
            merkle_root: TxMerkleNode::consensus_decode(r)?,
            time: u32::consensus_decode(r)?,
            bits: u32::consensus_decode(r)?,
            nonce: u32::consensus_decode(r)?,
        })
    }
}

/// A block: a header plus its transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub txdata: Vec<Tx>,
}

impl Block {
    pub fn new(header: BlockHeader, txdata: Vec<Tx>) -> Self {
        Self { header, txdata }
    }

    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }
}

impl Default for Block {
    fn default() -> Self {
        Self::new(BlockHeader::null(), Vec::new())
    }
}

impl Encodable for Block {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.header.consensus_encode(w)?;
        len += encode_vec(&self.txdata, w)?;
        Ok(len)
    }
}

impl Decodable for Block {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            header: BlockHeader::consensus_decode(r)?,
            txdata: decode_vec(r)?,
        })
    }
}
