//! Context-free block checks.
//!
//! Ports, from `src/validation.cpp`, `CheckBlockHeader` (PoW part) and
//! `CheckBlock`, plus `CheckProofOfWork` from `src/pow.cpp` and
//! `ComputeMerkleRoot` / `BlockMerkleRoot` from `src/consensus/merkle.cpp`.
//!
//! Core's "block timestamp too far in the future" rule (`time-too-new`) is in
//! `ContextualCheckBlockHeader`, not in `CheckBlockHeader`. It is exposed here
//! as [`check_block_header_time`], which takes the clock as an argument so the
//! check stays pure.

use bitcoin::consensus::serialize;
use bitcoin::{BlockHash, TxMerkleNode};
use bitcoin_hashes::{sha256d, Hash};
use btc_consensus::{decode_compact, ChainParams};
use btc_primitives::{Block, BlockHeader};
use primitive_types::U256;
use thiserror::Error;

/// `MAX_FUTURE_BLOCK_TIME` (chain.h): 2 hours.
pub const MAX_FUTURE_BLOCK_TIME: i64 = 2 * 60 * 60;
/// `MAX_BLOCK_SERIALIZED_SIZE` (consensus/consensus.h).
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 4_000_000;
/// `MAX_BLOCK_WEIGHT` (consensus/consensus.h).
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;
/// `WITNESS_SCALE_FACTOR` (consensus/consensus.h).
const WITNESS_SCALE_FACTOR: usize = 4;

/// Reasons a block or header fails a context-free check.
///
/// Each variant maps to a Core reject reason via [`BlockError::reject_reason`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BlockError {
    /// Bad compact target, target above `powLimit`, or hash above target.
    /// Core reports every proof-of-work failure as `high-hash`.
    #[error("proof of work failed")]
    HighHash,
    /// Header timestamp is more than [`MAX_FUTURE_BLOCK_TIME`] ahead of now.
    #[error("block timestamp too far in the future")]
    TimeTooNew,
    /// Header `hashMerkleRoot` does not match the transactions.
    #[error("hashMerkleRoot mismatch")]
    BadMerkleRoot,
    /// Two identical adjacent hashes were paired in the merkle tree
    /// (CVE-2012-2459). The block has the same root as a shorter one.
    #[error("duplicate transaction in merkle tree (CVE-2012-2459)")]
    DuplicateTx,
    /// No transactions, too many transactions or too large a block.
    #[error("block size limits failed")]
    BadBlockLength,
    /// Total serialized weight exceeds `MAX_BLOCK_WEIGHT`.
    #[error("block weight limit failed")]
    BadBlockWeight,
    /// The first transaction is not a coinbase.
    #[error("first transaction is not coinbase")]
    MissingCoinbase,
    /// A transaction after the first is a coinbase.
    #[error("more than one coinbase")]
    MultipleCoinbase,
}

impl BlockError {
    /// The Core reject reason string for this failure.
    pub fn reject_reason(&self) -> &'static str {
        match self {
            BlockError::HighHash => "high-hash",
            BlockError::TimeTooNew => "time-too-new",
            BlockError::BadMerkleRoot => "bad-txnmrklroot",
            BlockError::DuplicateTx => "bad-txns-duplicate",
            BlockError::BadBlockLength => "bad-blk-length",
            BlockError::BadBlockWeight => "bad-blk-weight",
            BlockError::MissingCoinbase => "bad-cb-missing",
            BlockError::MultipleCoinbase => "bad-cb-multiple",
        }
    }
}

/// `CheckProofOfWork()` / `DeriveTarget()`.
///
/// The compact target must be positive, not overflow, and not exceed the
/// chain's `powLimit`. The hash must be less than or equal to the target.
pub fn check_proof_of_work(
    hash: &BlockHash,
    bits: u32,
    params: &ChainParams,
) -> Result<(), BlockError> {
    // decode_compact() already rejects negative, overflowing and zero targets.
    let target = decode_compact(bits).map_err(|_| BlockError::HighHash)?;
    if target > params.pow_limit {
        return Err(BlockError::HighHash);
    }

    // Core stores uint256 little-endian. BlockHash::to_byte_array() returns the
    // same internal byte order, so the hash is read little-endian.
    let hash_value = U256::from_little_endian(&hash.to_byte_array());
    if hash_value > target {
        return Err(BlockError::HighHash);
    }
    Ok(())
}

/// The proof-of-work part of `CheckBlockHeader()`.
pub fn check_block_header(header: &BlockHeader, params: &ChainParams) -> Result<(), BlockError> {
    check_proof_of_work(&header.block_hash(), header.bits, params)
}

/// The future-timestamp rule from `ContextualCheckBlockHeader()`.
///
/// `now` is the adjusted network time in seconds since the epoch. The header
/// is rejected if its time is strictly more than [`MAX_FUTURE_BLOCK_TIME`]
/// ahead of `now`.
pub fn check_block_header_time(header: &BlockHeader, now: i64) -> Result<(), BlockError> {
    if header.block_time() > now + MAX_FUTURE_BLOCK_TIME {
        return Err(BlockError::TimeTooNew);
    }
    Ok(())
}

/// Double SHA-256 of two concatenated 32-byte hashes (`SHA256D64`).
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256d::Hash::hash(&buf).to_byte_array()
}

/// `ComputeMerkleRoot()`: returns the root and whether a mutation was seen.
///
/// `mutated` is set when two identical hashes are paired at any level before
/// the odd-count duplication step (CVE-2012-2459). An empty list yields an
/// all-zero root.
pub fn compute_merkle_root(mut hashes: Vec<[u8; 32]>) -> ([u8; 32], bool) {
    let mut mutated = false;
    while hashes.len() > 1 {
        // Only complete pairs are compared. An unpaired last element is not
        // compared with itself, matching Core's `pos + 1 < size` loop.
        for pair in hashes.chunks_exact(2) {
            if pair[0] == pair[1] {
                mutated = true;
            }
        }
        if hashes.len() % 2 == 1 {
            let last = hashes[hashes.len() - 1];
            hashes.push(last);
        }
        hashes = hashes
            .chunks_exact(2)
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
    }
    (hashes.first().copied().unwrap_or([0u8; 32]), mutated)
}

/// `BlockMerkleRoot()`: merkle root over the txids of a block's transactions.
pub fn block_merkle_root(block: &Block) -> (TxMerkleNode, bool) {
    let leaves = block
        .txdata
        .iter()
        .map(|tx| tx.txid().to_byte_array())
        .collect();
    let (root, mutated) = compute_merkle_root(leaves);
    (TxMerkleNode::from_byte_array(root), mutated)
}

/// Bytes in the Bitcoin CompactSize encoding of `n`.
fn compact_size_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// `GetSerializeSize(TX_NO_WITNESS(block))`: block size without witness data.
fn stripped_block_size(block: &Block) -> usize {
    let mut len = serialize(&block.header).len() + compact_size_len(block.txdata.len());
    for tx in &block.txdata {
        let mut buf = Vec::new();
        tx.encode_with(&mut buf, false)
            .expect("in-memory writers cannot fail");
        len += buf.len();
    }
    len
}

/// `CheckBlock()`: context-free block checks.
///
/// Checks run in Core's order: proof of work (if `check_pow`), merkle root and
/// mutation (if `check_merkle_root`), size limits, then coinbase placement.
/// Transaction-level checks are not performed here.
///
/// The weight check is run here, but Core runs it in `ContextualCheckBlock`.
/// A block that fails both the size and weight limits may therefore report a
/// different reason than Core would.
pub fn check_block(
    block: &Block,
    params: &ChainParams,
    check_pow: bool,
    check_merkle_root: bool,
) -> Result<(), BlockError> {
    if check_pow {
        check_block_header(&block.header, params)?;
    }

    if check_merkle_root {
        let (root, mutated) = block_merkle_root(block);
        if root != block.header.merkle_root {
            return Err(BlockError::BadMerkleRoot);
        }
        if mutated {
            return Err(BlockError::DuplicateTx);
        }
    }

    let stripped = stripped_block_size(block);
    let total = serialize(block).len();
    // GetBlockWeight(): non-witness bytes count 4x, witness bytes count 1x.
    let weight = stripped * (WITNESS_SCALE_FACTOR - 1) + total;

    if block.txdata.is_empty()
        || block.txdata.len() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        || stripped * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
    {
        return Err(BlockError::BadBlockLength);
    }
    if total > MAX_BLOCK_SERIALIZED_SIZE {
        return Err(BlockError::BadBlockLength);
    }
    if weight > MAX_BLOCK_WEIGHT {
        return Err(BlockError::BadBlockWeight);
    }

    match block.txdata.first() {
        Some(first) if first.is_coin_base() => {}
        _ => return Err(BlockError::MissingCoinbase),
    }
    if block.txdata.iter().skip(1).any(|tx| tx.is_coin_base()) {
        return Err(BlockError::MultipleCoinbase);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, ScriptBuf, Txid};
    use bitcoin_hashes::Hash;
    use btc_primitives::{Tx, TxIn, TxOut};

    /// The mainnet genesis header with the given `nBits`.
    fn genesis_header(bits: u32) -> BlockHeader {
        BlockHeader::new(
            1,
            BlockHash::all_zeros(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                .parse::<TxMerkleNode>()
                .unwrap(),
            1_231_006_505,
            bits,
            2_083_236_893,
        )
    }

    #[test]
    fn genesis_header_proof_of_work() {
        let mainnet = ChainParams::mainnet();

        // Genesis hash 000000000019d6... is below the 0x1d00ffff target.
        assert_eq!(
            check_block_header(&genesis_header(0x1d00_ffff), &mainnet),
            Ok(())
        );

        // 0x1a00ffff is a much smaller target; the genesis hash is above it.
        assert_eq!(
            check_block_header(&genesis_header(0x1a00_ffff), &mainnet),
            Err(BlockError::HighHash)
        );

        // Targets above powLimit fail even though the hash is below them.
        assert_eq!(
            check_block_header(&genesis_header(0x1f00_ffff), &mainnet),
            Err(BlockError::HighHash)
        );
        // Negative and zero targets.
        assert_eq!(
            check_block_header(&genesis_header(0x1d80_ffff), &mainnet),
            Err(BlockError::HighHash)
        );
        assert_eq!(
            check_block_header(&genesis_header(0x1d00_0000), &mainnet),
            Err(BlockError::HighHash)
        );

        // Regtest genesis (own time and nonce) passes the regtest limit.
        let regtest = ChainParams::regtest();
        let regtest_genesis = BlockHeader::new(
            1,
            BlockHash::all_zeros(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                .parse::<TxMerkleNode>()
                .unwrap(),
            1_296_688_602,
            0x207f_ffff,
            2,
        );
        assert_eq!(check_block_header(&regtest_genesis, &regtest), Ok(()));
    }

    #[test]
    fn future_timestamp_boundary() {
        let header = genesis_header(0x1d00_ffff);
        let t = header.block_time();

        // Exactly MAX_FUTURE_BLOCK_TIME ahead is still accepted.
        assert_eq!(check_block_header_time(&header, t - MAX_FUTURE_BLOCK_TIME), Ok(()));
        assert_eq!(
            check_block_header_time(&header, t - MAX_FUTURE_BLOCK_TIME - 1),
            Err(BlockError::TimeTooNew)
        );
    }

    #[test]
    fn merkle_root_detects_cve_2012_2459() {
        let leaf = |i: u8| [i; 32];

        let six: Vec<_> = (1..=6).map(leaf).collect();
        let (root, mutated) = compute_merkle_root(six.clone());
        assert!(!mutated);

        // [1..6] and [1..6, 5, 6] share a root, but the second has a repeated
        // pair at the leaf level and must be flagged as mutated.
        let mut duplicated = six;
        duplicated.extend([leaf(5), leaf(6)]);
        let (dup_root, dup_mutated) = compute_merkle_root(duplicated);
        assert_eq!(root, dup_root);
        assert!(dup_mutated);

        // A single leaf is its own root. An empty list has the zero root.
        assert_eq!(compute_merkle_root(vec![leaf(7)]), (leaf(7), false));
        assert_eq!(compute_merkle_root(vec![]), ([0u8; 32], false));
    }

    #[test]
    fn check_block_structure() {
        let mainnet = ChainParams::mainnet();

        let coinbase = |tag: u8| {
            let mut input = TxIn::default();
            input.script_sig = ScriptBuf::from_bytes(vec![tag]);
            Tx::new(
                Tx::CURRENT_VERSION,
                vec![input],
                vec![TxOut::new(50 * 100_000_000, ScriptBuf::new())],
                0,
            )
        };
        let spend = |vout: u32| {
            Tx::new(
                2,
                vec![TxIn::new(OutPoint {
                    txid: Txid::all_zeros(),
                    vout,
                })],
                vec![TxOut::new(1_000, ScriptBuf::new())],
                0,
            )
        };
        // Build a block whose header commits to the given transactions.
        let block = |txdata: Vec<Tx>| {
            let mut block = Block::new(
                BlockHeader::new(
                    1,
                    BlockHash::all_zeros(),
                    TxMerkleNode::all_zeros(),
                    1_231_006_505,
                    0x207f_ffff,
                    0,
                ),
                txdata,
            );
            block.header.merkle_root = block_merkle_root(&block).0;
            block
        };
        // Structural checks only: PoW is skipped, merkle root is checked.
        let check = |b: &Block| check_block(b, &mainnet, false, true);

        assert_eq!(check(&block(vec![coinbase(1), spend(0)])), Ok(()));

        // Header root that does not match the transactions.
        let mut bad_root = block(vec![coinbase(1), spend(0)]);
        bad_root.header.merkle_root = TxMerkleNode::all_zeros();
        assert_eq!(check(&bad_root), Err(BlockError::BadMerkleRoot));

        // The last two leaves are equal, so the tree is flagged as mutated even
        // though the header root was computed from these exact transactions.
        assert_eq!(
            check(&block(vec![coinbase(1), spend(0), spend(1), spend(1)])),
            Err(BlockError::DuplicateTx)
        );

        assert_eq!(
            check(&block(vec![coinbase(1), coinbase(2)])),
            Err(BlockError::MultipleCoinbase)
        );
        assert_eq!(
            check(&block(vec![spend(0)])),
            Err(BlockError::MissingCoinbase)
        );
        assert_eq!(check(&block(vec![])), Err(BlockError::BadBlockLength));
    }
}
