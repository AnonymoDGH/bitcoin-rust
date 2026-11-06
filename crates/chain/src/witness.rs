//! SegWit block commitments. Port of `GetWitnessCommitmentIndex`,
//! `BlockWitnessMerkleRoot`, `GenerateCoinbaseCommitment`,
//! `CheckWitnessMalleation` (validation.cpp, consensus/merkle.cpp).

use btc_primitives::Block;

use crate::ValidationError;

/// `MINIMUM_WITNESS_COMMITMENT`: OP_RETURN + push36 + 0xaa21a9ed + 32 bytes.
pub const MINIMUM_WITNESS_COMMITMENT: usize = 38;
/// Header `0xaa21a9ed` of the commitment output.
pub const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// `GetWitnessCommitmentIndex`: last matching coinbase output, if any.
pub fn witness_commitment_index(block: &Block) -> Option<usize> {
    todo!()
}

/// `BlockWitnessMerkleRoot`: merkle root of wtxids with the coinbase leaf
/// replaced by zeros. Returns (root, mutated).
pub fn block_witness_merkle_root(block: &Block) -> ([u8; 32], bool) {
    todo!()
}

/// `GenerateCoinbaseCommitment`: if the block has no commitment, set the
/// coinbase witness to a single 32-byte zero reserved value and append the
/// commitment output (value 0). Caller must recompute the merkle root.
pub fn generate_coinbase_commitment(block: &mut Block) {
    todo!()
}

/// `CheckWitnessMalleation(block, expect_witness_commitment)`.
pub fn check_witness_malleation(block: &Block, expect_witness_commitment: bool) -> Result<(), ValidationError> {
    todo!()
}
