//! SegWit block commitments. Port of `GetWitnessCommitmentIndex`,
//! `BlockWitnessMerkleRoot`, `GenerateCoinbaseCommitment`,
//! `CheckWitnessMalleation` (validation.cpp, consensus/merkle.cpp).

use bitcoin::{ScriptBuf, Witness};
use bitcoin_hashes::{sha256d, Hash};
use btc_primitives::{Block, Tx, TxOut};
use btc_validation::block_verify::compute_merkle_root;

use crate::ValidationError;

/// `MINIMUM_WITNESS_COMMITMENT`: OP_RETURN + push36 + 0xaa21a9ed + 32 bytes.
pub const MINIMUM_WITNESS_COMMITMENT: usize = 38;
/// Header `0xaa21a9ed` of the commitment output.
pub const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

const OP_RETURN: u8 = 0x6a;
const COMMITMENT_PUSH: u8 = 0x24;
const RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// `GetWitnessCommitmentIndex`: last matching coinbase output, if any.
pub fn witness_commitment_index(block: &Block) -> Option<usize> {
    let coinbase = block.txdata.first()?;
    coinbase
        .vout
        .iter()
        .rposition(|out| is_witness_commitment(out.script_pubkey.as_bytes()))
}

fn is_witness_commitment(script: &[u8]) -> bool {
    script.len() >= MINIMUM_WITNESS_COMMITMENT
        && script[0] == OP_RETURN
        && script[1] == COMMITMENT_PUSH
        && script[2..6] == WITNESS_COMMITMENT_HEADER
}

/// `CHash256(witness_root || reserved_value)`.
fn commitment_hash(witness_root: &[u8; 32], reserved: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + reserved.len());
    buf.extend_from_slice(witness_root);
    buf.extend_from_slice(reserved);
    sha256d::Hash::hash(&buf).to_byte_array()
}

/// `BlockWitnessMerkleRoot`: merkle root of wtxids with the coinbase leaf
/// replaced by zeros. Returns (root, mutated).
pub fn block_witness_merkle_root(block: &Block) -> ([u8; 32], bool) {
    let leaves = std::iter::once(RESERVED_VALUE)
        .chain(block.txdata.iter().skip(1).map(|tx| tx.wtxid().to_byte_array()))
        .collect();
    compute_merkle_root(leaves)
}

/// `GenerateCoinbaseCommitment`: if the block has no commitment, set the
/// coinbase witness to a single 32-byte zero reserved value and append the
/// commitment output (value 0). Caller must recompute the merkle root.
pub fn generate_coinbase_commitment(block: &mut Block) {
    if witness_commitment_index(block).is_some() {
        return;
    }
    let (root, _) = block_witness_merkle_root(block);
    let commitment = commitment_hash(&root, &RESERVED_VALUE);

    let mut script = Vec::with_capacity(MINIMUM_WITNESS_COMMITMENT);
    script.extend_from_slice(&[OP_RETURN, COMMITMENT_PUSH]);
    script.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
    script.extend_from_slice(&commitment);

    if let Some(coinbase) = block.txdata.first_mut() {
        coinbase
            .vout
            .push(TxOut::new(0, ScriptBuf::from_bytes(script)));
        if let Some(input) = coinbase.vin.first_mut() {
            input.witness = Witness::from_slice(&[RESERVED_VALUE]);
        }
    }
}

/// `CheckWitnessMalleation(block, expect_witness_commitment)`.
pub fn check_witness_malleation(block: &Block, expect_witness_commitment: bool) -> Result<(), ValidationError> {
    if expect_witness_commitment {
        if let Some(pos) = witness_commitment_index(block) {
            let coinbase = &block.txdata[0];
            let reserved = match coinbase.vin.first() {
                Some(input) if input.witness.len() == 1 => input.witness.nth(0),
                _ => None,
            };
            let reserved = reserved
                .filter(|value| value.len() == 32)
                .ok_or(ValidationError::BadWitnessNonceSize)?;

            let (root, _) = block_witness_merkle_root(block);
            let commitment = commitment_hash(&root, reserved);
            let script = coinbase.vout[pos].script_pubkey.as_bytes();
            if script[6..38] != commitment {
                return Err(ValidationError::BadWitnessMerkleMatch);
            }
            return Ok(());
        }
    }

    if block.txdata.iter().any(Tx::has_witness) {
        return Err(ValidationError::UnexpectedWitness);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{BlockHash, OutPoint, Sequence, TxMerkleNode, Txid};
    use btc_primitives::{BlockHeader, TxIn};

    fn header() -> BlockHeader {
        BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: 0x1d00_ffff,
            nonce: 0,
        }
    }

    fn input(prevout: OutPoint, witness: Witness) -> TxIn {
        TxIn {
            prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }
    }

    fn coinbase() -> Tx {
        Tx::new(
            2,
            vec![input(OutPoint::null(), Witness::new())],
            vec![TxOut::new(50_0000_0000, ScriptBuf::from_bytes(vec![0x51]))],
            0,
        )
    }

    fn segwit_tx(tag: u8) -> Tx {
        let witness = Witness::from_slice(&[vec![tag; 71], vec![tag ^ 0x55; 33]]);
        Tx::new(
            2,
            vec![input(OutPoint::new(Txid::from_byte_array([tag; 32]), 0), witness)],
            vec![TxOut::new(1_000 + i64::from(tag), ScriptBuf::from_bytes(vec![0x00, 0x14]))],
            0,
        )
    }

    fn block_with_segwit() -> Block {
        Block::new(header(), vec![coinbase(), segwit_tx(1), segwit_tx(2)])
    }

    fn commitment_script(bytes: &[u8; 32]) -> ScriptBuf {
        let mut script = vec![OP_RETURN, COMMITMENT_PUSH];
        script.extend_from_slice(&WITNESS_COMMITMENT_HEADER);
        script.extend_from_slice(bytes);
        ScriptBuf::from_bytes(script)
    }

    #[test]
    fn generated_commitment_validates() {
        let mut block = block_with_segwit();
        generate_coinbase_commitment(&mut block);
        assert_eq!(witness_commitment_index(&block), Some(1));
        assert_eq!(block.txdata[0].vin[0].witness.len(), 1);
        assert_eq!(block.txdata[0].vin[0].witness.nth(0), Some(&[0u8; 32][..]));
        assert_eq!(check_witness_malleation(&block, true), Ok(()));
    }

    #[test]
    fn generate_is_idempotent() {
        let mut block = block_with_segwit();
        generate_coinbase_commitment(&mut block);
        let before = block.clone();
        generate_coinbase_commitment(&mut block);
        assert_eq!(block, before);
    }

    #[test]
    fn coinbase_only_block_has_zero_witness_root() {
        let mut block = Block::new(header(), vec![coinbase()]);
        assert_eq!(block_witness_merkle_root(&block), ([0u8; 32], false));
        generate_coinbase_commitment(&mut block);
        let expected = commitment_hash(&[0u8; 32], &[0u8; 32]);
        assert_eq!(block.txdata[0].vout[1].script_pubkey.as_bytes()[6..38], expected);
        assert_eq!(check_witness_malleation(&block, true), Ok(()));
    }

    #[test]
    fn tampered_witness_fails_merkle_match() {
        let mut block = block_with_segwit();
        generate_coinbase_commitment(&mut block);
        block.txdata[2].vin[0].witness = Witness::from_slice(&[vec![0xff; 64]]);
        assert_eq!(
            check_witness_malleation(&block, true),
            Err(ValidationError::BadWitnessMerkleMatch)
        );
    }

    #[test]
    fn wrong_reserved_value_size_fails() {
        let mut block = block_with_segwit();
        generate_coinbase_commitment(&mut block);
        block.txdata[0].vin[0].witness = Witness::from_slice(&[vec![0u8; 31]]);
        assert_eq!(
            check_witness_malleation(&block, true),
            Err(ValidationError::BadWitnessNonceSize)
        );
        block.txdata[0].vin[0].witness = Witness::from_slice(&[vec![0u8; 32], vec![0u8; 32]]);
        assert_eq!(
            check_witness_malleation(&block, true),
            Err(ValidationError::BadWitnessNonceSize)
        );
        block.txdata[0].vin[0].witness = Witness::new();
        assert_eq!(
            check_witness_malleation(&block, true),
            Err(ValidationError::BadWitnessNonceSize)
        );
    }

    #[test]
    fn witness_without_commitment_is_unexpected() {
        let block = block_with_segwit();
        assert_eq!(witness_commitment_index(&block), None);
        assert_eq!(
            check_witness_malleation(&block, true),
            Err(ValidationError::UnexpectedWitness)
        );
        assert_eq!(
            check_witness_malleation(&block, false),
            Err(ValidationError::UnexpectedWitness)
        );
    }

    #[test]
    fn commitment_ignored_when_not_expected() {
        let mut block = block_with_segwit();
        generate_coinbase_commitment(&mut block);
        assert_eq!(
            check_witness_malleation(&block, false),
            Err(ValidationError::UnexpectedWitness)
        );
        let plain = Block::new(header(), vec![coinbase()]);
        assert_eq!(check_witness_malleation(&plain, false), Ok(()));
    }

    #[test]
    fn commitment_index_picks_last_match() {
        let mut block = block_with_segwit();
        generate_coinbase_commitment(&mut block);
        let mut bogus = [0u8; 32];
        bogus[0] = 0x42;
        block.txdata[0].vout.insert(0, TxOut::new(0, commitment_script(&bogus)));
        block.txdata[0].vout.push(TxOut::new(0, commitment_script(&bogus)));
        assert_eq!(witness_commitment_index(&block), Some(3));
        assert_eq!(
            check_witness_malleation(&block, true),
            Err(ValidationError::BadWitnessMerkleMatch)
        );
        block.txdata[0].vout.pop();
        assert_eq!(witness_commitment_index(&block), Some(2));
        assert_eq!(check_witness_malleation(&block, true), Ok(()));
    }

    #[test]
    fn short_or_misprefixed_scripts_are_not_commitments() {
        let mut block = Block::new(header(), vec![coinbase()]);
        let mut script = commitment_script(&[0u8; 32]).into_bytes();
        script.truncate(MINIMUM_WITNESS_COMMITMENT - 1);
        block.txdata[0].vout.push(TxOut::new(0, ScriptBuf::from_bytes(script)));
        let mut wrong_header = commitment_script(&[0u8; 32]).into_bytes();
        wrong_header[5] = 0xee;
        block.txdata[0].vout.push(TxOut::new(0, ScriptBuf::from_bytes(wrong_header)));
        assert_eq!(witness_commitment_index(&block), None);
    }
}
