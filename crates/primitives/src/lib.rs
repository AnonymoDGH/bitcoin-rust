//! `btc-primitives`: minimal Rust port of Bitcoin Core transaction and block
//! primitives.
//!
//! The data model mirrors `primitives/transaction.h` and `primitives/block.h`.
//! Hashing (SHA256D) and consensus encoding are delegated to `bitcoin_hashes`
//! and `rust-bitcoin` instead of being reimplemented.

pub mod block;
pub mod transaction;

pub use block::{Block, BlockHeader};
pub use transaction::{Tx, TxIn, TxOut, NULL_VALUE};

/// Re-exported hash/script types used by the primitives.
pub use bitcoin::{BlockHash, OutPoint, ScriptBuf, Sequence, Txid, Wtxid, Witness};

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::TxMerkleNode;
    use bitcoin_hashes::Hash;

    fn dummy_txout(value: i64) -> TxOut {
        TxOut::new(value, ScriptBuf::new())
    }

    #[test]
    fn genesis_header_hash_matches_mainnet() {
        let header = BlockHeader::new(
            1,
            BlockHash::all_zeros(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                .parse::<TxMerkleNode>()
                .unwrap(),
            1_231_006_505,
            0x1d00_ffff,
            2_083_236_893,
        );

        assert!(!header.is_null());
        assert_eq!(
            header.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(serialize(&header).len(), 80);

        let decoded: BlockHeader = deserialize(&serialize(&header)).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn coinbase_transaction_roundtrips_without_witness() {
        let mut coinbase_in = TxIn::default();
        coinbase_in.script_sig = ScriptBuf::from_bytes(vec![0x01, 0x02, 0x03]);
        let tx = Tx::new(
            Tx::CURRENT_VERSION,
            vec![coinbase_in],
            vec![dummy_txout(50_0000_0000)],
            0,
        );

        assert!(tx.is_coin_base());
        assert!(!tx.has_witness());
        assert_eq!(tx.txid().to_byte_array(), tx.wtxid().to_byte_array());
        assert_eq!(tx.value_out(), 50_0000_0000);

        let decoded: Tx = deserialize(&serialize(&tx)).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(decoded.txid(), tx.txid());
    }

    #[test]
    fn segwit_transaction_has_distinct_wtxid() {
        let mut input = TxIn::new(OutPoint {
            txid: Txid::all_zeros(),
            vout: 1,
        });
        input.sequence = Sequence(Sequence::ENABLE_RBF_NO_LOCKTIME.0);
        input.witness.push([0xab; 72]);

        let tx = Tx::new(
            2,
            vec![input],
            vec![dummy_txout(1_000)],
            0,
        );

        assert!(tx.has_witness());
        assert_ne!(tx.txid().to_byte_array(), tx.wtxid().to_byte_array());
        assert!(tx.total_size() > 0);

        let decoded: Tx = deserialize(&serialize(&tx)).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(decoded.wtxid(), tx.wtxid());

        let block = Block::new(BlockHeader::null(), vec![tx]);
        let decoded_block: Block = deserialize(&serialize(&block)).unwrap();
        assert_eq!(decoded_block, block);
    }
}
