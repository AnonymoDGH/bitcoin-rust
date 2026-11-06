//! Genesis block construction.
//!
//! Ported from `CreateGenesisBlock()` in `kernel/chainparams.cpp`. The
//! coinbase scriptSig is built exactly as Core does it: the push of
//! `486604799` (`0x1d00ffff`) as a script number, the push of `CScriptNum(4)`,
//! then the timestamp string as a data push.

use bitcoin::{OutPoint, ScriptBuf, Txid};
use bitcoin_hashes::{sha256d, Hash};
use btc_primitives::{Block, BlockHeader, Tx, TxIn, TxOut};
use primitive_types::U256;

use crate::compact::decode_compact;
use crate::subsidy::COIN;

/// Timestamp string embedded in the mainnet and testnet genesis coinbase.
pub const BITCOIN_GENESIS_TIMESTAMP: &str =
    "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

/// Hex of the uncompressed public key paid by the mainnet genesis output.
const SATOSHI_PUBKEY_HEX: &str = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";

/// `OP_CHECKSIG`.
const OP_CHECKSIG: u8 = 0xac;

/// Appends a minimal data push of `data` to `out` (`CScript::operator<<(vector)`).
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 0x4b {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x4c);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(len as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Builds a genesis block with the given header fields and a single coinbase
/// paying `reward` to `output_script` (`CreateGenesisBlock()`).
pub fn create_genesis_block(
    timestamp: &str,
    output_script: ScriptBuf,
    time: u32,
    nonce: u32,
    bits: u32,
    version: i32,
    reward: i64,
) -> Block {
    // `CScript() << 486604799 << CScriptNum(4) << timestamp`
    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &486_604_799u32.to_le_bytes());
    push_data(&mut script_sig, &[4]);
    push_data(&mut script_sig, timestamp.as_bytes());

    let mut input = TxIn::new(OutPoint::null());
    input.script_sig = ScriptBuf::from_bytes(script_sig);
    let coinbase = Tx::new(1, vec![input], vec![TxOut::new(reward, output_script)], 0);

    let merkle_root = merkle_root(&[coinbase.txid()]);
    let header = BlockHeader::new(
        version,
        bitcoin::BlockHash::all_zeros(),
        merkle_root,
        time,
        bits,
        nonce,
    );
    Block::new(header, vec![coinbase])
}

/// Mainnet genesis block (`CMainParams`).
pub fn mainnet_genesis_block() -> Block {
    create_genesis_block(
        BITCOIN_GENESIS_TIMESTAMP,
        satoshi_output_script(),
        1_231_006_505,
        2_083_236_893,
        0x1d00_ffff,
        1,
        50 * COIN,
    )
}

/// Testnet3 genesis block (`CTestNetParams`).
pub fn testnet_genesis_block() -> Block {
    create_genesis_block(
        BITCOIN_GENESIS_TIMESTAMP,
        satoshi_output_script(),
        1_296_688_602,
        414_098_458,
        0x1d00_ffff,
        1,
        50 * COIN,
    )
}

/// Regtest genesis block (`CRegTestParams`).
pub fn regtest_genesis_block() -> Block {
    create_genesis_block(
        BITCOIN_GENESIS_TIMESTAMP,
        satoshi_output_script(),
        1_296_688_602,
        2,
        0x207f_ffff,
        1,
        50 * COIN,
    )
}

/// Searches for a nonce (and, when the nonce space is exhausted, a later
/// timestamp) such that the header hash is at most the target encoded in
/// `block.header.bits`. Returns the nonce that was found; the block is updated
/// in place.
///
/// # Panics
///
/// Panics if `bits` does not decode to a valid target, or if that target is
/// above `pow_limit`, since such a genesis would fail `CheckProofOfWork`.
pub fn mine_genesis(block: &mut Block, pow_limit: U256) -> u32 {
    let target = decode_compact(block.header.bits).expect("genesis bits must be a valid target");
    assert!(
        target <= pow_limit,
        "genesis target is above the proof-of-work limit"
    );
    loop {
        for nonce in 0..=u32::MAX {
            block.header.nonce = nonce;
            let hash = block.block_hash().to_byte_array();
            if U256::from_little_endian(&hash) <= target {
                return nonce;
            }
        }
        block.header.time = block.header.time.wrapping_add(1);
    }
}

/// The Satoshi coinbase output script (`genesisOutputScript`).
fn satoshi_output_script() -> ScriptBuf {
    let mut bytes = Vec::new();
    push_data(&mut bytes, &hex_decode(SATOSHI_PUBKEY_HEX));
    bytes.push(OP_CHECKSIG);
    ScriptBuf::from_bytes(bytes)
}

/// Merkle root of `txids`, pairing and duplicating the last hash on odd levels
/// (`ComputeMerkleRoot`).
pub(crate) fn merkle_root(txids: &[Txid]) -> bitcoin::TxMerkleNode {
    let mut level: Vec<[u8; 32]> = txids.iter().map(|txid| txid.to_byte_array()).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty level"));
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                sha256d::Hash::hash(&buf).to_byte_array()
            })
            .collect();
    }
    let root = level.first().copied().unwrap_or([0u8; 32]);
    bitcoin::TxMerkleNode::from_byte_array(root)
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hard-coded hex is valid"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        ChainParams, MAINNET_GENESIS_HASH, REGTEST_GENESIS_HASH, TESTNET_GENESIS_HASH,
    };
    use bitcoin::TxMerkleNode;

    const GENESIS_MERKLE_ROOT: &str =
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

    #[test]
    fn named_genesis_blocks_match_params() {
        let merkle: TxMerkleNode = GENESIS_MERKLE_ROOT.parse().unwrap();

        for (block, expected_hash) in [
            (mainnet_genesis_block(), MAINNET_GENESIS_HASH),
            (testnet_genesis_block(), TESTNET_GENESIS_HASH),
            (regtest_genesis_block(), REGTEST_GENESIS_HASH),
        ] {
            assert_eq!(block.header.merkle_root, merkle);
            assert_eq!(block.txdata.len(), 1);
            assert_eq!(block.block_hash().to_string(), expected_hash);
        }

        let mainnet = ChainParams::mainnet();
        assert_eq!(mainnet_genesis_block().block_hash(), mainnet.genesis_hash);
        assert_eq!(
            testnet_genesis_block().block_hash(),
            ChainParams::testnet().genesis_hash
        );
        assert_eq!(
            regtest_genesis_block().block_hash(),
            ChainParams::regtest().genesis_hash
        );
    }

    #[test]
    fn coinbase_matches_core_layout() {
        let block = mainnet_genesis_block();
        let coinbase = &block.txdata[0];
        assert_eq!(coinbase.version, 1);
        assert_eq!(coinbase.lock_time, 0);
        assert!(coinbase.is_coin_base());
        assert_eq!(coinbase.vout[0].value, 50 * COIN);

        let script = coinbase.vin[0].script_sig.as_bytes();
        assert_eq!(&script[..5], &[0x04, 0xff, 0xff, 0x00, 0x1d]);
        assert_eq!(&script[5..7], &[0x01, 0x04]);
        assert_eq!(script[7] as usize, BITCOIN_GENESIS_TIMESTAMP.len());
        assert_eq!(&script[8..], BITCOIN_GENESIS_TIMESTAMP.as_bytes());
    }

    #[test]
    fn mined_custom_genesis_meets_target() {
        let mut block = create_genesis_block(
            "custom genesis",
            ScriptBuf::new(),
            1_700_000_000,
            0,
            0x207f_ffff,
            1,
            COIN,
        );
        let pow_limit = decode_compact(0x207f_ffff).unwrap();
        let nonce = mine_genesis(&mut block, pow_limit);

        assert_eq!(block.header.nonce, nonce);
        let target = decode_compact(block.header.bits).unwrap();
        let hash = block.block_hash().to_byte_array();
        assert!(U256::from_little_endian(&hash) <= target);
    }

    #[test]
    #[should_panic(expected = "above the proof-of-work limit")]
    fn mine_rejects_target_above_pow_limit() {
        // Regtest bits (~2^255) are above the 0x1f00ffff limit (~2^240).
        let mut block = regtest_genesis_block();
        mine_genesis(&mut block, decode_compact(0x1f00_ffff).unwrap());
    }
}
