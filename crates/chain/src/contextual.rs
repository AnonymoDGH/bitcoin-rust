//! Contextual checks. Port of `ContextualCheckBlockHeader`,
//! `ContextualCheckBlock` and `GetBlockScriptFlags` (validation.cpp).

use bitcoin::consensus::serialize;
use btc_consensus::ChainParams;
use btc_primitives::{Block, BlockHeader};
use btc_script::script_num::ScriptNum;
use btc_script::ScriptVerifyFlags;
use btc_validation::block_verify::{MAX_BLOCK_WEIGHT, MAX_FUTURE_BLOCK_TIME};

use crate::finality::is_final_tx;
use crate::witness::check_witness_malleation;
use crate::{BlockTree, IndexId, ValidationError};

/// `GetBlockScriptFlags` for the block at `height` with `hash`:
/// P2SH|WITNESS|TAPROOT always (unless a `script_flag_exceptions` entry),
/// DERSIG from bip66, CLTV from bip65, CSV from csv, NULLDUMMY from segwit.
pub fn block_script_flags(height: u32, hash: &btc_primitives::BlockHash, params: &ChainParams) -> ScriptVerifyFlags {
    let d = &params.deployments;
    let mut flags = d
        .script_flag_exceptions
        .iter()
        .find(|(h, _)| h == hash)
        .map(|(_, bits)| ScriptVerifyFlags::from_bits(*bits))
        .unwrap_or(ScriptVerifyFlags::P2SH | ScriptVerifyFlags::WITNESS | ScriptVerifyFlags::TAPROOT);
    if height >= d.bip66_height {
        flags |= ScriptVerifyFlags::DERSIG;
    }
    if height >= d.bip65_height {
        flags |= ScriptVerifyFlags::CHECKLOCKTIMEVERIFY;
    }
    if height >= d.csv_height {
        flags |= ScriptVerifyFlags::CHECKSEQUENCEVERIFY;
    }
    if height >= d.segwit_height {
        flags |= ScriptVerifyFlags::NULLDUMMY;
    }
    flags
}

/// `CScript() << height`: the BIP34 coinbase prefix. 0 is OP_0, 1..=16 are
/// OP_1..OP_16, anything else is a minimal little-endian push.
pub fn bip34_height_script(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        _ => {
            let num = ScriptNum::encode(i64::from(height));
            let mut out = vec![num.len() as u8];
            out.extend_from_slice(&num);
            out
        }
    }
}

/// `ContextualCheckBlockHeader(header, prev)`: nBits == next_work_required,
/// time > MTP(prev), time <= now + MAX_FUTURE_BLOCK_TIME, reject
/// version < 2/3/4 once bip34/bip66/bip65 are active at prev.height+1.
pub fn contextual_check_block_header(
    header: &BlockHeader,
    tree: &BlockTree,
    prev: IndexId,
    params: &ChainParams,
    now: i64,
) -> Result<(), ValidationError> {
    let d = &params.deployments;
    let height = tree.get(prev).height + 1;

    if header.bits != tree.next_work_required(prev, header, params) {
        return Err(ValidationError::BadDiffBits);
    }
    if header.block_time() <= tree.median_time_past(prev) {
        return Err(ValidationError::TimeTooOld);
    }
    if header.block_time() > now + MAX_FUTURE_BLOCK_TIME {
        return Err(ValidationError::TimeTooNew);
    }
    let version = header.version;
    if (version < 2 && height >= d.bip34_height)
        || (version < 3 && height >= d.bip66_height)
        || (version < 4 && height >= d.bip65_height)
    {
        return Err(ValidationError::BadVersion(version));
    }
    Ok(())
}

/// `ContextualCheckBlock(block, prev)`: finality (MTP cutoff once CSV is
/// active, else block time), BIP34 height prefix in the coinbase scriptSig,
/// witness malleation (commitment expected once segwit is active), and the
/// block weight limit. `prev == None` only for genesis.
pub fn contextual_check_block(
    block: &Block,
    tree: &BlockTree,
    prev: Option<IndexId>,
    params: &ChainParams,
) -> Result<(), ValidationError> {
    let d = &params.deployments;
    let height = prev.map_or(0, |p| tree.get(p).height + 1);

    let lock_time_cutoff = match prev {
        Some(p) if height >= d.csv_height => tree.median_time_past(p),
        _ => block.header.block_time(),
    };
    if block
        .txdata
        .iter()
        .any(|tx| !is_final_tx(tx, height as i32, lock_time_cutoff))
    {
        return Err(ValidationError::NonFinalTx);
    }

    if height >= d.bip34_height {
        let expect = bip34_height_script(height);
        let script_sig = block
            .txdata
            .first()
            .and_then(|tx| tx.vin.first())
            .map_or(&[][..], |input| input.script_sig.as_bytes());
        if !script_sig.starts_with(&expect) {
            return Err(ValidationError::BadCbHeight);
        }
    }

    check_witness_malleation(block, height >= d.segwit_height)?;

    if block_weight(block) > MAX_BLOCK_WEIGHT {
        return Err(ValidationError::BadBlockWeight);
    }
    Ok(())
}

/// `GetBlockWeight()`: non-witness bytes count 4x, witness bytes 1x.
fn block_weight(block: &Block) -> usize {
    let mut stripped = serialize(&block.header).len() + compact_size_len(block.txdata.len());
    for tx in &block.txdata {
        let mut buf = Vec::new();
        tx.encode_with(&mut buf, false).expect("in-memory writers cannot fail");
        stripped += buf.len();
    }
    let total = serialize(block).len();
    stripped * 3 + total
}

fn compact_size_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{BlockHash, OutPoint, ScriptBuf, Sequence, TxMerkleNode, Txid, Witness};
    use bitcoin_hashes::Hash as _;
    use btc_primitives::{Tx, TxIn, TxOut};

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const BASE_TIME: u32 = 1_600_000_000;
    const SPACING: u32 = 600;

    fn header(prev: BlockHash, time: u32, version: i32, bits: u32) -> BlockHeader {
        BlockHeader::new(version, prev, TxMerkleNode::all_zeros(), time, bits, 0)
    }

    /// Genesis plus `len` headers, version 4, `SPACING` seconds apart.
    /// Returns the tree and the tip.
    fn chain(len: u32) -> (BlockTree, IndexId) {
        let mut tree = BlockTree::new();
        let mut prev = BlockHash::all_zeros();
        let mut tip = 0;
        for i in 0..=len {
            let h = header(prev, BASE_TIME + i * SPACING, 4, REGTEST_BITS);
            prev = h.block_hash();
            tip = tree.insert_header(h).unwrap();
        }
        (tree, tip)
    }

    fn next_time(tree: &BlockTree, tip: IndexId) -> u32 {
        tree.get(tip).header.time + SPACING
    }

    fn coinbase(script_sig: &[u8]) -> Tx {
        let mut input = TxIn::new(OutPoint::null());
        input.script_sig = ScriptBuf::from_bytes(script_sig.to_vec());
        Tx::new(2, vec![input], vec![TxOut::new(50_0000_0000, ScriptBuf::from_bytes(vec![0x51]))], 0)
    }

    /// A non-coinbase transaction spending a fixed outpoint.
    fn spend(lock_time: u32, sequence: u32, witness: Witness) -> Tx {
        let mut input = TxIn::new(OutPoint::new(Txid::from_byte_array([7; 32]), 0));
        input.sequence = Sequence(sequence);
        input.witness = witness;
        Tx::new(2, vec![input], vec![TxOut::new(1_000, ScriptBuf::from_bytes(vec![0x51]))], lock_time)
    }

    fn block(time: u32, txs: Vec<Tx>) -> Block {
        Block::new(header(BlockHash::all_zeros(), time, 4, REGTEST_BITS), txs)
    }

    /// Block on top of `prev` with a BIP34-correct coinbase for its height.
    fn child(tree: &BlockTree, prev: IndexId, txs: Vec<Tx>) -> Block {
        let height = tree.get(prev).height + 1;
        let mut all = vec![coinbase(&bip34_height_script(height))];
        all.extend(txs);
        block(next_time(tree, prev), all)
    }

    #[test]
    fn bip34_encodings_match_cscript_push() {
        assert_eq!(bip34_height_script(0), vec![0x00]);
        assert_eq!(bip34_height_script(1), vec![0x51]);
        assert_eq!(bip34_height_script(16), vec![0x60]);
        assert_eq!(bip34_height_script(17), vec![0x01, 0x11]);
        assert_eq!(bip34_height_script(127), vec![0x01, 0x7f]);
        assert_eq!(bip34_height_script(128), vec![0x02, 0x80, 0x00]);
        assert_eq!(bip34_height_script(255), vec![0x02, 0xff, 0x00]);
        assert_eq!(bip34_height_script(256), vec![0x02, 0x00, 0x01]);
        assert_eq!(bip34_height_script(65536), vec![0x03, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn header_accepted_when_consistent() {
        let (tree, tip) = chain(3);
        let time = next_time(&tree, tip);
        let h = header(tree.get(tip).hash, time, 4, REGTEST_BITS);
        let params = ChainParams::regtest();
        assert_eq!(contextual_check_block_header(&h, &tree, tip, &params, i64::from(time)), Ok(()));
    }

    #[test]
    fn header_bad_bits() {
        let (tree, tip) = chain(3);
        let time = next_time(&tree, tip);
        let h = header(tree.get(tip).hash, time, 4, 0x1d00_ffff);
        let params = ChainParams::regtest();
        assert_eq!(
            contextual_check_block_header(&h, &tree, tip, &params, i64::from(time)),
            Err(ValidationError::BadDiffBits)
        );
    }

    #[test]
    fn header_time_at_mtp_is_too_old() {
        let (tree, tip) = chain(3);
        let mtp = tree.median_time_past(tip) as u32;
        let h = header(tree.get(tip).hash, mtp, 4, REGTEST_BITS);
        let params = ChainParams::regtest();
        assert_eq!(
            contextual_check_block_header(&h, &tree, tip, &params, i64::from(mtp)),
            Err(ValidationError::TimeTooOld)
        );
    }

    #[test]
    fn header_future_time_limit() {
        let (tree, tip) = chain(3);
        let now = i64::from(next_time(&tree, tip)) + 1_000;
        let ok = header(tree.get(tip).hash, (now + MAX_FUTURE_BLOCK_TIME) as u32, 4, REGTEST_BITS);
        let late = header(tree.get(tip).hash, (now + MAX_FUTURE_BLOCK_TIME + 1) as u32, 4, REGTEST_BITS);
        let params = ChainParams::regtest();
        assert_eq!(contextual_check_block_header(&ok, &tree, tip, &params, now), Ok(()));
        assert_eq!(
            contextual_check_block_header(&late, &tree, tip, &params, now),
            Err(ValidationError::TimeTooNew)
        );
    }

    #[test]
    fn header_low_version_rejected_by_active_bips() {
        let (tree, tip) = chain(3);
        let time = next_time(&tree, tip);
        let params = ChainParams::regtest();
        let check = |version| {
            let h = header(tree.get(tip).hash, time, version, REGTEST_BITS);
            contextual_check_block_header(&h, &tree, tip, &params, i64::from(time))
        };
        assert_eq!(check(1), Err(ValidationError::BadVersion(1)));
        assert_eq!(check(2), Err(ValidationError::BadVersion(2)));
        assert_eq!(check(3), Err(ValidationError::BadVersion(3)));
        assert_eq!(check(4), Ok(()));
    }

    #[test]
    fn header_version_only_checked_at_activation_height() {
        let mut params = ChainParams::regtest();
        params.deployments.bip34_height = 5;
        params.deployments.bip65_height = 100;
        params.deployments.bip66_height = 100;

        // Child height 1 is below bip34: version 1 passes.
        let (tree, tip) = chain(0);
        let time = next_time(&tree, tip);
        let h = header(tree.get(tip).hash, time, 1, REGTEST_BITS);
        assert_eq!(contextual_check_block_header(&h, &tree, tip, &params, i64::from(time)), Ok(()));

        // Child height 5 is at bip34: version 1 is rejected.
        let (tree, tip) = chain(4);
        let time = next_time(&tree, tip);
        let h = header(tree.get(tip).hash, time, 1, REGTEST_BITS);
        assert_eq!(
            contextual_check_block_header(&h, &tree, tip, &params, i64::from(time)),
            Err(ValidationError::BadVersion(1))
        );
    }

    #[test]
    fn genesis_block_accepted_without_bip34_prefix() {
        let block = block(BASE_TIME, vec![coinbase(&[0xab])]);
        let params = ChainParams::regtest();
        assert_eq!(contextual_check_block(&block, &BlockTree::new(), None, &params), Ok(()));
    }

    #[test]
    fn bip34_prefix_must_match_height() {
        let params = ChainParams::regtest();
        for height in [1u32, 16, 17, 127, 128, 255, 256] {
            let (tree, tip) = chain(height - 1);

            let good = child(&tree, tip, vec![]);
            assert_eq!(contextual_check_block(&good, &tree, Some(tip), &params), Ok(()), "height {height}");

            let mut extra = bip34_height_script(height);
            extra.extend_from_slice(&[0xaa, 0xbb]);
            let mut prefixed = child(&tree, tip, vec![]);
            prefixed.txdata[0] = coinbase(&extra);
            assert_eq!(contextual_check_block(&prefixed, &tree, Some(tip), &params), Ok(()), "height {height}");

            let mut wrong = child(&tree, tip, vec![]);
            wrong.txdata[0] = coinbase(&bip34_height_script(height - 1));
            assert_eq!(
                contextual_check_block(&wrong, &tree, Some(tip), &params),
                Err(ValidationError::BadCbHeight),
                "height {height}"
            );
        }

        let (tree, tip) = chain(0);
        let mut empty = child(&tree, tip, vec![]);
        empty.txdata[0] = coinbase(&[]);
        assert_eq!(
            contextual_check_block(&empty, &tree, Some(tip), &params),
            Err(ValidationError::BadCbHeight)
        );
    }

    #[test]
    fn non_final_transaction_rejected() {
        let params = ChainParams::regtest();
        let (tree, tip) = chain(0);

        // Height-based lock time 10 is not reached at height 1.
        let block = child(&tree, tip, vec![spend(10, 0, Witness::new())]);
        assert_eq!(contextual_check_block(&block, &tree, Some(tip), &params), Err(ValidationError::NonFinalTx));

        let block = child(&tree, tip, vec![spend(10, Sequence::MAX.0, Witness::new())]);
        assert_eq!(contextual_check_block(&block, &tree, Some(tip), &params), Ok(()));
    }

    #[test]
    fn csv_switches_lock_time_cutoff_to_mtp() {
        // MTP(tip) = BASE + 1200 while the block time is BASE + 2400.
        let (tree, tip) = chain(3);
        let lock_time = BASE_TIME + 1200;
        let block = child(&tree, tip, vec![spend(lock_time, 0, Witness::new())]);
        assert!(block.header.block_time() > tree.median_time_past(tip));

        let params = ChainParams::regtest();
        assert_eq!(
            contextual_check_block(&block, &tree, Some(tip), &params),
            Err(ValidationError::NonFinalTx)
        );

        let mut pre_csv = ChainParams::regtest();
        pre_csv.deployments.csv_height = 1000;
        assert_eq!(contextual_check_block(&block, &tree, Some(tip), &pre_csv), Ok(()));
    }

    #[test]
    fn unexpected_witness_rejected_once_segwit_active() {
        let (tree, tip) = chain(0);
        let mut witness = Witness::new();
        witness.push([1u8]);
        let block = child(&tree, tip, vec![spend(0, Sequence::MAX.0, witness)]);
        assert_eq!(
            contextual_check_block(&block, &tree, Some(tip), &ChainParams::regtest()),
            Err(ValidationError::UnexpectedWitness)
        );
    }

    #[test]
    fn block_weight_limit() {
        let params = ChainParams::regtest();
        let (tree, tip) = chain(0);
        let heavy_coinbase = |len: usize| {
            let mut cb = coinbase(&bip34_height_script(1));
            cb.vout[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a; len]);
            cb
        };

        let ok = block(next_time(&tree, tip), vec![heavy_coinbase(900_000)]);
        assert_eq!(contextual_check_block(&ok, &tree, Some(tip), &params), Ok(()));

        let heavy = block(next_time(&tree, tip), vec![heavy_coinbase(1_000_100)]);
        assert_eq!(
            contextual_check_block(&heavy, &tree, Some(tip), &params),
            Err(ValidationError::BadBlockWeight)
        );
    }

    #[test]
    fn block_weight_counts_witness_at_one_quarter() {
        let (tree, tip) = chain(0);
        let mut witness = Witness::new();
        witness.push(vec![0u8; 1_000]);
        let block = child(&tree, tip, vec![spend(0, Sequence::MAX.0, witness)]);
        let stripped = serialize(&block.header).len()
            + compact_size_len(block.txdata.len())
            + block.txdata.iter().map(|tx| tx.encode_with(&mut Vec::new(), false).unwrap()).sum::<usize>();
        let total = serialize(&block).len();
        assert_eq!(block_weight(&block), stripped * 3 + total);
        assert!(total > stripped);
    }

    #[test]
    fn full_block_accepted() {
        let params = ChainParams::regtest();
        let (tree, tip) = chain(5);
        let block = child(&tree, tip, vec![spend(0, Sequence::MAX.0, Witness::new())]);
        assert_eq!(contextual_check_block(&block, &tree, Some(tip), &params), Ok(()));
    }
}
