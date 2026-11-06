//! Contextual checks. Port of `ContextualCheckBlockHeader`,
//! `ContextualCheckBlock` and `GetBlockScriptFlags` (validation.cpp).

use btc_consensus::ChainParams;
use btc_primitives::{Block, BlockHeader};
use btc_script::ScriptVerifyFlags;

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
    todo!()
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
    todo!()
}
