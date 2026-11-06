//! JSON renderings of blocks, headers, transactions and scripts, with the field
//! names of `blockToJSON`, `TxToUniv` and `ScriptPubKeyToUniv` in Core.

use bitcoin::consensus::encode::{serialize, serialize_hex};
use bitcoin::hex::DisplayHex;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin_hashes::Hash;
use btc_primitives::{Block, BlockHash, BlockHeader, ScriptBuf, Tx, TxIn, TxOut};
use btc_wallet::address::{decode_address_with, encode_address_with, AddressParams};
use serde_json::{json, Map, Value};

const BLOCK_HEADER_SIZE: usize = 80;
/// Program of pay-to-anchor (`OP_1 <0x4e73>`).
const PAY_TO_ANCHOR_PROGRAM: [u8; 2] = [0x4e, 0x73];

/// Renders satoshis as the BTC number Core prints (`ValueFromAmount`): exactly eight
/// decimals. Needs serde_json's `arbitrary_precision` feature to keep the digits.
pub(crate) fn amount(sats: i64) -> Value {
    let sign = if sats < 0 { "-" } else { "" };
    let magnitude = sats.unsigned_abs();
    let text = format!(
        "{sign}{}.{:08}",
        magnitude / 100_000_000,
        magnitude % 100_000_000
    );
    serde_json::from_str(&text).expect("a decimal literal is valid JSON")
}

pub(crate) fn script_hex(script: &ScriptBuf) -> String {
    script.as_bytes().to_lower_hex_string()
}

/// The address `script` pays to under `params`, when it has one.
pub(crate) fn address_of(params: &AddressParams, script: &ScriptBuf) -> Option<String> {
    encode_address_with(params, script).ok()
}

pub(crate) fn script_json(script: &ScriptBuf, params: &AddressParams) -> Value {
    let mut m = Map::new();
    m.insert("asm".into(), json!(script.to_asm_string()));
    m.insert("hex".into(), json!(script_hex(script)));
    m.insert("type".into(), json!(script_type(script)));
    if let Some(address) = address_of(params, script) {
        m.insert("address".into(), json!(address));
    }
    Value::Object(m)
}

/// `validateaddress`: the decoded address in canonical form, or `{"isvalid": false}`.
pub(crate) fn validate_address(params: &AddressParams, text: &str) -> Value {
    let decoded = decode_address_with(params, text)
        .ok()
        .and_then(|script| address_of(params, &script).map(|address| (script, address)));
    let Some((script, address)) = decoded else {
        return json!({ "isvalid": false });
    };
    let mut m = Map::new();
    m.insert("isvalid".into(), json!(true));
    m.insert("address".into(), json!(address));
    m.insert("scriptPubKey".into(), json!(script_hex(&script)));
    describe_script(&script, &mut m);
    Value::Object(m)
}

/// The `isscript`, `iswitness` and witness fields of `DescribeAddress`.
fn describe_script(script: &ScriptBuf, m: &mut Map<String, Value>) {
    if script.is_p2pkh() {
        m.insert("isscript".into(), json!(false));
        m.insert("iswitness".into(), json!(false));
        return;
    }
    if script.is_p2sh() {
        m.insert("isscript".into(), json!(true));
        m.insert("iswitness".into(), json!(false));
        return;
    }
    let Some(version) = script.witness_version() else {
        return;
    };
    let version = version.to_num();
    let program = &script.as_bytes()[2..];
    if version == 1 && program == PAY_TO_ANCHOR_PROGRAM.as_slice() {
        m.insert("isscript".into(), json!(true));
        m.insert("iswitness".into(), json!(true));
        return;
    }
    match (version, program.len()) {
        (0, 20) => {
            m.insert("isscript".into(), json!(false));
        }
        (0, 32) | (1, 32) => {
            m.insert("isscript".into(), json!(true));
        }
        _ => {}
    }
    m.insert("iswitness".into(), json!(true));
    m.insert("witness_version".into(), json!(version));
    m.insert(
        "witness_program".into(),
        json!(program.to_lower_hex_string()),
    );
}

fn script_type(script: &ScriptBuf) -> &'static str {
    if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2tr() {
        "witness_v1_taproot"
    } else if script.is_p2pk() {
        "pubkey"
    } else if script.is_multisig() {
        "multisig"
    } else if script.is_op_return() {
        "nulldata"
    } else if script.is_witness_program() {
        "witness_unknown"
    } else {
        "nonstandard"
    }
}

pub(crate) fn header_fields(
    header: &BlockHeader,
    height: u32,
    confirmations: i64,
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("hash".into(), json!(header.block_hash().to_string()));
    m.insert("confirmations".into(), json!(confirmations));
    m.insert("height".into(), json!(height));
    m.insert("version".into(), json!(header.version));
    m.insert(
        "versionHex".into(),
        json!(format!("{:08x}", header.version)),
    );
    m.insert("merkleroot".into(), json!(header.merkle_root.to_string()));
    m.insert("time".into(), json!(header.time));
    m.insert("nonce".into(), json!(header.nonce));
    m.insert("bits".into(), json!(format!("{:08x}", header.bits)));
    m.insert("difficulty".into(), json!(difficulty(header.bits)));
    if header.prev_blockhash != BlockHash::all_zeros() {
        m.insert(
            "previousblockhash".into(),
            json!(header.prev_blockhash.to_string()),
        );
    }
    m
}

/// Port of `GetDifficulty`: the difficulty implied by the compact target.
pub(crate) fn difficulty(bits: u32) -> f64 {
    Target::from_compact(CompactTarget::from_consensus(bits)).difficulty_float()
}

/// `getblock` at verbosity 1 (txids) or 2 (decoded transactions).
pub(crate) fn block_json(
    block: &Block,
    height: u32,
    confirmations: i64,
    params: &AddressParams,
    decode_txs: bool,
) -> Value {
    let size = serialize(block).len();
    let stripped = BLOCK_HEADER_SIZE
        + compact_size_len(block.txdata.len())
        + block.txdata.iter().map(stripped_size).sum::<usize>();
    let mut m = header_fields(&block.header, height, confirmations);
    m.insert("strippedsize".into(), json!(stripped));
    m.insert("size".into(), json!(size));
    m.insert("weight".into(), json!(stripped * 3 + size));
    m.insert("nTx".into(), json!(block.txdata.len()));
    let txs: Vec<Value> = if decode_txs {
        block
            .txdata
            .iter()
            .map(|tx| tx_json(tx, params, false))
            .collect()
    } else {
        block
            .txdata
            .iter()
            .map(|tx| json!(tx.txid().to_string()))
            .collect()
    };
    m.insert("tx".into(), Value::Array(txs));
    Value::Object(m)
}

/// Decoded transaction as in `TxToUniv`.
pub(crate) fn tx_json(tx: &Tx, params: &AddressParams, with_hex: bool) -> Value {
    let size = tx.total_size();
    let weight = stripped_size(tx) * 3 + size;
    let mut m = Map::new();
    m.insert("txid".into(), json!(tx.txid().to_string()));
    m.insert("hash".into(), json!(tx.wtxid().to_string()));
    m.insert("version".into(), json!(tx.version));
    m.insert("size".into(), json!(size));
    m.insert("vsize".into(), json!(weight.div_ceil(4)));
    m.insert("weight".into(), json!(weight));
    m.insert("locktime".into(), json!(tx.lock_time));
    m.insert(
        "vin".into(),
        Value::Array(tx.vin.iter().map(|input| vin_json(tx, input)).collect()),
    );
    m.insert(
        "vout".into(),
        Value::Array(
            tx.vout
                .iter()
                .enumerate()
                .map(|(n, output)| vout_json(output, n, params))
                .collect(),
        ),
    );
    if with_hex {
        m.insert("hex".into(), json!(serialize_hex(tx)));
    }
    Value::Object(m)
}

fn vin_json(tx: &Tx, input: &TxIn) -> Value {
    let mut m = Map::new();
    if tx.is_coin_base() {
        m.insert(
            "coinbase".into(),
            json!(input.script_sig.as_bytes().to_lower_hex_string()),
        );
    } else {
        m.insert("txid".into(), json!(input.prevout.txid.to_string()));
        m.insert("vout".into(), json!(input.prevout.vout));
        m.insert(
            "scriptSig".into(),
            json!({
                "asm": input.script_sig.to_asm_string(),
                "hex": input.script_sig.as_bytes().to_lower_hex_string(),
            }),
        );
    }
    if !input.witness.is_empty() {
        let stack: Vec<String> = input
            .witness
            .iter()
            .map(|item| item.to_lower_hex_string())
            .collect();
        m.insert("txinwitness".into(), json!(stack));
    }
    m.insert("sequence".into(), json!(input.sequence.0));
    Value::Object(m)
}

fn vout_json(output: &TxOut, n: usize, params: &AddressParams) -> Value {
    json!({
        "value": amount(output.value),
        "n": n,
        "scriptPubKey": script_json(&output.script_pubkey, params),
    })
}

fn stripped_size(tx: &Tx) -> usize {
    let mut buf = Vec::new();
    tx.encode_with(&mut buf, false)
        .expect("in-memory writers cannot fail");
    buf.len()
}

fn compact_size_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}
