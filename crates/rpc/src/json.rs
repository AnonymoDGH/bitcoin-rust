//! JSON renderings of blocks, headers, transactions and scripts, with the field
//! names of `blockToJSON`, `TxToUniv` and `ScriptPubKeyToUniv` in Core.

use bitcoin::consensus::encode::{serialize, serialize_hex};
use bitcoin::hex::DisplayHex;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::Network as BitcoinNetwork;
use bitcoin_hashes::Hash;
use btc_primitives::{Block, BlockHash, BlockHeader, ScriptBuf, Tx, TxIn, TxOut};
use btc_wallet::address::{encode_address, Network};
use serde_json::{json, Map, Value};

const BLOCK_HEADER_SIZE: usize = 80;

/// Converts satoshis to the BTC-denominated JSON number Core uses.
pub(crate) fn amount(sats: i64) -> Value {
    json!(sats as f64 / 100_000_000.0)
}

/// Maps the node's network to the one the address codec uses. Testnet4 and signet
/// share the `tb` bech32 prefix with testnet.
pub(crate) fn wallet_network(network: BitcoinNetwork) -> Network {
    match network {
        BitcoinNetwork::Bitcoin => Network::Main,
        BitcoinNetwork::Regtest => Network::Regtest,
        _ => Network::Test,
    }
}

pub(crate) fn script_json(script: &ScriptBuf, network: Network) -> Value {
    let mut m = Map::new();
    m.insert("asm".into(), json!(script.to_asm_string()));
    m.insert("hex".into(), json!(script.as_bytes().to_lower_hex_string()));
    m.insert("type".into(), json!(script_type(script)));
    if let Ok(address) = encode_address(network, script) {
        m.insert("address".into(), json!(address));
    }
    Value::Object(m)
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
    network: Network,
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
            .map(|tx| tx_json(tx, network, false))
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
pub(crate) fn tx_json(tx: &Tx, network: Network, with_hex: bool) -> Value {
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
                .map(|(n, output)| vout_json(output, n, network))
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

fn vout_json(output: &TxOut, n: usize, network: Network) -> Value {
    json!({
        "value": amount(output.value),
        "n": n,
        "scriptPubKey": script_json(&output.script_pubkey, network),
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
