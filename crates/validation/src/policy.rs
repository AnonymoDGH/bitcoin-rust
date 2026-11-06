//! Standardness policy. Port of src/policy/policy.{h,cpp}.
//!
//! Only checks that can be decided from the transaction bytes are implemented.
//! Anything that needs script execution (sigop counting, witness stack limits,
//! P2SH redeem-script checks) is out of scope.

use btc_primitives::{ScriptBuf, Tx, TxOut};
use thiserror::Error;

/// `WITNESS_SCALE_FACTOR` from `consensus/consensus.h`.
pub const WITNESS_SCALE_FACTOR: i64 = 4;

/// `MAX_STANDARD_TX_WEIGHT`: the largest transaction we relay or mine.
pub const MAX_STANDARD_TX_WEIGHT: i64 = 400_000;
/// `MAX_STANDARD_SCRIPTSIG_SIZE`.
pub const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1650;
/// `DEFAULT_INCREMENTAL_RELAY_FEE`, in satoshis per 1000 vbytes.
pub const DEFAULT_INCREMENTAL_RELAY_FEE: u32 = 100;
/// `DUST_RELAY_TX_FEE`, in satoshis per 1000 vbytes.
pub const DUST_RELAY_TX_FEE: u32 = 3000;
/// `MAX_OP_RETURN_RELAY`: default byte budget for OP_RETURN outputs in one tx.
pub const MAX_OP_RETURN_RELAY: u32 = (MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR) as u32;
/// `DEFAULT_PERMIT_BAREMULTISIG`.
pub const DEFAULT_PERMIT_BAREMULTISIG: bool = true;
/// `MAX_DUST_OUTPUTS_PER_TX`: dust outputs allowed in a standard tx (ephemeral dust).
pub const MAX_DUST_OUTPUTS_PER_TX: usize = 1;
/// `TX_MIN_STANDARD_VERSION`.
pub const TX_MIN_STANDARD_VERSION: u32 = 1;
/// `TX_MAX_STANDARD_VERSION`.
pub const TX_MAX_STANDARD_VERSION: u32 = 3;

/// `MAX_SCRIPT_SIZE` from `script/script.h`.
const MAX_SCRIPT_SIZE: usize = 10_000;

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_RETURN: u8 = 0x6a;
const OP_DUP: u8 = 0x76;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;

/// Pay-to-Anchor: `OP_1 <0x4e73>`.
const P2A_SCRIPT: &[u8] = &[0x51, 0x02, 0x4e, 0x73];

/// Output script classes, mirroring `TxoutType` in `script/solver.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxoutType {
    NonStandard,
    PubKey,
    PubKeyHash,
    ScriptHash,
    MultiSig { required: u8, total: u8 },
    NullData,
    WitnessV0KeyHash,
    WitnessV0ScriptHash,
    WitnessV1Taproot,
    Anchor,
    WitnessUnknown,
}

/// Knobs that Core passes into `IsStandardTx`. `Default` matches Core's defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardnessOptions {
    /// Total OP_RETURN script bytes allowed per tx. `None` rejects all OP_RETURN outputs.
    pub max_datacarrier_bytes: Option<u32>,
    pub permit_bare_multisig: bool,
    /// Dust relay rate, in satoshis per 1000 vbytes.
    pub dust_relay_fee_per_kvb: u32,
}

impl Default for StandardnessOptions {
    fn default() -> Self {
        Self {
            max_datacarrier_bytes: Some(MAX_OP_RETURN_RELAY),
            permit_bare_multisig: DEFAULT_PERMIT_BAREMULTISIG,
            dust_relay_fee_per_kvb: DUST_RELAY_TX_FEE,
        }
    }
}

/// Reasons a transaction is non-standard. `reason()` gives Core's reason string.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum StandardnessError {
    #[error("transaction version {0} is not standard")]
    Version(u32),
    #[error("transaction weight {0} exceeds the standard limit")]
    TxSize(i64),
    #[error("input {index} scriptSig is {size} bytes, over the standard limit")]
    ScriptSigSize { index: usize, size: usize },
    #[error("input {index} scriptSig is not push-only")]
    ScriptSigNotPushOnly { index: usize },
    #[error("output {index} has a non-standard scriptPubKey")]
    ScriptPubKey { index: usize },
    #[error("output {index} exceeds the OP_RETURN data budget")]
    DataCarrier { index: usize },
    #[error("output {index} is bare multisig, which is not permitted")]
    BareMultisig { index: usize },
    #[error("{count} dust outputs, at most {MAX_DUST_OUTPUTS_PER_TX} allowed")]
    Dust { count: usize },
}

impl StandardnessError {
    /// Core's `reason` string for this error.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Version(_) => "version",
            Self::TxSize(_) => "tx-size",
            Self::ScriptSigSize { .. } => "scriptsig-size",
            Self::ScriptSigNotPushOnly { .. } => "scriptsig-not-pushonly",
            Self::ScriptPubKey { .. } => "scriptpubkey",
            Self::DataCarrier { .. } => "datacarrier",
            Self::BareMultisig { .. } => "bare-multisig",
            Self::Dust { .. } => "dust",
        }
    }
}

/// Reads one script op at `*pos`, like `CScript::GetOp`. Returns the opcode and
/// its pushed data (empty for non-push ops), or `None` if the script is truncated.
fn next_op<'a>(script: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    let opcode = *script.get(*pos)?;
    *pos += 1;
    let len = match opcode {
        0x01..=0x4b => usize::from(opcode),
        OP_PUSHDATA1 => {
            let len = usize::from(*script.get(*pos)?);
            *pos += 1;
            len
        }
        OP_PUSHDATA2 => {
            let b = script.get(*pos..*pos + 2)?;
            *pos += 2;
            usize::from(u16::from_le_bytes([b[0], b[1]]))
        }
        OP_PUSHDATA4 => {
            let b = script.get(*pos..*pos + 4)?;
            *pos += 4;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        _ => return Some((opcode, &[])),
    };
    let end = (*pos).checked_add(len)?;
    let data = script.get(*pos..end)?;
    *pos = end;
    Some((opcode, data))
}

/// Mirrors `CScript::IsPushOnly`: every op must be OP_0..OP_16 or a data push.
fn is_push_only(script: &[u8]) -> bool {
    let mut pos = 0;
    while pos < script.len() {
        match next_op(script, &mut pos) {
            Some((op, _)) if op <= OP_16 => {}
            _ => return false,
        }
    }
    true
}

/// Value of an OP_1..OP_16 opcode.
fn small_int(op: u8) -> Option<u8> {
    (OP_1..=OP_16).contains(&op).then(|| op - OP_1 + 1)
}

/// Mirrors `CPubKey::ValidSize`: the header byte determines the length.
fn is_valid_pubkey_size(data: &[u8]) -> bool {
    match data.first() {
        Some(0x02 | 0x03) => data.len() == 33,
        Some(0x04 | 0x06 | 0x07) => data.len() == 65,
        _ => false,
    }
}

/// Mirrors `CScript::IsWitnessProgram`: returns (version, program).
fn witness_program(s: &[u8]) -> Option<(u8, &[u8])> {
    if !(4..=42).contains(&s.len()) {
        return None;
    }
    let version = if s[0] == OP_0 { 0 } else { small_int(s[0])? };
    if usize::from(s[1]) + 2 != s.len() {
        return None;
    }
    Some((version, &s[2..]))
}

/// `CScript::IsUnspendable`.
fn is_unspendable(s: &[u8]) -> bool {
    s.first() == Some(&OP_RETURN) || s.len() > MAX_SCRIPT_SIZE
}

fn is_p2sh(s: &[u8]) -> bool {
    s.len() == 23 && s[0] == OP_HASH160 && s[1] == 0x14 && s[22] == OP_EQUAL
}

fn is_p2pkh(s: &[u8]) -> bool {
    s.len() == 25
        && s[0] == OP_DUP
        && s[1] == OP_HASH160
        && s[2] == 0x14
        && s[23] == OP_EQUALVERIFY
        && s[24] == OP_CHECKSIG
}

/// Bare `<key> OP_CHECKSIG` with a 33- or 65-byte key.
fn is_p2pk(s: &[u8]) -> bool {
    let Some(&push_len) = s.first() else {
        return false;
    };
    let key_len = match push_len {
        33 | 65 => usize::from(push_len),
        _ => return false,
    };
    s.len() == key_len + 2
        && s[key_len + 1] == OP_CHECKSIG
        && is_valid_pubkey_size(&s[1..=key_len])
}

/// Parses `OP_m <pubkey>... OP_n OP_CHECKMULTISIG`. Returns `(m, n)`.
fn match_multisig(s: &[u8]) -> Option<(u8, u8)> {
    if s.last() != Some(&OP_CHECKMULTISIG) {
        return None;
    }
    let mut pos = 0;
    let (op, _) = next_op(s, &mut pos)?;
    let required = small_int(op)?;

    let mut keys = 0usize;
    // The first non-key op is OP_n.
    let total_op = loop {
        let (op, data) = next_op(s, &mut pos)?;
        if !is_valid_pubkey_size(data) {
            break op;
        }
        keys += 1;
    };
    let total = small_int(total_op)?;
    // Only OP_CHECKMULTISIG may follow OP_n.
    if usize::from(total) != keys || pos + 1 != s.len() {
        return None;
    }
    Some((required, total))
}

/// Mirrors `Solver`: classifies a scriptPubKey without executing it.
pub fn solve(script: &ScriptBuf) -> TxoutType {
    let s = script.as_bytes();

    if is_p2sh(s) {
        return TxoutType::ScriptHash;
    }
    if let Some((version, program)) = witness_program(s) {
        return match (version, program.len()) {
            (0, 20) => TxoutType::WitnessV0KeyHash,
            (0, 32) => TxoutType::WitnessV0ScriptHash,
            (1, 32) => TxoutType::WitnessV1Taproot,
            _ if s == P2A_SCRIPT => TxoutType::Anchor,
            (v, _) if v != 0 => TxoutType::WitnessUnknown,
            _ => TxoutType::NonStandard,
        };
    }
    if s.first() == Some(&OP_RETURN) && is_push_only(&s[1..]) {
        return TxoutType::NullData;
    }
    if is_p2pk(s) {
        return TxoutType::PubKey;
    }
    if is_p2pkh(s) {
        return TxoutType::PubKeyHash;
    }
    if let Some((required, total)) = match_multisig(s) {
        return TxoutType::MultiSig { required, total };
    }
    TxoutType::NonStandard
}

/// Mirrors `IsStandard(scriptPubKey, whichType)`. Returns the script type if
/// the script is standard, or `None` otherwise.
///
/// Bare multisig is standard only for `1 <= m <= n <= 3`. Whether it is
/// allowed in a transaction is a separate option (`permit_bare_multisig`).
pub fn is_standard_script_pubkey(script: &ScriptBuf) -> Option<TxoutType> {
    let kind = solve(script);
    match kind {
        TxoutType::NonStandard => None,
        TxoutType::MultiSig { required, total } => {
            ((1..=3).contains(&total) && (1..=total).contains(&required)).then_some(kind)
        }
        _ => Some(kind),
    }
}

/// Core's `GetVirtualTransactionSize` without the sigop adjustment:
/// the weight divided by 4, rounded up.
pub fn get_virtual_transaction_size(weight: i64) -> i64 {
    (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR
}

/// Mirrors `GetTransactionWeight`: stripped size * 3 + total size.
pub fn get_transaction_weight(tx: &Tx) -> i64 {
    let mut stripped: Vec<u8> = Vec::new();
    let stripped_len = tx
        .encode_with(&mut stripped, false)
        .expect("in-memory writers cannot fail") as i64;
    stripped_len * (WITNESS_SCALE_FACTOR - 1) + tx.total_size() as i64
}

/// Fee in satoshis for `vsize` vbytes at `fee_rate_per_kvb`, rounded up
/// (`CFeeRate::GetFee`).
pub fn fee_for_vsize(fee_rate_per_kvb: u32, vsize: i64) -> i64 {
    (i64::from(fee_rate_per_kvb) * vsize + 999) / 1000
}

/// CompactSize length prefix for `n`.
fn compact_size_len(n: usize) -> i64 {
    match n as u64 {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// `GetSerializeSize(txout)`: 8-byte value, CompactSize script length, script.
fn serialized_txout_size(txout: &TxOut) -> i64 {
    let script_len = txout.script_pubkey.as_bytes().len();
    8 + compact_size_len(script_len) + script_len as i64
}

/// Mirrors `GetDustThreshold`: the smallest value that is not dust, in satoshis.
/// Output size plus the estimated size to spend it, priced at `fee_rate_per_kvb`.
pub fn get_dust_threshold(txout: &TxOut, fee_rate_per_kvb: u32) -> i64 {
    if is_unspendable(txout.script_pubkey.as_bytes()) {
        return 0;
    }
    // Spending input size. Segwit inputs get the witness discount on the 107-byte
    // P2WPKH witness. Taproot uses the same estimate, as in Core.
    let spend_size = if witness_program(txout.script_pubkey.as_bytes()).is_some() {
        32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4
    } else {
        32 + 4 + 1 + 107 + 4
    };
    fee_for_vsize(fee_rate_per_kvb, serialized_txout_size(txout) + spend_size)
}

/// Mirrors `IsDust`.
pub fn is_dust(txout: &TxOut, fee_rate_per_kvb: u32) -> bool {
    txout.value < get_dust_threshold(txout, fee_rate_per_kvb)
}

/// Mirrors `GetDust`: indices of dust outputs.
pub fn get_dust(tx: &Tx, fee_rate_per_kvb: u32) -> Vec<usize> {
    tx.vout
        .iter()
        .enumerate()
        .filter(|(_, out)| is_dust(out, fee_rate_per_kvb))
        .map(|(index, _)| index)
        .collect()
}

/// Mirrors `IsStandardTx` with explicit options. Checks run in Core's order.
pub fn is_standard_tx_with(tx: &Tx, opts: &StandardnessOptions) -> Result<(), StandardnessError> {
    if !(TX_MIN_STANDARD_VERSION..=TX_MAX_STANDARD_VERSION).contains(&tx.version) {
        return Err(StandardnessError::Version(tx.version));
    }

    let weight = get_transaction_weight(tx);
    if weight > MAX_STANDARD_TX_WEIGHT {
        return Err(StandardnessError::TxSize(weight));
    }

    for (index, txin) in tx.vin.iter().enumerate() {
        let script_sig = txin.script_sig.as_bytes();
        if script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(StandardnessError::ScriptSigSize {
                index,
                size: script_sig.len(),
            });
        }
        if !is_push_only(script_sig) {
            return Err(StandardnessError::ScriptSigNotPushOnly { index });
        }
    }

    let mut datacarrier_left = opts.max_datacarrier_bytes.unwrap_or(0) as usize;
    for (index, txout) in tx.vout.iter().enumerate() {
        let kind = is_standard_script_pubkey(&txout.script_pubkey)
            .ok_or(StandardnessError::ScriptPubKey { index })?;
        match kind {
            TxoutType::NullData => {
                let size = txout.script_pubkey.as_bytes().len();
                if size > datacarrier_left {
                    return Err(StandardnessError::DataCarrier { index });
                }
                datacarrier_left -= size;
            }
            TxoutType::MultiSig { .. } if !opts.permit_bare_multisig => {
                return Err(StandardnessError::BareMultisig { index });
            }
            _ => {}
        }
    }

    let dust = get_dust(tx, opts.dust_relay_fee_per_kvb);
    if dust.len() > MAX_DUST_OUTPUTS_PER_TX {
        return Err(StandardnessError::Dust { count: dust.len() });
    }
    Ok(())
}

/// `IsStandardTx` with Core's default options.
pub fn is_standard_tx(tx: &Tx) -> Result<(), StandardnessError> {
    is_standard_tx_with(tx, &StandardnessOptions::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::TxIn;

    fn p2pkh() -> ScriptBuf {
        let mut s = vec![OP_DUP, OP_HASH160, 0x14];
        s.extend([0x11; 20]);
        s.extend([OP_EQUALVERIFY, OP_CHECKSIG]);
        ScriptBuf::from_bytes(s)
    }

    fn p2sh() -> ScriptBuf {
        let mut s = vec![OP_HASH160, 0x14];
        s.extend([0x11; 20]);
        s.push(OP_EQUAL);
        ScriptBuf::from_bytes(s)
    }

    fn witness_script(version_op: u8, program: &[u8]) -> ScriptBuf {
        let mut s = vec![version_op, program.len() as u8];
        s.extend_from_slice(program);
        ScriptBuf::from_bytes(s)
    }

    fn p2wpkh() -> ScriptBuf {
        witness_script(OP_0, &[0x11; 20])
    }

    fn p2wsh() -> ScriptBuf {
        witness_script(OP_0, &[0x11; 32])
    }

    fn p2tr() -> ScriptBuf {
        witness_script(OP_1, &[0x11; 32])
    }

    /// `data` must be under 76 bytes so a single-byte push length is enough.
    fn op_return(data: &[u8]) -> ScriptBuf {
        let mut s = vec![OP_RETURN, data.len() as u8];
        s.extend_from_slice(data);
        ScriptBuf::from_bytes(s)
    }

    fn bare_multisig(required: u8, keys: usize) -> ScriptBuf {
        let mut s = vec![OP_1 - 1 + required];
        for _ in 0..keys {
            s.push(33);
            s.push(0x02);
            s.extend([0x11; 32]);
        }
        s.push(OP_1 - 1 + keys as u8);
        s.push(OP_CHECKMULTISIG);
        ScriptBuf::from_bytes(s)
    }

    fn tx_with(outputs: Vec<TxOut>) -> Tx {
        Tx::new(2, vec![TxIn::default()], outputs, 0)
    }

    #[test]
    fn dust_thresholds_match_core() {
        let rate = DUST_RELAY_TX_FEE;

        // 546 sat for P2PKH and 294 sat for P2WPKH at 3000 sat/kvB (policy.cpp comments).
        let pkh = TxOut::new(545, p2pkh());
        assert_eq!(get_dust_threshold(&pkh, rate), 546);
        assert!(is_dust(&pkh, rate));
        assert!(!is_dust(&TxOut::new(546, p2pkh()), rate));

        assert_eq!(get_dust_threshold(&TxOut::new(0, p2wpkh()), rate), 294);
        assert_eq!(get_dust_threshold(&TxOut::new(0, p2sh()), rate), 540);
        assert_eq!(get_dust_threshold(&TxOut::new(0, p2tr()), rate), 330);

        // Unspendable outputs have a zero threshold and are never dust.
        let null = TxOut::new(0, op_return(b"x"));
        assert_eq!(get_dust_threshold(&null, rate), 0);
        assert!(!is_dust(&null, rate));
    }

    #[test]
    fn script_classification() {
        assert_eq!(solve(&p2pkh()), TxoutType::PubKeyHash);
        assert_eq!(solve(&p2sh()), TxoutType::ScriptHash);
        assert_eq!(solve(&p2wpkh()), TxoutType::WitnessV0KeyHash);
        assert_eq!(solve(&p2wsh()), TxoutType::WitnessV0ScriptHash);
        assert_eq!(solve(&p2tr()), TxoutType::WitnessV1Taproot);
        assert_eq!(
            solve(&ScriptBuf::from_bytes(P2A_SCRIPT.to_vec())),
            TxoutType::Anchor
        );
        assert_eq!(solve(&op_return(b"hello")), TxoutType::NullData);
        // Unknown witness version 2 is standard (WITNESS_UNKNOWN).
        assert_eq!(
            solve(&witness_script(OP_1 + 1, &[0xab, 0xcd])),
            TxoutType::WitnessUnknown
        );
        // Witness v0 with a non-20/32-byte program is not a template.
        assert_eq!(
            solve(&witness_script(OP_0, &[0x11; 25])),
            TxoutType::NonStandard
        );

        // Bare multisig is standard for 1 <= m <= n <= 3 only.
        assert_eq!(
            is_standard_script_pubkey(&bare_multisig(1, 3)),
            Some(TxoutType::MultiSig { required: 1, total: 3 })
        );
        assert_eq!(is_standard_script_pubkey(&bare_multisig(1, 4)), None);
        assert_eq!(is_standard_script_pubkey(&bare_multisig(2, 1)), None);

        // A bare OP_1 is not a recognised template.
        assert_eq!(is_standard_script_pubkey(&ScriptBuf::from_bytes(vec![OP_1])), None);
    }

    #[test]
    fn standardness_rejections() {
        let ok_out = TxOut::new(10_000, p2wpkh());
        assert_eq!(is_standard_tx(&tx_with(vec![ok_out.clone()])), Ok(()));

        // Versions 1..=3 are standard.
        for version in [0u32, 4] {
            let tx = Tx::new(version, vec![TxIn::default()], vec![ok_out.clone()], 0);
            assert_eq!(is_standard_tx(&tx), Err(StandardnessError::Version(version)));
        }
        let v3 = Tx::new(3, vec![TxIn::default()], vec![ok_out.clone()], 0);
        assert_eq!(is_standard_tx(&v3), Ok(()));

        // One dust output is allowed (ephemeral dust); two are not.
        let dust = TxOut::new(545, p2pkh());
        assert_eq!(is_standard_tx(&tx_with(vec![dust.clone()])), Ok(()));
        assert_eq!(
            is_standard_tx(&tx_with(vec![dust.clone(), dust])),
            Err(StandardnessError::Dust { count: 2 })
        );

        let weird = TxOut::new(10_000, ScriptBuf::from_bytes(vec![OP_1]));
        assert_eq!(
            is_standard_tx(&tx_with(vec![weird])),
            Err(StandardnessError::ScriptPubKey { index: 0 })
        );

        // OP_RETURN outputs share one byte budget. Each script here is 62 bytes.
        let small_budget = StandardnessOptions {
            max_datacarrier_bytes: Some(70),
            ..Default::default()
        };
        let null = TxOut::new(0, op_return(&[0x22; 60]));
        assert_eq!(
            is_standard_tx_with(&tx_with(vec![null.clone(), null.clone()]), &small_budget),
            Err(StandardnessError::DataCarrier { index: 1 })
        );
        assert_eq!(
            is_standard_tx_with(&tx_with(vec![null.clone()]), &small_budget),
            Ok(())
        );
        let no_data = StandardnessOptions {
            max_datacarrier_bytes: None,
            ..Default::default()
        };
        assert_eq!(
            is_standard_tx_with(&tx_with(vec![null]), &no_data),
            Err(StandardnessError::DataCarrier { index: 0 })
        );

        // Bare multisig is permitted by default, and rejected when turned off.
        let ms = TxOut::new(10_000, bare_multisig(1, 3));
        assert_eq!(is_standard_tx(&tx_with(vec![ms.clone()])), Ok(()));
        let no_multisig = StandardnessOptions {
            permit_bare_multisig: false,
            ..Default::default()
        };
        assert_eq!(
            is_standard_tx_with(&tx_with(vec![ms]), &no_multisig),
            Err(StandardnessError::BareMultisig { index: 0 })
        );

        // OP_DUP in a scriptSig is not push-only.
        let mut input = TxIn::default();
        input.script_sig = ScriptBuf::from_bytes(vec![OP_1, OP_DUP]);
        let tx = Tx::new(2, vec![input], vec![ok_out], 0);
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::ScriptSigNotPushOnly { index: 0 })
        );
    }

    #[test]
    fn weight_and_vsize() {
        let plain = tx_with(vec![TxOut::new(10_000, p2wpkh())]);
        assert!(!plain.has_witness());
        // Without witness data, weight is exactly 4x the serialized size.
        assert_eq!(get_transaction_weight(&plain), 4 * plain.total_size() as i64);

        // Witness bytes count 1 WU each, so a 400k-byte witness exceeds the limit.
        let mut heavy = TxIn::default();
        heavy.witness.push(vec![0u8; 400_000]);
        let tx = Tx::new(2, vec![heavy], vec![TxOut::new(10_000, p2wpkh())], 0);
        assert!(get_transaction_weight(&tx) > MAX_STANDARD_TX_WEIGHT);
        assert!(matches!(
            is_standard_tx(&tx),
            Err(StandardnessError::TxSize(_))
        ));

        assert_eq!(get_virtual_transaction_size(400_000), 100_000);
        assert_eq!(get_virtual_transaction_size(400_001), 100_001);
        assert_eq!(get_virtual_transaction_size(1), 1);
        assert_eq!(get_virtual_transaction_size(0), 0);
    }
}
