//! Integration test: Core's script_tests.json evaluated against btc-script's verify_script.
//! Vector format: [witness..., amount_btc]?, scriptSig_asm, scriptPubKey_asm, flags, expected, ...comments]
//! Evaluation mirrors Core's script_tests.cpp: a credit transaction (coinbase-like, version 1,
//! SEQUENCE_FINAL inputs, OP_0 OP_0 scriptSig, one output with the given amount and scriptPubKey),
//! then a spending transaction spending that output. VerifyScript is called with the given flags.

use btc_primitives::{Tx, TxIn, TxOut};
use btc_script::checker::TransactionSignatureChecker;
use btc_script::{verify_script, ScriptError, ScriptVerifyFlags};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Witness};
use bitcoin::secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};
use bitcoin_hashes::{sha256, Hash};

const TAG_TAP_TWEAK: &[u8] = b"TapTweak";
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
// Internal key for the taproot test vectors is the x-only generator point (sec1 private key = 1),
// which matches the test KeyData key0 used to build the taproot vectors.
const INTERNAL_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
    0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
    0x16, 0xf8, 0x17, 0x98,
];

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag);
    let mut buf = Vec::with_capacity(64 + data.len());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(data);
    sha256::Hash::hash(&buf).to_byte_array()
}

fn tapleaf_hash(script: &[u8]) -> [u8; 32] {
    // TAPROOT_LEAF_TAPSCRIPT, depth 0. Leaf hash = tagged TapLeaf of (leaf_version || CompactSize(script) || script).
    let mut buf = Vec::with_capacity(script.len() + 10);
    buf.push(TAPROOT_LEAF_TAPSCRIPT);
    if script.len() < 253 {
        buf.push(script.len() as u8);
    } else if script.len() <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(script.len() as u16).to_le_bytes());
    } else {
        buf.push(0xfe);
        buf.extend_from_slice(&(script.len() as u32).to_le_bytes());
    }
    buf.extend_from_slice(script);
    tagged_hash(b"TapLeaf", &buf)
}

fn taproot_tweak_and_parity(tapleaf_hash: [u8; 32]) -> ([u8; 32], u8) {
    let internal = XOnlyPublicKey::from_slice(&INTERNAL_X).expect("generator x is valid");
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&INTERNAL_X);
    buf.extend_from_slice(&tapleaf_hash);
    let tweak32 = tagged_hash(TAG_TAP_TWEAK, &buf);
    let tweak = Scalar::from_be_bytes(tweak32).expect("tweak in range");
    let secp = Secp256k1::verification_only();
    let (tweaked, parity) = internal.add_tweak(&secp, &tweak).expect("tweak verifies");
    (tweaked.serialize(), parity.to_u8())
}


use btc_script::opcodes::*;

fn opcodes_table() -> &'static [(&'static str, u8)] {
    &[
        ("0NOTEQUAL", OP_0NOTEQUAL), ("1ADD", OP_1ADD), ("1SUB", OP_1SUB),
        ("2DIV", OP_2DIV), ("2DROP", OP_2DROP), ("2DUP", OP_2DUP),
        ("2MUL", OP_2MUL), ("2OVER", OP_2OVER), ("2ROT", OP_2ROT), ("2SWAP", OP_2SWAP),
        ("3DUP", OP_3DUP), ("ABS", OP_ABS), ("ADD", OP_ADD),
        ("AND", OP_AND), ("BOOLAND", OP_BOOLAND), ("BOOLOR", OP_BOOLOR),
        ("CAT", OP_CAT),
        ("CHECKLOCKTIMEVERIFY", OP_CHECKLOCKTIMEVERIFY),
        ("CHECKMULTISIG", OP_CHECKMULTISIG),
        ("CHECKMULTISIGVERIFY", OP_CHECKMULTISIGVERIFY),
        ("CHECKSEQUENCEVERIFY", OP_CHECKSEQUENCEVERIFY),
        ("CHECKSIG", OP_CHECKSIG), ("CHECKSIGVERIFY", OP_CHECKSIGVERIFY),
        ("CODESEPARATOR", OP_CODESEPARATOR),
        ("DEPTH", OP_DEPTH), ("DIV", OP_DIV), ("DROP", OP_DROP), ("DUP", OP_DUP),
        ("ELSE", OP_ELSE), ("ENDIF", OP_ENDIF),
        ("EQUAL", OP_EQUAL), ("EQUALVERIFY", OP_EQUALVERIFY),
        ("FROMALTSTACK", OP_FROMALTSTACK),
        ("GREATERTHAN", OP_GREATERTHAN), ("GREATERTHANOREQUAL", OP_GREATERTHANOREQUAL),
        ("HASH160", OP_HASH160), ("HASH256", OP_HASH256),
        ("IF", OP_IF), ("IFDUP", OP_IFDUP), ("INVERT", OP_INVERT),
        ("LEFT", OP_LEFT), ("LESSTHAN", OP_LESSTHAN),
        ("LESSTHANOREQUAL", OP_LESSTHANOREQUAL), ("LSHIFT", OP_LSHIFT),
        ("MAX", OP_MAX), ("MIN", OP_MIN), ("MOD", OP_MOD), ("MUL", OP_MUL),
        ("NEGATE", OP_NEGATE), ("NIP", OP_NIP), ("NOP", OP_NOP),
        ("NOP1", OP_NOP1), ("NOP10", OP_NOP10), ("NOP4", OP_NOP4), ("NOP5", OP_NOP5),
        ("NOP6", OP_NOP6), ("NOP7", OP_NOP7), ("NOP8", OP_NOP8), ("NOP9", OP_NOP9),
        ("NOT", OP_NOT), ("NOTIF", OP_NOTIF),
        ("NUMEQUAL", OP_NUMEQUAL), ("NUMEQUALVERIFY", OP_NUMEQUALVERIFY),
        ("NUMNOTEQUAL", OP_NUMNOTEQUAL),
        ("OR", OP_OR), ("OVER", OP_OVER), ("PICK", OP_PICK),
        ("RESERVED", OP_RESERVED), ("RESERVED1", OP_RESERVED1), ("RESERVED2", OP_RESERVED2),
        ("RETURN", OP_RETURN), ("RIGHT", OP_RIGHT),
        ("RIPEMD160", OP_RIPEMD160), ("ROLL", OP_ROLL), ("ROT", OP_ROT), ("RSHIFT", OP_RSHIFT),
        ("SHA1", OP_SHA1), ("SHA256", OP_SHA256), ("SIZE", OP_SIZE),
        ("SUB", OP_SUB), ("SUBSTR", OP_SUBSTR), ("SWAP", OP_SWAP),
        ("TOALTSTACK", OP_TOALTSTACK), ("TUCK", OP_TUCK),
        ("VER", OP_VER), ("VERIF", OP_VERIF), ("VERIFY", OP_VERIFY), ("VERNOTIF", OP_VERNOTIF),
        ("WITHIN", OP_WITHIN), ("XOR", OP_XOR),
    ]
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn encode_minimal_number(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    let last = out.len() - 1;
    if out[last] & 0x80 != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        out[last] |= 0x80;
    }
    out
}

/// Parse Core's script-asm notation: opcode names, decimal numbers (push minimal),
/// and raw bytes via 0x-prefixed hex tokens.
fn parse_asm(asm: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for tok in asm.split(' ').map(str::trim).filter(|t| !t.is_empty()) {
        if tok.len() >= 2 && tok.starts_with('\'') && tok.ends_with('\'') {
            // Single-quoted literal: push the raw bytes of the inner string.
            let inner = &tok[1..tok.len() - 1];
            let bytes = inner.as_bytes();
            if bytes.len() <= 75 {
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            } else if bytes.len() <= 255 {
                out.push(0x4c);
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            } else {
                out.push(0x4d);
                out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            continue;
        }
        if let Some(hex) = tok.strip_prefix("0x") {
            match hex_decode(hex) {
                Some(bytes) => out.extend_from_slice(&bytes),
                None => panic!("bad hex token: {tok}"),
            }
            continue;
        }
        if let Ok(num) = tok.parse::<i64>() {
            // Decimal number: pushed via CScript << int64_t semantics:
            // -1 -> OP_1NEGATE, 0 -> OP_0, 1..16 -> OP_1..OP_16, else minimal ScriptNum serialization.
            match num {
                -1 => out.push(OP_1NEGATE),
                0 => out.push(OP_0),
                1..=16 => out.push((0x50 + num) as u8),
                _ => {
                    let bytes = encode_minimal_number(num);
                    if bytes.len() <= 75 {
                        out.push(bytes.len() as u8);
                        out.extend_from_slice(&bytes);
                    } else if bytes.len() <= 255 {
                        out.push(0x4c);
                        out.push(bytes.len() as u8);
                        out.extend_from_slice(&bytes);
                    } else {
                        out.push(0x4d);
                        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                        out.extend_from_slice(&bytes);
                    }
                }
            }
            continue;
        }
        match opcodes_table().iter().find(|(name, _)| *name == tok) {
            Some((_, op)) => out.push(*op),
            None => panic!("unknown asm token: {tok}"),
        }
    }
    out
}

fn parse_flags(s: &str) -> ScriptVerifyFlags {
    let mut flags = ScriptVerifyFlags::NONE;
    if s.trim().is_empty() {
        return flags;
    }
    for raw in s.split(',') {
        let name = raw.trim();
        let f = match name {
            "P2SH" => ScriptVerifyFlags::P2SH,
            "STRICTENC" => ScriptVerifyFlags::STRICTENC,
            "DERSIG" => ScriptVerifyFlags::DERSIG,
            "LOW_S" => ScriptVerifyFlags::LOW_S,
            "SIGPUSHONLY" => ScriptVerifyFlags::SIGPUSHONLY,
            "MINIMALDATA" => ScriptVerifyFlags::MINIMALDATA,
            "NULLDUMMY" => ScriptVerifyFlags::NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" => ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => ScriptVerifyFlags::CLEANSTACK,
            "MINIMALIF" => ScriptVerifyFlags::MINIMALIF,
            "NULLFAIL" => ScriptVerifyFlags::NULLFAIL,
            "CHECKLOCKTIMEVERIFY" => ScriptVerifyFlags::CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => ScriptVerifyFlags::CHECKSEQUENCEVERIFY,
            "WITNESS" => ScriptVerifyFlags::WITNESS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            "WITNESS_PUBKEYTYPE" => ScriptVerifyFlags::WITNESS_PUBKEYTYPE,
            "CONST_SCRIPTCODE" => ScriptVerifyFlags::CONST_SCRIPTCODE,
            "TAPROOT" => ScriptVerifyFlags::TAPROOT,
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
            "DISCOURAGE_OP_SUCCESS" => ScriptVerifyFlags::DISCOURAGE_OP_SUCCESS,
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => ScriptVerifyFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
            other => panic!("unknown flag: {other}"),
        };
        flags |= f;
    }
    flags
}

fn map_error(s: &str) -> ScriptError {
    match s {
        "OK" => ScriptError::Ok,
        "BAD_OPCODE" => ScriptError::BadOpcode,
        "CHECKMULTISIGVERIFY" => ScriptError::CheckMultisigVerify,
        "CHECKSIGVERIFY" => ScriptError::CheckSigVerify,
        "CLEANSTACK" => ScriptError::Cleanstack,
        "DISABLED_OPCODE" => ScriptError::DisabledOpcode,
        "DISCOURAGE_UPGRADABLE_NOPS" => ScriptError::DiscourageUpgradableNops,
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => ScriptError::DiscourageUpgradableWitnessProgram,
        "EQUALVERIFY" => ScriptError::EqualVerify,
        "EVAL_FALSE" => ScriptError::EvalFalse,
        "INVALID_ALTSTACK_OPERATION" => ScriptError::InvalidAltstackOperation,
        "INVALID_STACK_OPERATION" => ScriptError::InvalidStackOperation,
        "MINIMALDATA" => ScriptError::Minimaldata,
        "MINIMALIF" => ScriptError::Minimalif,
        "NEGATIVE_LOCKTIME" => ScriptError::NegativeLocktime,
        "NULLFAIL" => ScriptError::SigNullfail,
        "NUMEQUALVERIFY" => ScriptError::NumEqualVerify,
        "OP_CODESEPARATOR" => ScriptError::OpCodeseparator,
        "OP_COUNT" => ScriptError::OpCount,
        "OP_RETURN" => ScriptError::OpReturn,
        "PUBKEYTYPE" => ScriptError::Pubkeytype,
        "PUBKEY_COUNT" => ScriptError::PubkeyCount,
        "PUSH_SIZE" => ScriptError::PushSize,
        "SCRIPTNUM" => ScriptError::ScriptNum,
        "SCRIPT_SIZE" => ScriptError::ScriptSize,
        "SIG_COUNT" => ScriptError::SigCount,
        "SIG_DER" => ScriptError::SigDer,
        "SIG_FINDANDDELETE" => ScriptError::SigFindanddelete,
        "SIG_HASHTYPE" => ScriptError::SigHashtype,
        "SIG_HIGH_S" => ScriptError::SigHighS,
        "SIG_NULLDUMMY" => ScriptError::SigNulldummy,
        "SIG_PUSHONLY" => ScriptError::SigPushonly,
        "STACK_SIZE" => ScriptError::StackSize,
        "TAPSCRIPT_EMPTY_PUBKEY" => ScriptError::TapscriptEmptyPubkey,
        "TAPSCRIPT_MINIMALIF" => ScriptError::TapscriptMinimalif,
        "UNBALANCED_CONDITIONAL" => ScriptError::UnbalancedConditional,
        "UNSATISFIED_LOCKTIME" => ScriptError::UnsatisfiedLocktime,
        "VERIFY" => ScriptError::Verify,
        "WITNESS_MALLEATED" => ScriptError::WitnessMalleated,
        "WITNESS_MALLEATED_P2SH" => ScriptError::WitnessMalleatedP2sh,
        "WITNESS_PROGRAM_MISMATCH" => ScriptError::WitnessProgramMismatch,
        "WITNESS_PROGRAM_WITNESS_EMPTY" => ScriptError::WitnessProgramWitnessEmpty,
        "WITNESS_PROGRAM_WRONG_LENGTH" => ScriptError::WitnessProgramWrongLength,
        "WITNESS_PUBKEYTYPE" => ScriptError::WitnessPubkeytype,
        "WITNESS_UNEXPECTED" => ScriptError::WitnessUnexpected,
        other => panic!("unknown error string: {other}"),
    }
}

struct Vector {
    script_sig: Vec<u8>,
    script_pubkey: Vec<u8>,
    witness: Vec<Vec<u8>>,
    amount: i64,
    flags: ScriptVerifyFlags,
    expected: ScriptError,
}

fn parse_vectors(raw: &str) -> Vec<Vector> {
    let json: serde_json::Value = serde_json::from_str(raw).expect("parse json");
    let arr = json.as_array().expect("top-level array");
    let mut out = Vec::new();
    for v in arr {
        let a = match v.as_array() {
            // Vectors are either [scriptSig, scriptPubKey, flags, expected] or
            // [[witness..., amount], scriptSig, scriptPubKey, flags, expected].
            Some(a) if a.len() >= 4 && (a[0].is_string() || a[0].is_array()) => a,
            _ => continue,
        };
        let (script_sig_asm, script_pubkey, witness, amount, flags_asm, expected) =
            if a[0].is_array() {
                // [[witness..., amount_btc], scriptSig, scriptPubKey, flags, expected]
                let wit_arr = a[0].as_array().unwrap();
                let mut amount = 0i64;
                let mut witness: Vec<Vec<u8>> = Vec::new();
                let mut tapscript: Option<Vec<u8>> = None;
                for (i, item) in wit_arr.iter().enumerate() {
                    let last = i == wit_arr.len() - 1;
                    if last && item.is_number() {
                        amount = (item.as_f64().unwrap() * 100_000_000.0).round() as i64;
                    } else if let Some(s) = item.as_str() {
                        if let Some(asm) = s.strip_prefix("#SCRIPT# ") {
                            let script = parse_asm(asm);
                            witness.push(script.clone());
                            tapscript = Some(script);
                        } else if s == "#CONTROLBLOCK#" {
                            // Auto-generated control block for single-leaf taproot script-path spends.
                            let script = witness.last().expect("tapscript must be pushed before #CONTROLBLOCK#").clone();
                            let leaf = tapleaf_hash(&script);
                            let (_tweaked, parity) = taproot_tweak_and_parity(leaf);
                            let mut control = vec![TAPROOT_LEAF_TAPSCRIPT | parity];
                            control.extend_from_slice(&INTERNAL_X);
                            witness.push(control);
                        } else {
                            witness.push(hex_decode(s).expect("witness hex"));
                        }
                    } else {
                        panic!("unexpected witness item: {item}");
                    }
                }
                let spk_asm = a[2].as_str().expect("scriptPubKey asm");
                let script_pubkey_bytes = if spk_asm == "0x51 0x20 #TAPROOTOUTPUT#" {
                    let leaf = tapleaf_hash(tapscript.as_ref().expect("#TAPROOTOUTPUT# requires #SCRIPT#"));
                    let (tweaked, _parity) = taproot_tweak_and_parity(leaf);
                    let mut spk = vec![OP_1, 0x20];
                    spk.extend_from_slice(&tweaked);
                    spk
                } else {
                    parse_asm(spk_asm)
                };
                (
                    a[1].as_str().expect("scriptSig asm").to_string(),
                    script_pubkey_bytes,
                    witness,
                    amount,
                    a[3].as_str().expect("flags").to_string(),
                    a[4].as_str().expect("expected").to_string(),
                )
            } else {
                (
                    a[0].as_str().expect("scriptSig asm").to_string(),
                    parse_asm(a[1].as_str().expect("scriptPubKey asm")),
                    Vec::new(),
                    0,
                    a[2].as_str().expect("flags").to_string(),
                    a[3].as_str().expect("expected").to_string(),
                )
            };
        out.push(Vector {
            script_sig: parse_asm(&script_sig_asm),
            script_pubkey,
            witness,
            amount,
            flags: parse_flags(&flags_asm),
            expected: map_error(&expected),
        });
    }
    out
}

fn crediting_transaction(script_pubkey: &[u8], amount: i64) -> Tx {
    let coinbase_input = TxIn {
        prevout: OutPoint::null(),
        script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
        sequence: Sequence(u32::MAX),
        witness: Witness::new(),
    };
    Tx::new(
        1,
        vec![coinbase_input],
        vec![TxOut::new(amount, ScriptBuf::from_bytes(script_pubkey.to_vec()))],
        0,
    )
}

fn spending_transaction(tx_credit: &Tx, script_sig: &[u8], witness: &[Vec<u8>]) -> Tx {
    let mut wit = Witness::new();
    for item in witness {
        wit.push(item);
    }
    let spend_input = TxIn {
        prevout: OutPoint { txid: tx_credit.txid(), vout: 0 },
        script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
        sequence: Sequence(u32::MAX),
        witness: wit,
    };
    Tx::new(
        1,
        vec![spend_input],
        vec![TxOut::new(tx_credit.vout[0].value, ScriptBuf::new())],
        0,
    )
}

#[test]
fn script_tests() {
    let raw = include_str!("data/script_tests.json");
    let vectors = parse_vectors(raw);

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for v in &vectors {
        total += 1;
        let tx_credit = crediting_transaction(&v.script_pubkey, v.amount);
        let tx_spend = spending_transaction(&tx_credit, &v.script_sig, &v.witness);
        let spent_outputs = vec![TxOut {
            value: tx_credit.vout[0].value,
            script_pubkey: tx_credit.vout[0].script_pubkey.clone(),
        }];
        let checker = TransactionSignatureChecker::new(&tx_spend, 0, &spent_outputs);
        let result = verify_script(
            &v.script_sig,
            &v.script_pubkey,
            &v.witness,
            v.flags,
            &checker,
        );
        let ok = match (&result, &v.expected) {
            (Ok(()), ScriptError::Ok) => true,
            (Err(e), expected) => e == expected,
            _ => false,
        };
        if ok {
            passed += 1;
        } else {
            failures.push(format!(
                "scriptSig={:?} scriptPubKey={:?} witness={:?} flags={:?} expected={} got={:?}",
                v.script_sig, v.script_pubkey, v.witness, v.flags, v.expected, result
            ));
        }
    }

    println!("TOTAL {total} PASS {passed} FAIL {}", total - passed);
    for line in &failures {
        println!("{line}");
    }
    assert_eq!(passed, total, "script_tests failed");
}


