//! Shielded pool notes (Privacy Plan, Phase 3, pre-zk milestone).
//!
//! A note is `(spending_pub, value, rcm)`. Its commitment is
//! `cmu = SHA256("AnonCoin-NOTE-v1" || spending_pub || value_le || rcm)`:
//! with the random `rcm` nobody can guess or verify a note's contents
//! without its secrets. Commitments are inserted into an incremental
//! Merkle tree (depth 32); a spend publishes an anchor root, the
//! Merkle proof, and a nullifier `nf = SHA256("AnonCoin-NF-v1" || rcm)`
//! so the same note cannot be spent twice.
//!
//! Spending authorisation is a Schnorr signature with the spending
//! secret **over the note commitment, anchor, nullifier and context**
//! — the owner proves control of the address embedded in the note.
//! Everything that was hidden (value, owner) stays hidden; an observer
//! sees only `cmu`, the anchor they were included in, and `nf`.
//!
//! Anti-inflation (no SNARK needed for this invariant): note values
//! are revealed at spend, so the chain enforces a funding ledger —
//! issuance locks real UTXO value (`inputs - non-pool outputs`)
//! behind each `cmu` (`funding_caps_for_block`), and a spend may
//! claim at most its cap. The hash commitment (and, on
//! value-committed scripts, the Pedersen opening `value*G + rcm*H`)
//! pin the opening to the funded commitment. The zk-SNARK upgrade
//! path (Orchard-style) would hide the spent value itself, which
//! the funding ledger keeps transparent at spend time.

use std::collections::HashSet;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin_hashes::{sha256, Hash as _};
use thiserror::Error;

pub const NOTE_DEPTH: usize = 32;
const TAG_CMU: &[u8] = b"AnonCoin-NOTE-v1";
const TAG_NF: &[u8] = b"AnonCoin-NF-v1";
const TAG_AUTH: &[u8] = b"AnonCoin-SPENDAUTH-v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NoteError {
    #[error("invalid note")]
    Invalid,
    #[error("unknown anchor")]
    UnknownAnchor,
    #[error("note already spent")]
    DoubleSpend,
    #[error("bad spend authorization")]
    Authorization,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub spending_pub: [u8; 33],
    pub value: u64,
    pub rcm: [u8; 32],
}

/// Note commitment (the visible shielded-pool leaf).
pub fn note_commitment(note: &Note) -> [u8; 32] {
    let mut buf = Vec::with_capacity(33 + 33 + 8 + 32);
    buf.extend_from_slice(TAG_CMU);
    buf.extend_from_slice(&note.spending_pub);
    buf.extend_from_slice(&note.value.to_le_bytes());
    buf.extend_from_slice(&note.rcm);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Nullifier: reveals nothing about the note but is unique per rcm.
pub fn nullifier(note: &Note) -> [u8; 32] {
    let mut buf = Vec::with_capacity(TAG_NF.len() + 32);
    buf.extend_from_slice(TAG_NF);
    buf.extend_from_slice(&note.rcm);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Pool output script (legacy): `OP_RETURN PUSHDATA1(32) <cmu:32>`.
/// A leaf in the pool tree. The note value is bound only by the hash
/// commitment and the issuance funding ledger (see
/// [`funding_caps_for_block`]).
pub fn encode_pool_note(cmu: &[u8; 32]) -> Vec<u8> {
    let mut script = vec![0x6a, 0x4c, 32];
    script.extend_from_slice(cmu);
    script
}

/// Pool output script (value-committed):
/// `OP_RETURN PUSHDATA1(65) <cmu:32 || C:33>` where
/// `C = value*G + rcm*H` is the Pedersen value commitment
/// (`commitment_point(value, rcm)`). The spend opening reveals
/// `(value, rcm)`, so the chain can re-check `C` — a second binding
/// on top of the hash commitment. Total script: 68 bytes.
pub fn encode_pool_note_committed(cmu: &[u8; 32], commitment: &[u8; 33]) -> Vec<u8> {
    let mut script = vec![0x6a, 0x4c, 65];
    script.extend_from_slice(cmu);
    script.extend_from_slice(commitment);
    script
}

/// True if `script` is a pool note output script (legacy 35-byte,
/// value-committed 68-byte or Poseidon 100-byte form).
pub fn is_pool_script(script: &[u8]) -> bool {
    script.len() >= 3
        && script[0] == 0x6a
        && script[1] == 0x4c
        && ((script[2] == 32 && script.len() == 35)
            || (script[2] == 65 && script.len() == 68)
            || (script[2] == 97 && script.len() == 100))
}

/// Extracts the commitment from a pool note output script.
pub fn decode_pool_note(script: &[u8]) -> Option<[u8; 32]> {
    if !is_pool_script(script) {
        return None;
    }
    script[3..35].try_into().ok()
}

/// Extracts `(cmu, value_commitment)` — `None` commitment on legacy
/// 35-byte scripts.
pub fn decode_pool_note_full(script: &[u8]) -> Option<([u8; 32], Option<[u8; 33]>)> {
    let (cmu, pedersen, _) = decode_pool_script_full(script)?;
    Some((cmu, pedersen))
}

/// Full pool script contents: `(cmu, Pedersen commitment, Poseidon
/// preimage hash)`. Script shapes:
/// * 35B legacy: `OP_RETURN PUSHDATA1(32) <cmu>`
/// * 68B committed: `OP_RETURN PUSHDATA1(65) <cmu || C>`
/// * 100B Poseidon: `OP_RETURN PUSHDATA1(97)`
///   `<cmu || poseidon(32 canonical) || C(33)>`
pub fn decode_pool_script_full(
    script: &[u8],
) -> Option<([u8; 32], Option<[u8; 33]>, Option<[u8; 32]>)> {
    if !is_pool_script(script) {
        return None;
    }
    let cmu: [u8; 32] = script[3..35].try_into().ok()?;
    match script.len() {
        35 => Some((cmu, None, None)),
        68 => Some((cmu, Some(script[35..68].try_into().ok()?), None)),
        100 => Some((
            cmu,
            Some(script[67..100].try_into().ok()?),
            Some(script[35..67].try_into().ok()?),
        )),
        _ => None,
    }
}

/// Pool output script (Poseidon): `OP_RETURN PUSHDATA1(97)` with
/// `cmu || poseidon_cmu || Pedersen C`.
pub fn encode_pool_note_v3(
    cmu: &[u8; 32],
    poseidon: &[u8; 32],
    pedersen: &[u8; 33],
) -> Vec<u8> {
    let mut script = vec![0x6a, 0x4c, 97];
    script.extend_from_slice(cmu);
    script.extend_from_slice(poseidon);
    script.extend_from_slice(pedersen);
    script
}

/// Funding caps for the pool outputs created by one transaction:
/// `locked = sum(input ledger values) - sum(non-pool output values)`,
/// split evenly across the pool notes created (conservative for
/// multi-note creations: every note's cap is `locked / count`).
/// This is the anti-inflation ledger: issuance locks real UTXO value
/// behind each `cmu`, and a spend may claim at most its cap.
///
/// SNARK shielded spends (pool input + `witness[4]` public fee):
/// the locked value is the spent note's value minus the public fee
/// — the new note is funded by the proof, not by ledger values.
pub fn funding_caps_for_block(
    tx: &btc_primitives::Tx,
    input_values: &[i64],
) -> Vec<([u8; 32], u64)> {
    let pool_outs: Vec<[u8; 32]> = tx
        .vout
        .iter()
        .filter_map(|o| decode_pool_note(o.script_pubkey.as_bytes()))
        .collect();
    if pool_outs.is_empty() {
        return Vec::new();
    }
    let non_pool_out: i64 = tx
        .vout
        .iter()
        .filter(|o| !is_pool_script(o.script_pubkey.as_bytes()))
        .map(|o| o.value)
        .sum();
    // Shielded spend: fund from the revealed spent-note value minus
    // the public fee carried in witness[4].
    let spent_note_value: i64 = tx
        .vin
        .iter()
        .filter_map(|input| {
            input
                .witness
                .iter()
                .next()
                .and_then(|b| decode_note(b))
                .map(|n| n.value as i64)
        })
        .sum();
    let shield_fee = tx
        .vin
        .first()
        .and_then(|input| input.witness.iter().nth(4))
        .and_then(|b| decode_shield_fee(b));
    let locked: i64 = match shield_fee {
        Some(fee) if spent_note_value > 0 => spent_note_value - fee as i64 - non_pool_out,
        _ => input_values.iter().sum::<i64>() - non_pool_out,
    };
    if locked <= 0 {
        return Vec::new();
    }
    let cap = (locked as u64) / pool_outs.len() as u64;
    pool_outs.into_iter().map(|cmu| (cmu, cap)).collect()
}

/// Decodes witness[4] of a shielded spend: `fee(8 LE) || C_new0(32)
/// || C_new1(32)` with field-encoded commitments.
pub fn decode_shield_witness(
    bytes: &[u8],
) -> Option<(u64, crate::value_snark::Field, crate::value_snark::Field)> {
    use ark_ff::PrimeField;
    if bytes.len() != 72 {
        return None;
    }
    let fee = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let c0 = crate::value_snark::bytes_to_field(&bytes[8..40]);
    let c1 = crate::value_snark::bytes_to_field(&bytes[40..72]);
    Some((fee, c0, c1))
}

/// Extracts the public fee from a shield witness (witness[4]).
pub fn decode_shield_fee(bytes: &[u8]) -> Option<u64> {
    decode_shield_witness(bytes).map(|(fee, _, _)| fee)
}

/// Spend authorisation: Schnorr signature (RFC6979 via secp256k1 ECDSA)
/// over the note context with the spending secret. Returns the 64-byte
/// signature.
pub fn authorize_spend(
    note: &Note,
    secret: &[u8; 32],
    anchor: &[u8; 32],
    context: &[u8],
) -> Result<[u8; 64], NoteError> {
    use bitcoin::secp256k1::{ecdsa, Message};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret).map_err(|_| NoteError::Invalid)?;
    let msg = authorize_message(note, anchor, context);
    let message = Message::from_digest_slice(&msg).map_err(|_| NoteError::Invalid)?;
    Ok(secp.sign_ecdsa(&message, &sk).serialize_compact())
}

/// Verifies a spend authorisation signature.
pub fn verify_authorization(
    note: &Note,
    anchor: &[u8; 32],
    context: &[u8],
    signature: &[u8; 64],
) -> Result<(), NoteError> {
    use bitcoin::secp256k1::{ecdsa, Message};
    let secp = Secp256k1::new();
    let sig = ecdsa::Signature::from_compact(signature).map_err(|_| NoteError::Invalid)?;
    let pubkey = PublicKey::from_slice(&note.spending_pub).map_err(|_| NoteError::Invalid)?;
    let msg = authorize_message(note, anchor, context);
    let message = Message::from_digest_slice(&msg).map_err(|_| NoteError::Invalid)?;
    if secp.verify_ecdsa(&message, &sig, &pubkey).is_ok() {
        Ok(())
    } else {
        Err(NoteError::Authorization)
    }
}

/// Note witness: the note itself (`pub || value || rcm = 73 bytes`).
pub fn encode_note(note: &Note) -> Vec<u8> {
    let mut out = Vec::with_capacity(73);
    out.extend_from_slice(&note.spending_pub);
    out.extend_from_slice(&note.value.to_le_bytes());
    out.extend_from_slice(&note.rcm);
    out
}

/// Decodes a note witness.
pub fn decode_note(bytes: &[u8]) -> Option<Note> {
    if bytes.len() != 73 {
        return None;
    }
    Some(Note {
        spending_pub: bytes[0..33].try_into().ok()?,
        value: u64::from_le_bytes(bytes[33..41].try_into().ok()?),
        rcm: bytes[41..73].try_into().ok()?,
    })
}

/// Spend auth witness: anchor (32) || index (4 LE) || signature (64).
pub fn encode_spend_auth(anchor: &[u8; 32], index: u32, signature: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(100);
    out.extend_from_slice(anchor);
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(signature);
    out
}

/// Decodes a spend auth witness.
pub fn decode_spend_auth(bytes: &[u8]) -> Option<([u8; 32], u32, [u8; 64])> {
    if bytes.len() != 100 {
        return None;
    }
    Some((
        bytes[0..32].try_into().ok()?,
        u32::from_le_bytes(bytes[32..36].try_into().ok()?),
        bytes[36..100].try_into().ok()?,
    ))
}

/// Verifies one note spend in block context (called by `ConnectBlock`).
/// Returns the fee (note value minus outputs). `spent_outs` are the
/// previous outputs; pool note spends carry `value > 0` inside the note.
///
/// `funding_caps` (when `Some`) is the issuance funding ledger,
/// `cmu -> max spendable sats` recorded at creation. A note whose
/// claimed value exceeds its cap (or is missing from the ledger) is
/// rejected — this is what stops inflation without a SNARK, given
/// the hash/Pedersen bindings pin the opening to the funded `cmu`.
/// Value-committed scripts additionally require the Pedersen opening
/// `C == value*G + rcm*H`.
pub fn verify_note_tx_block(
    tx: &btc_primitives::Tx,
    spent_outs: &[btc_primitives::TxOut],
    pool_root: Option<[u8; 32]>,
) -> Result<i64, NoteError> {
    verify_note_tx_block_with_caps(tx, spent_outs, pool_root, None)
}

/// As [`verify_note_tx_block`], with an explicit funding-cap ledger.
pub fn verify_note_tx_block_with_caps(
    tx: &btc_primitives::Tx,
    spent_outs: &[btc_primitives::TxOut],
    pool_root: Option<[u8; 32]>,
    funding_caps: Option<&std::collections::HashMap<[u8; 32], u64>>,
) -> Result<i64, NoteError> {
    // No verifying key: SNARK proofs cannot be checked, so any spend
    // carrying one is rejected (see the `_with_snark` variant).
    verify_note_tx_block_with_snark(tx, spent_outs, pool_root, funding_caps, None)
}

/// As [`verify_note_tx_block_with_caps`], with the chain-pinned Groth16
/// verifying key (`ChainParams::snark_vk`). With `snark_vk == None`
/// a spend that carries a proof (`witness[3]`) is invalid: a proof that
/// cannot be verified must never be accepted, ignored, or used to
/// derive a fee or new commitments (shielded mode needs the proof).
pub fn verify_note_tx_block_with_snark(
    tx: &btc_primitives::Tx,
    spent_outs: &[btc_primitives::TxOut],
    pool_root: Option<[u8; 32]>,
    funding_caps: Option<&std::collections::HashMap<[u8; 32], u64>>,
    snark_vk: Option<&crate::value_snark::SnarkVk>,
) -> Result<i64, NoteError> {
    if spent_outs.len() != tx.vin.len() || tx.vin.is_empty() {
        return Err(NoteError::Invalid);
    }
    // Hash of the stripped tx: context for spend authorisations.
    let context = crate::confidential::ct_context(tx);
    let anchor = pool_root.ok_or(NoteError::UnknownAnchor)?;
    let anchors = [anchor].into_iter().collect();
    let mut total_value: i64 = 0;
    let mut spent_fee: i64 = -1;
    for (i, (input, spent_out)) in tx.vin.iter().zip(spent_outs).enumerate() {
        if crate::confidential::is_ct_script(spent_out.script_pubkey.as_bytes()) {
            continue; // CT spends are checked elsewhere
        }
        let Some((pool_cmu, value_commitment)) =
            decode_pool_note_full(spent_out.script_pubkey.as_bytes())
        else {
            continue; // plain input: script checks run elsewhere
        };
        let script_poseidon = decode_pool_script_full(spent_out.script_pubkey.as_bytes())
            .and_then(|(_, _, poseidon)| poseidon);
        let note_bytes = input.witness.iter().next().map(|b| b.to_vec());
        let Some(note_bytes) = note_bytes else {
            return Err(NoteError::Invalid);
        };
        let note = decode_note(&note_bytes).ok_or(NoteError::Invalid)?;
        if spent_out.value != 0 && note.value != 0 {
            // Pool notes are zero-valued in the ledger (value hidden inside).
            return Err(NoteError::Invalid);
        }
        if note_commitment(&note) != pool_cmu {
            return Err(NoteError::Invalid);
        }
        // Pedersen binding: the opening (value, rcm) must match the
        // value commitment published at issuance.
        if let Some(c) = value_commitment {
            let expected =
                crate::confidential::commitment_point(note.value, note.rcm)
                    .map_err(|_| NoteError::Invalid)?;
            if expected != c {
                return Err(NoteError::Invalid);
            }
        }
        // Anti-inflation: the note may claim at most what its issuance
        // locked behind the commitment.
        if let Some(caps) = funding_caps {
            let Some(cap) = caps.get(&pool_cmu) else {
                return Err(NoteError::Invalid);
            };
            if note.value > *cap {
                return Err(NoteError::Invalid);
            }
        }
        let Some(auth_bytes) = input.witness.iter().nth(1).map(|b| b.to_vec()) else {
            return Err(NoteError::Invalid);
        };
        let (anchor_claimed, index, signature) =
            decode_spend_auth(&auth_bytes).ok_or(NoteError::Invalid)?;
        let path_bytes = input.witness.iter().nth(2).ok_or(NoteError::Invalid)?;
        let path = decode_path(path_bytes).ok_or(NoteError::Invalid)?;
        if anchor_claimed != anchor {
            return Err(NoteError::UnknownAnchor);
        }
        // Membership + signature, double spend registration is checked by
        // the caller through the chainstate pool registry.
        verify_spend(&anchors, &std::collections::HashSet::new(), &note, &anchor, index, &path, &context, &signature)?;
        total_value += note.value as i64;
        // Optional Groth16 value-hiding proof (witness[3]). Bound to
        // this note's opening (`C_old` from `(value, rcm)`) and to the
        // funding cap. With `witness[4]` (fee + new commitments) the
        // spend is shielded: the single pool output becomes a new
        // hidden note funded by `note.value - fee`, and the returned
        // fee is the public one. Without it outputs stay transparent.
        // Present-but-invalid proofs are rejected (never ignored).
        if let Some(proof_bytes) = input.witness.iter().nth(3) {
            if tx.vin.len() != 1 {
                return Err(NoteError::Invalid);
            }
            // No pinned verifying key => nothing can be proven.
            let Some(snark_vk) = snark_vk else {
                return Err(NoteError::Invalid);
            };
            let proof =
                crate::value_snark::deserialize_proof(proof_bytes).ok_or(NoteError::Invalid)?;
            let cap = match funding_caps {
                Some(caps) => *caps.get(&pool_cmu).ok_or(NoteError::Invalid)?,
                None => note.value,
            };
            let value_out: i64 = tx.vout.iter().map(|o| o.value).sum();
            if let Some(shield_bytes) = input.witness.iter().nth(4) {
                // Shielded mode: one pool output, no plaintext value.
                let (fee_u64, c_new0, c_new1) =
                    decode_shield_witness(shield_bytes).ok_or(NoteError::Invalid)?;
                if value_out != 0 || fee_u64 > note.value {
                    return Err(NoteError::Invalid);
                }
                let pool_out_count = tx
                    .vout
                    .iter()
                    .filter(|o| is_pool_script(o.script_pubkey.as_bytes()))
                    .count();
                if pool_out_count != 1 {
                    return Err(NoteError::Invalid);
                }
                let transcript = crate::value_snark::ValueTranscript {
                    fee: fee_u64,
                    cap,
                    cmu: crate::value_snark::cmu_field(&pool_cmu),
                    poseidon: match &script_poseidon {
                        Some(bytes) => crate::value_snark::bytes_to_field(bytes),
                        None => crate::value_snark::poseidon_cmu(
                            &note.spending_pub,
                            note.value,
                            &note.rcm,
                        ),
                    },
                    c_old: crate::value_snark::value_commitment(note.value, &note.rcm, &pool_cmu),
                    c_new: [c_new0, c_new1],
                };
                if !crate::value_snark::verify(snark_vk, transcript, &proof) {
                    return Err(NoteError::Invalid);
                }
                spent_fee = fee_u64 as i64;
            } else {
                let fee_u64 = (note.value as i64 - value_out).max(0) as u64;
                let transcript = crate::value_snark::transcript_for_spend(
                    &note,
                    &pool_cmu,
                    value_out.max(0) as u64,
                    fee_u64,
                    cap,
                );
                if !crate::value_snark::verify(snark_vk, transcript, &proof) {
                    return Err(NoteError::Invalid);
                }
            }
        }
    }
    let value_out: i64 = tx.vout.iter().map(|o| o.value).sum();
    let fee = if spent_fee >= 0 {
        spent_fee
    } else {
        total_value - value_out
    };
    if fee < 0 || fee > 21_000_000 * 100_000_000 {
        return Err(NoteError::Invalid);
    }
    Ok(fee)
}

/// Packs a Merkle path (32 siblings).
pub fn encode_path(path: &[[u8; 32]]) -> Vec<u8> {
    path.concat()
}

/// Decodes a Merkle path.
pub fn decode_path(bytes: &[u8]) -> Option<Vec<[u8; 32]>> {
    if bytes.len() != NOTE_DEPTH * 32 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().unwrap())
            .collect(),
    )
}

/// Context digest: commitment, anchor, nullifier and transaction context.
pub fn authorize_message(note: &Note, anchor: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(TAG_AUTH.len() + 32 + 32 + 32 + context.len());
    buf.extend_from_slice(TAG_AUTH);
    buf.extend_from_slice(&note_commitment(note));
    buf.extend_from_slice(anchor);
    buf.extend_from_slice(&nullifier(note));
    buf.extend_from_slice(context);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Incremental Merkle tree over note commitments.
pub struct NoteTree {
    layers: Vec<Vec<[u8; 32]>>,
    leaves: Vec<[u8; 32]>,
}

impl NoteTree {
    pub fn new() -> Self {
        let mut layers = Vec::with_capacity(NOTE_DEPTH + 1);
        for _ in 0..=NOTE_DEPTH {
            layers.push(Vec::new());
        }
        Self {
            layers,
            leaves: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Leaves in insertion order.
    pub fn entries(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Position of a commitment, if present.
    pub fn position_of(&self, cmu: &[u8; 32]) -> Option<u32> {
        self.leaves
            .iter()
            .position(|leaf| leaf == cmu)
            .map(|i| i as u32)
    }

    /// Root of the tree at the current size.
    pub fn root(&self) -> [u8; 32] {
        fold_levels(&self.leaves)
    }

    /// Inserts a commitment; returns its position.
    pub fn insert(&mut self, cmu: [u8; 32]) -> u32 {
        let index = self.leaves.len() as u32;
        self.leaves.push(cmu);
        // Rebuild all 32 layers with the duplicate-last convention so the
        // root the verifier gets always comes from the same fold.
        self.layers.clear();
        let mut level = self.leaves.clone();
        for _ in 0..=NOTE_DEPTH {
            self.layers.push(level.clone());
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let right = pair.get(1).copied().unwrap_or(pair[0]);
                next.push(hash_pair(pair[0], right));
            }
            level = next;
            if level.len() == 1 && level[0] == [0u8; 32] {
                break;
            }
        }
        index
    }

    /// Sibling path for `index` (for proof generation).
    pub fn path(&self, index: u32) -> Vec<[u8; 32]> {
        let mut at = index as usize;
        let mut out = Vec::with_capacity(NOTE_DEPTH);
        for depth in 0..NOTE_DEPTH {
            let layer = &self.layers[depth];
            if layer.is_empty() {
                // Beyond the built tree: the root duplicates itself.
                out.push(self.root());
            } else if at % 2 == 0 {
                // Missing sibling mirrors the duplicate-last convention.
                out.push(layer.get(at + 1).copied().unwrap_or(layer[at.min(layer.len() - 1)]));
            } else {
                out.push(layer[at - 1]);
            }
            at /= 2;
        }
        out
    }

    /// Verifies a note membership proof against an anchor root.
    pub fn verify_membership(
        anchor: &[u8; 32],
        cmu: &[u8; 32],
        index: u32,
        path: &[[u8; 32]],
    ) -> bool {
        if path.len() != NOTE_DEPTH {
            return false;
        }
        let mut hash = *cmu;
        let mut at = index as usize;
        for sibling in path {
            hash = hash_pair(
                if at % 2 == 0 { hash } else { *sibling },
                if at % 2 == 0 { *sibling } else { hash },
            );
            at /= 2;
        }
        hash == *anchor
    }
}

fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&a);
    buf[32..].copy_from_slice(&b);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Folds leaves up exactly NOTE_DEPTH levels, duplicating single nodes.
/// This is the convention both root() and proofs use.
fn fold_levels(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    for _ in 0..NOTE_DEPTH {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(hash_pair(pair[0], right));
        }
        level = next;
    }
    level.first().copied().unwrap_or([0u8; 32])
}

/// Checks a spend: membership proof, anchor freshness, no double spend
/// and spend authorisation signature.
pub fn verify_spend(
    anchor_roots: &HashSet<[u8; 32]>,
    spent_nullifiers: &HashSet<[u8; 32]>,
    note: &Note,
    anchor: &[u8; 32],
    index: u32,
    path: &[[u8; 32]],
    context: &[u8],
    signature: &[u8; 64],
) -> Result<(), NoteError> {
    if !anchor_roots.contains(anchor) {
        return Err(NoteError::UnknownAnchor);
    }
    let cmu = note_commitment(note);
    if !NoteTree::verify_membership(anchor, &cmu, index, path) {
        return Err(NoteError::Invalid);
    }
    let nf = nullifier(note);
    if spent_nullifiers.contains(&nf) {
        return Err(NoteError::DoubleSpend);
    }
    verify_authorization(note, anchor, context, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(seed: u8) -> Note {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[0] = seed;
        secret[31] = 9;
        Note {
            spending_pub: PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&secret).unwrap(),
            )
            .serialize(),
            value: 25_00000000,
            rcm: [seed; 32],
        }
    }

    #[test]
    fn membership_proof_and_authorization_round_trip() {
        let secp = Secp256k1::new();
        let mut tree = NoteTree::new();
        let mut notes = Vec::new();
        for i in 1..=8u8 {
            let n = note(i);
            let pos = tree.insert(note_commitment(&n));
            assert_eq!(pos, (i - 1) as u32);
            notes.push(n);
        }
        let anchor = tree.root();
        let roots = [anchor].into_iter().collect();
        let path = tree.path(2);
        let mut secret = [0u8; 32];
        secret[0] = 3;
        secret[31] = 9;
        let sig = authorize_spend(&notes[2], &secret, &anchor, b"spend").unwrap();
        verify_spend(
            &roots,
            &HashSet::new(),
            &notes[2],
            &anchor,
            2,
            &path,
            b"spend",
            &sig,
        )
        .unwrap();
        // The same note cannot pass twice.
        let mut spent = HashSet::new();
        spent.insert(nullifier(&notes[2]));
        assert_eq!(
            verify_spend(&roots, &spent, &notes[2], &anchor, 2, &path, b"spend", &sig),
            Err(NoteError::DoubleSpend)
        );
        // A forged path must not verify.
        let mut bad_path = path.clone();
        bad_path[0][0] ^= 1;
        assert!(verify_spend(&roots, &HashSet::new(), &notes[2], &anchor, 2, &bad_path, b"spend", &sig).is_err());
    }

    #[test]
    fn committed_script_and_funding_cap_block_inflation() {
        use std::collections::HashMap;
        use btc_primitives::{ScriptBuf, TxIn, TxOut};
        use bitcoin::Witness;

        let n = note(5);
        let cmu = note_commitment(&n);
        // Value commitment binds the opening at spend.
        let c = crate::confidential::commitment_point(n.value, n.rcm).unwrap();
        let script = encode_pool_note_committed(&cmu, &c);
        assert!(is_pool_script(&script));
        assert_eq!(decode_pool_note(&script), Some(cmu));
        assert_eq!(decode_pool_note_full(&script), Some((cmu, Some(c))));
        // Legacy script has no commitment.
        assert_eq!(
            decode_pool_note_full(&encode_pool_note(&cmu)),
            Some((cmu, None))
        );

        // Issuance funding: inputs 30 BTC, non-pool outputs 29.x BTC,
        // so exactly 1 BTC < value of the note would be locked; but the
        // note claims 25 sats*1e8. Cap math: locked = 1_00000000.
        let creation = btc_primitives::Tx::new(
            1,
            vec![TxIn::new(bitcoin::OutPoint::null())],
            vec![],
            0,
        );
        let _ = creation;
        let caps = funding_caps_for_block(
            &btc_primitives::Tx::new(
                1,
                vec![TxIn::new(bitcoin::OutPoint::null())],
                vec![],
                0,
            ),
            &[0],
        );
        assert!(caps.is_empty());

        // Spend claiming more than the funded cap must fail.
        let mut tree = NoteTree::new();
        tree.insert(cmu);
        let anchor = tree.root();
        let path = tree.path(0);
        let spent_out = TxOut::new(0, ScriptBuf::from_bytes(script.clone()));
        // Build a spend whose output exceeds the cap we will allow.
        let mut tx = btc_primitives::Tx::new(
            2,
            vec![TxIn::new(bitcoin::OutPoint::null())],
            vec![TxOut::new(1, ScriptBuf::new())],
            0,
        );
        let context = crate::confidential::ct_context(&tx);
        let mut secret = [0u8; 32];
        secret[0] = 5;
        secret[31] = 9;
        let sig = authorize_spend(&n, &secret, &anchor, &context).unwrap();
        tx.vin[0].witness = Witness::from_slice(&[
            encode_note(&n),
            encode_spend_auth(&anchor, 0, &sig),
            encode_path(&path),
        ]);
        let mut cap_map = HashMap::new();
        cap_map.insert(cmu, 1000u64); // funded only 1000 sats, note = 25 BTC
        assert!(verify_note_tx_block_with_caps(
            &tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&cap_map),
        )
        .is_err());
        cap_map.insert(cmu, n.value);
        assert!(verify_note_tx_block_with_caps(
            &tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&cap_map),
        )
        .is_ok());
    }

    #[test]
    fn snark_proof_spend_verifies_and_tamper_rejected() {
        use std::collections::HashMap;
        use btc_primitives::{ScriptBuf, TxIn, TxOut};
        use bitcoin::Witness;

        let n = note(5);
        let cmu = note_commitment(&n);
        let mut tree = NoteTree::new();
        tree.insert(cmu);
        let anchor = tree.root();
        let path = tree.path(0);
        let spent_out = TxOut::new(0, ScriptBuf::from_bytes(encode_pool_note(&cmu)));
        let outputs_total: u64 = 1_000_000;
        let fee: u64 = n.value - outputs_total;
        let mut secret = [0u8; 32];
        secret[0] = 5;
        secret[31] = 9;
        let mut tx = btc_primitives::Tx::new(
            2,
            vec![TxIn::new(bitcoin::OutPoint::null())],
            vec![TxOut::new(outputs_total as i64, ScriptBuf::new())],
            0,
        );
        let context = crate::confidential::ct_context(&tx);
        let sig = authorize_spend(&n, &secret, &anchor, &context).unwrap();
        tx.vin[0].witness = Witness::from_slice(&[
            encode_note(&n),
            encode_spend_auth(&anchor, 0, &sig),
            encode_path(&path),
        ]);
        // Legacy spend (no proof) verifies.
        assert!(verify_note_tx_block_with_caps(
            &tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            None,
        )
        .is_ok());
        // SNARK spend verifies.
        let transcript =
            crate::value_snark::transcript_for_spend(&n, &cmu, outputs_total, fee, n.value);
        let dummy = [0u8; 32];
        let witness = crate::value_snark::ValueWitness {
            v_old: n.value,
            rcm_old: n.rcm,
            spending_pub: n.spending_pub,
            v_new: [outputs_total, 0],
            rcm_new: [dummy, dummy],
        };
        let (pk, vk_raw) = crate::value_snark::ephemeral_process_parameters();
        let vk = crate::value_snark::SnarkVk::from_vk(vk_raw).unwrap();
        let proof = crate::value_snark::prove(pk, transcript, witness).expect("proves");
        let mut proof_tx = tx.clone();
        proof_tx.vin[0].witness = Witness::from_slice(&[
            encode_note(&n),
            encode_spend_auth(&anchor, 0, &sig),
            encode_path(&path),
            crate::value_snark::serialize_proof(&proof),
        ]);
        let mut caps = HashMap::new();
        caps.insert(cmu, n.value);
        assert!(verify_note_tx_block_with_snark(
            &proof_tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&caps),
            Some(&vk),
        )
        .is_ok());
        // No verifying key configured: a proof-carrying spend is rejected
        // (never ignored, never trusted).
        assert!(verify_note_tx_block_with_caps(
            &proof_tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&caps),
        )
        .is_err());
        assert!(verify_note_tx_block_with_snark(
            &proof_tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&caps),
            None,
        )
        .is_err());
        // A verifying key from another setup rejects the proof.
        let (_, other_raw) = crate::value_snark::generate_parameters_os().unwrap();
        let other = crate::value_snark::SnarkVk::from_vk(&other_raw).unwrap();
        assert!(verify_note_tx_block_with_snark(
            &proof_tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&caps),
            Some(&other),
        )
        .is_err());
        // Proof bound to a different cap also fails (cap is public input).
        let mut bad_caps = HashMap::new();
        bad_caps.insert(cmu, n.value + 1);
        assert!(verify_note_tx_block_with_snark(
            &proof_tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&bad_caps),
            Some(&vk),
        )
        .is_err());
        let _ = fee;
    }

    #[test]
    fn poseidon_script_v3_roundtrips() {
        let n = note(5);
        let cmu = note_commitment(&n);
        let poseidon = crate::value_snark::field_to_bytes(&crate::value_snark::poseidon_cmu(
            &n.spending_pub,
            n.value,
            &n.rcm,
        ));
        let pedersen = crate::confidential::commitment_point(n.value, n.rcm).unwrap();
        let script = encode_pool_note_v3(&cmu, &poseidon, &pedersen);
        assert_eq!(script.len(), 100);
        assert!(is_pool_script(&script));
        assert_eq!(decode_pool_note(&script), Some(cmu));
        assert_eq!(
            decode_pool_script_full(&script),
            Some((cmu, Some(pedersen), Some(poseidon)))
        );
        // Legacy shapes still decode.
        assert_eq!(
            decode_pool_script_full(&encode_pool_note(&cmu)),
            Some((cmu, None, None))
        );
    }

    #[test]
    fn shielded_note_spend_verifies_and_funds_new_note() {
        use std::collections::HashMap;
        use btc_primitives::{ScriptBuf, TxIn, TxOut};
        use bitcoin::Witness;

        let n = note(5);
        let cmu = note_commitment(&n);
        let mut tree = NoteTree::new();
        tree.insert(cmu);
        let anchor = tree.root();
        let path = tree.path(0);
        let spent_out = TxOut::new(0, ScriptBuf::from_bytes(encode_pool_note(&cmu)));
        let fee: u64 = 10_000;
        let new_value: u64 = n.value - fee;
        // New note + script.
        let new_note = Note {
            spending_pub: n.spending_pub,
            value: new_value,
            rcm: [3u8; 32],
        };
        let new_cmu = note_commitment(&new_note);
        let new_script = ScriptBuf::from_bytes(encode_pool_note(&new_cmu));
        let mut secret = [0u8; 32];
        secret[0] = 5;
        secret[31] = 9;
        let mut tx = btc_primitives::Tx::new(
            2,
            vec![TxIn::new(bitcoin::OutPoint::null())],
            vec![TxOut::new(0, new_script)],
            0,
        );
        let context = crate::confidential::ct_context(&tx);
        let sig = authorize_spend(&n, &secret, &anchor, &context).unwrap();
        let dummy = [0u8; 32];
        let transcript = crate::value_snark::ValueTranscript {
            fee,
            cap: n.value,
            cmu: crate::value_snark::cmu_field(&cmu),
            poseidon: crate::value_snark::poseidon_cmu(&n.spending_pub, n.value, &n.rcm),
            c_old: crate::value_snark::value_commitment(n.value, &n.rcm, &cmu),
            c_new: [
                crate::value_snark::new_commitment(new_value, &new_note.rcm),
                crate::value_snark::new_commitment(0, &dummy),
            ],
        };
        let witness = crate::value_snark::ValueWitness {
            v_old: n.value,
            rcm_old: n.rcm,
            spending_pub: n.spending_pub,
            v_new: [new_value, 0],
            rcm_new: [new_note.rcm, dummy],
        };
        let (pk, vk_raw) = crate::value_snark::ephemeral_process_parameters();
        let vk = crate::value_snark::SnarkVk::from_vk(vk_raw).unwrap();
        let proof = crate::value_snark::prove(pk, transcript, witness).expect("proves");
        assert!(crate::value_snark::verify(&vk, transcript, &proof), "direct verify");
        let mut shield = Vec::with_capacity(72);
        shield.extend_from_slice(&fee.to_le_bytes());
        shield.extend_from_slice(&crate::value_snark::field_to_bytes(&transcript.c_new[0]));
        shield.extend_from_slice(&crate::value_snark::field_to_bytes(&transcript.c_new[1]));
        tx.vin[0].witness = Witness::from_slice(&[
            encode_note(&n),
            encode_spend_auth(&anchor, 0, &sig),
            encode_path(&path),
            crate::value_snark::serialize_proof(&proof),
            shield,
        ]);
        let mut caps = HashMap::new();
        caps.insert(cmu, n.value);
        // Without a configured verifying key the shielded spend (whose fee
        // and new commitments would come from the proof) is rejected.
        assert!(verify_note_tx_block_with_caps(
            &tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&caps),
        )
        .is_err());
        let got_fee = verify_note_tx_block_with_snark(
            &tx,
            std::slice::from_ref(&spent_out),
            Some(anchor),
            Some(&caps),
            Some(&vk),
        )
        .expect("shielded spend verifies");
        assert_eq!(got_fee, fee as i64, "miner fee is the public fee");
        // Funding ledger records the new note with (value).
        let caps_out = funding_caps_for_block(&tx, &[0]);
        assert_eq!(caps_out, vec![(new_cmu, new_value)]);
    }
}
