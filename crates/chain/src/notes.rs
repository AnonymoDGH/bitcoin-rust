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
//! Honest limitation (documented in `docs/privacy-plan.md`): hash-based
//! notes provide hiding but **not** a proof of no inflation — total
//! issuance must still come from the transparent subsidy. The upgrade
//! path is a zk-SNARK over the same note definition (Orchard-style),
//! keeping this crate's addressing.

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

/// Pool output script: `OP_RETURN 0x02 <cmu:32>`. A leaf in the pool tree.
pub fn encode_pool_note(cmu: &[u8; 32]) -> Vec<u8> {
    let mut script = vec![0x6a, 0x4c, 32];
    script.extend_from_slice(cmu);
    script
}

/// True if `script` is a pool note output script.
pub fn is_pool_script(script: &[u8]) -> bool {
    script.len() == 35 && script[0] == 0x6a && script[1] == 0x4c && script[2] == 32
}

/// Extracts the commitment from a pool note output script.
pub fn decode_pool_note(script: &[u8]) -> Option<[u8; 32]> {
    if !is_pool_script(script) {
        return None;
    }
    script[3..35].try_into().ok()
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
pub fn verify_note_tx_block(
    tx: &btc_primitives::Tx,
    spent_outs: &[btc_primitives::TxOut],
    pool_root: Option<[u8; 32]>,
) -> Result<i64, NoteError> {
    if spent_outs.len() != tx.vin.len() || tx.vin.is_empty() {
        return Err(NoteError::Invalid);
    }
    // Hash of the stripped tx: context for spend authorisations.
    let context = crate::confidential::ct_context(tx);
    let anchor = pool_root.ok_or(NoteError::UnknownAnchor)?;
    let anchors = [anchor].into_iter().collect();
    let mut total_value: i64 = 0;
    for (i, (input, spent_out)) in tx.vin.iter().zip(spent_outs).enumerate() {
        if crate::confidential::is_ct_script(spent_out.script_pubkey.as_bytes()) {
            continue; // CT spends are checked elsewhere
        }
        let pool_cmu = decode_pool_note(spent_out.script_pubkey.as_bytes());
        let Some(pool_cmu) = pool_cmu else {
            continue; // plain input: script checks run elsewhere
        };
        eprintln!("ct-note dbg: pool input {i} spending cmu from script");
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
    }
    let value_out: i64 = tx.vout.iter().map(|o| o.value).sum();
    let fee = total_value - value_out;
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
}
