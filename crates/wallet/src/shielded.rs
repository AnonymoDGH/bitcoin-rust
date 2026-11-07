//! Wallet-side shielded notes (Privacy Plan, Phase 3).
//!
//! The wallet creates notes for its own spending keys, recovers them
//! through the pool list of commitments, and produces spend
//! authorizations against a chain anchor. Nullifier bookkeeping
//! (double-spend protection) is chain-side in `btc-chain::notes`.

use btc_chain::notes::{
    authorize_spend, note_commitment, nullifier, Note, NoteError, NoteTree,
    verify_spend,
};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShieldError {
    #[error(transparent)]
    Note(#[from] NoteError),
    #[error("random number generation failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("invalid spending secret")]
    InvalidSecret,
}

/// Note summary for listing (no secrets in the listing itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSummary {
    pub commitment: [u8; 32],
    pub value: u64,
    pub spent: bool,
}

/// Creates a note: fresh owner key, random `rcm`, hidden amount.
pub fn create_note(value: u64) -> Result<(Note, [u8; 32]), ShieldError> {
    let secp = Secp256k1::new();
    let mut secret = [0u8; 32];
    loop {
        getrandom::getrandom(&mut secret)?;
        if SecretKey::from_slice(&secret).is_ok() {
            break;
        }
    }
    let mut rcm = [0u8; 32];
    getrandom::getrandom(&mut rcm)?;
    let note = Note {
        spending_pub: PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secret).map_err(|_| ShieldError::InvalidSecret)?,
        )
        .serialize(),
        value,
        rcm,
    };
    Ok((note, secret))
}

/// Builds a wallet-side note store (commitment list + tree + paths).
pub struct NoteStore {
    pub notes: Vec<(u32, Note)>,
    pub tree: NoteTree,
}

impl Default for NoteStore {
    fn default() -> Self {
        Self {
            notes: Vec::new(),
            tree: NoteTree::new(),
        }
    }
}

impl NoteStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.notes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Records a note; returns its pool position.
    pub fn add(&mut self, note: Note) -> u32 {
        let position = self.tree.insert(note_commitment(&note));
        self.notes.push((position, note));
        position
    }

    /// Witness for spending `position` at chain anchor `root`.
    pub fn spend(&self, position: u32, context: &[u8]) -> Option<(Note, Vec<[u8; 32]>, [u8; 32])> {
        let root = self.tree.root();
        let path = self.tree.path(position);
        let (_position, note) = self
            .notes
            .iter()
            .find(|(pos, _)| *pos == position)?;
        Some((note.clone(), path, root))
    }

    /// Recovers note candidates by scanning commitments: given the
    /// secrets the wallet holds, find matching commitments and return
    /// their positions. Matching happens off-chain on owned secrets.
    pub fn recover(&self, mut known_secrets: Vec<[u8; 32]>) -> Vec<Note> {
        let secp = Secp256k1::new();
        let mut found = Vec::new();
        for (position, note) in &self.notes {
            let pubkey = PublicKey::from_slice(&note.spending_pub)
                .map(|pk| pk.serialize())
                .unwrap_or([0u8; 33]);
            if known_secrets
                .iter()
                .any(|s| {
                    SecretKey::from_slice(s)
                        .map(|sk| PublicKey::from_secret_key(&secp, &sk).serialize())
                        == Ok(pubkey)
                })
            {
                found.push(note.clone());
            }
            let _ = position;
        }
        found
    }
}

/// Authorizes a shielded spend of `note` at `anchor`.
pub fn authorize(note: &Note, secret: &[u8; 32], anchor: &[u8; 32], context: &[u8]) -> Result<[u8; 64], ShieldError> {
    Ok(authorize_spend(note, secret, anchor, context)?)
}

/// Verifies a shielded spend authorisation.
pub fn verify_note_spend(
    anchor_roots: &std::collections::HashSet<[u8; 32]>,
    spent_nullifiers: &std::collections::HashSet<[u8; 32]>,
    note: &Note,
    anchor: &[u8; 32],
    index: u32,
    path: &[[u8; 32]],
    context: &[u8],
    signature: &[u8; 64],
) -> Result<(), ShieldError> {
    Ok(verify_spend(
        anchor_roots,
        spent_nullifiers,
        note,
        anchor,
        index,
        path,
        context,
        signature,
    )?)
}

/// Returns the note nullifier (double-spend identity).
pub fn note_nullifier(note: &Note) -> [u8; 32] {
    nullifier(note)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_creates_scans_and_spends_a_note() {
        let (note, secret) = create_note(10_00000000).unwrap();
        let mut store = NoteStore::new();
        let position = store.add(note.clone());
        assert_eq!(store.len(), 1);
        let recovered = store.recover(vec![secret]);
        assert_eq!(recovered, vec![note.clone()]);
        let (note2, path, anchor) = store.spend(position, b"ctx").unwrap();
        let sig = authorize(&note2, &secret, &anchor, b"ctx").unwrap();
        let roots = [anchor].into_iter().collect();
        verify_note_spend(&roots, &std::collections::HashSet::new(), &note2, &anchor, position, &path, b"ctx", &sig).unwrap();
        assert_eq!(note_nullifier(&note2), nullifier(&note));
    }
}
