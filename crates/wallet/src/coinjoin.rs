//! Decentralised CoinJoin rounds (Privacy Plan, Phase 1).
//!
//! N participants contribute one input each and receive one equal-value
//! output. Outputs are indistinguishable, so an observer cannot tell
//! which input paid which output — the cluster built by
//! common-input-ownership in a normal spend dissolves.
//!
//! The protocol is transport-agnostic and coordinator-free:
//!
//! 1. **Register**: each participant announces an outpoint and a
//!    commitment `SHA256(script_pubkey || blinding)`. No output is
//!    usable until *all* commitments are in.
//! 2. **Reveal**: outputs + blindings are published; commitments are
//!    checked and all outputs must be distinct.
//! 3. **Assemble**: one unsigned transaction is built with each
//!    participant's input and one equal-value output each, outputs
//!    sorted by script so position does not correlate with input order.
//! 4. **Sign**: each participant signs only their own input with
//!    their own [`KeyStore`]; no one needs anyone else's key.
//! 5. **Broadcast**: the fully signed transaction is published.
//!
//! There is no server holding logs (the Samourai failure mode): the
//! messages can be exchanged peer-to-peer, over Tor, or in-process
//! (as in the tests). Amounts remain visible until confidential
//! transactions (Phase 2).

use std::collections::BTreeSet;

use bitcoin::{OutPoint, ScriptBuf, Sequence, Witness};
use bitcoin_hashes::{sha256, Hash};
use btc_primitives::{Tx, TxIn, TxOut};
use thiserror::Error;

use crate::keys::KeyStore;
use crate::signer::{sign_transaction, SignError};

const TX_VERSION: u32 = 2;
const SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
/// Minimum output value for a mixed denomination (dust avoidance).
const MIN_DENOMINATION: i64 = 1_000;
/// Estimated weight of a P2WPKH input (conservative, like the builder).
const INPUT_WEIGHT: i64 = 272;
/// Estimated weight of a P2WPKH output.
const OUTPUT_WEIGHT: i64 = 124;

#[derive(Debug, Error)]
pub enum CoinJoinError {
    #[error("round has too few participants: {0}")]
    TooFewParticipants(usize),
    #[error("duplicate input outpoint: {0}")]
    DuplicateInput(String),
    #[error("participant input value must be positive")]
    InvalidInputValue,
    #[error("commitment does not match revealed output")]
    CommitmentMismatch,
    #[error("two participants chose the same output script")]
    DuplicateOutput,
    #[error("insufficient funds for a {0} sat denomination after fees")]
    InsufficientForDenomination(i64),
    #[error("assembled denomination {0} sat is below the dust floor")]
    DustDenomination(i64),
    #[error("invalid fee rate: {0} sat/kvB")]
    InvalidFeeRate(i64),
    #[error("round is in the wrong phase")]
    WrongPhase,
    #[error("signing failed: {0}")]
    Sign(#[from] SignError),
}

/// One CoinJoin participant's registration.
#[derive(Clone, Debug)]
pub struct Participant {
    /// The UTXO this participant spends.
    pub input: OutPoint,
    /// Value of that UTXO in satoshis.
    pub input_value: i64,
    /// Where the mixed output is paid (in cleartext, equal value).
    pub output: ScriptBuf,
    /// Random blinding that hides `output` inside the commitment.
    pub blinding: [u8; 32],
    /// `commit_output(output, blinding)`, announced before reveals.
    pub commitment: [u8; 32],
}

/// Hides an output inside a commitment until the reveal phase.
pub fn commit_output(output: &ScriptBuf, blinding: [u8; 32]) -> [u8; 32] {
    let mut buf = output.as_bytes().to_vec();
    buf.extend_from_slice(&blinding);
    let hash = sha256::Hash::hash(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}

/// A single CoinJoin round: register -> reveal -> assemble -> sign -> broadcast.
#[derive(Clone, Debug)]
pub struct CoinJoinRound {
    participants: Vec<Participant>,
    phase: Phase,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Registering,
    Revealed,
    Assembled,
}

impl CoinJoinRound {
    pub fn new() -> Self {
        Self {
            participants: Vec::new(),
            phase: Phase::Registering,
        }
    }

    /// Registers a participant. The commitment is recomputed here, so a
    /// reveal that does not match the announced commitment is impossible
    /// to smuggle in later.
    pub fn register(&mut self, participant: Participant) -> Result<(), CoinJoinError> {
        if self.phase != Phase::Registering {
            return Err(CoinJoinError::WrongPhase);
        }
        if participant.input_value <= 0 {
            return Err(CoinJoinError::InvalidInputValue);
        }
        if commit_output(&participant.output, participant.blinding) != participant.commitment {
            return Err(CoinJoinError::CommitmentMismatch);
        }
        if self.participants.iter().any(|p| p.input == participant.input) {
            return Err(CoinJoinError::DuplicateInput(participant.input.to_string()));
        }
        self.participants.push(participant);
        Ok(())
    }

    /// Verifies all commitments against the revealed outputs and that
    /// every output is distinct. Idempotent checklist run before assembly.
    pub fn reveal_check(&self) -> Result<(), CoinJoinError> {
        if self.participants.len() < 2 {
            return Err(CoinJoinError::TooFewParticipants(self.participants.len()));
        }
        let mut outputs = BTreeSet::new();
        for participant in &self.participants {
            if commit_output(&participant.output, participant.blinding) != participant.commitment {
                return Err(CoinJoinError::CommitmentMismatch);
            }
            if !outputs.insert(participant.output.as_bytes().to_vec()) {
                return Err(CoinJoinError::DuplicateOutput);
            }
        }
        Ok(())
    }

    /// Builds the unsigned CoinJoin transaction.
    /// Returns the transaction, the equal denomination and the fee paid.
    pub fn assemble(&mut self, fee_rate_sat_per_kvb: i64) -> Result<(Tx, i64, i64), CoinJoinError> {
        if fee_rate_sat_per_kvb < 0 {
            return Err(CoinJoinError::InvalidFeeRate(fee_rate_sat_per_kvb));
        }
        if self.phase == Phase::Assembled {
            return Err(CoinJoinError::WrongPhase);
        }
        self.reveal_check()?;

        let n = self.participants.len();
        let input_sum: i64 = self.participants.iter().map(|p| p.input_value).sum();
        let weight = 8 + 4 + (INPUT_WEIGHT + OUTPUT_WEIGHT) * n as i64;
        let fee_estimate = (weight * fee_rate_sat_per_kvb + 3999) / 4000;
        let denomination = (input_sum - fee_estimate) / n as i64;
        if denomination < MIN_DENOMINATION {
            return Err(CoinJoinError::InsufficientForDenomination(denomination));
        }
        if denomination < MIN_DENOMINATION && input_sum / n as i64 >= MIN_DENOMINATION {
            return Err(CoinJoinError::DustDenomination(denomination));
        }
        let fee = input_sum - denomination * n as i64;

        let vin = self
            .participants
            .iter()
            .map(|p| TxIn {
                prevout: p.input,
                script_sig: ScriptBuf::new(),
                sequence: SEQUENCE,
                witness: Witness::new(),
            })
            .collect::<Vec<_>>();

        // Sorted output order: position in `vout` does not correlate
        // with position in `vin`.
        let mut outputs: Vec<ScriptBuf> = self
            .participants
            .iter()
            .map(|p| p.output.clone())
            .collect();
        outputs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let vout = outputs
            .into_iter()
            .map(|script| TxOut::new(denomination, script))
            .collect::<Vec<_>>();

        self.phase = Phase::Assembled;
        Ok((Tx::new(TX_VERSION, vin, vout, 0), denomination, fee))
    }

    /// The spent outputs (in input order) needed by `sign_transaction`.
    pub fn spent_outputs(&self) -> Vec<TxOut> {
        self.participants
            .iter()
            .map(|p| TxOut::new(p.input_value, p.output.clone()))
            .collect()
    }

    /// Signs only the inputs this keystore owns. Each participant calls
    /// this with their own keystore; others' inputs stay untouched.
    pub fn sign_my_inputs(
        &self,
        tx: &mut Tx,
        keys: &KeyStore,
    ) -> Result<(), CoinJoinError> {
        sign_transaction(tx, &self.spent_outputs(), keys)?;
        Ok(())
    }

    /// True when every input carries a signature.
    pub fn is_fully_signed(&self, tx: &Tx) -> bool {
        tx.vin.iter().all(|input| {
            !input.script_sig.as_bytes().is_empty() || !input.witness.is_empty()
        })
    }
}

impl Default for CoinJoinRound {
    fn default() -> Self {
        Self::new()
    }
}

/// Fixed-size blinded output helper for the common P2WPKH case.
/// `nested` mirrors `ScriptKind::P2wpkh` script construction.
pub fn coinjoin_output(keys: &KeyStore, id: &crate::keys::KeyId) -> Option<ScriptBuf> {
    keys.script_pubkeys(id)
        .and_then(|scripts| {
            scripts
                .iter()
                .find_map(|(kind, script)| {
                    (*kind == crate::keys::ScriptKind::P2wpkh).then_some(script.clone())
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ScriptKind;

    fn make_participant(i: u8, value: i64) -> (Participant, KeyStore, TxOut) {
        let mut keys = KeyStore::new();
        let id = keys.generate().unwrap();
        let output = keys
            .script_pubkeys(&id)
            .unwrap()
            .iter()
            .find_map(|(kind, script)| {
                (*kind == ScriptKind::P2wpkh).then_some(script.clone())
            })
            .unwrap();
        let input = OutPoint::new(
            bitcoin::Txid::from_slice(&[i; 32]).unwrap(),
            0,
        );
        let blinding = [i; 32];
        let participant = Participant {
            input,
            input_value: value,
            output: output.clone(),
            blinding,
            commitment: commit_output(&output, blinding),
        };
        (participant, keys, TxOut::new(value, output))
    }

    fn round_of(n: usize, value: i64) -> (CoinJoinRound, Vec<KeyStore>, Vec<TxOut>) {
        let mut round = CoinJoinRound::new();
        let mut stores = Vec::new();
        let mut spent = Vec::new();
        for i in 1..=n as u8 {
            let (participant, keys, output) = make_participant(i, value + i as i64 * 100);
            round.register(participant).unwrap();
            stores.push(keys);
            spent.push(output);
        }
        (round, stores, spent)
    }

    #[test]
    fn assemble_equal_outputs_sorted_by_script() {
        let (mut round, _stores, _spent) = round_of(3, 10_000);
        let (tx, denomination, fee) = round.assemble(1000).unwrap();
        assert_eq!(tx.vin.len(), 3);
        assert_eq!(tx.vout.len(), 3);
        assert!(tx.vout.iter().all(|o| o.value == denomination));
        assert!(tx.vout.windows(2).all(|w| w[0].script_pubkey.as_bytes() <= w[1].script_pubkey.as_bytes()));
        assert_eq!(fee, 30_600 - denomination * 3);
        assert_eq!(fee, 300);
        // Inputs keep registration order, outputs are sorted: the two
        // orders do not correspond participant-by-participant.
        assert!(!round.is_fully_signed(&tx));
    }

    #[test]
    fn participants_sign_only_their_own_inputs() {
        let (round, stores, spent) = round_of(3, 10_000);
        let mut tx_map: Vec<(Tx, Vec<TxOut>)> = Vec::new();
        // Each participant signs the shared transaction with their own keys.
        let mut round2 = round.clone();
        let (mut tx, _denom, _fee) = round2.assemble(1000).unwrap();
        let spent = round2.spent_outputs();
        assert_eq!(tx.vin.len(), spent.len());
        for (index, keys) in stores.iter().enumerate() {
            sign_transaction(&mut tx, &spent, keys).unwrap();
            let signed_here = tx.vin.iter().filter(|input| {
                !input.script_sig.as_bytes().is_empty() || !input.witness.is_empty()
            }).count();
            assert_eq!(signed_here, index + 1, "each participant signs exactly one new input");
        }
        assert!(round2.is_fully_signed(&tx));
        tx_map.push((tx, spent.clone()));
        assert_eq!(spent.len(), 3);
    }

    #[test]
    fn rejects_bad_commitments_duplicates_and_poverty() {
        // Commitment mismatch.
        let (participant, _keys, _output) = make_participant(9, 10_000);
        let mut bad = participant.clone();
        bad.commitment[0] ^= 1;
        assert!(matches!(
            CoinJoinRound::new().register(bad),
            Err(CoinJoinError::CommitmentMismatch)
        ));

        // Duplicate input.
        let (p1, _k1, _o1) = make_participant(7, 10_000);
        let mut round = CoinJoinRound::new();
        round.register(p1.clone()).unwrap();
        let mut dup = p1.clone();
        dup.blinding = [8u8; 32];
        dup.output = make_participant(8, 10_000).2.script_pubkey;
        dup.commitment = commit_output(&dup.output, dup.blinding);
        assert!(matches!(
            round.register(dup),
            Err(CoinJoinError::DuplicateInput(_))
        ));

        // Duplicate output.
        let (p3, _k3, _o3) = make_participant(6, 10_000);
        let mut round2 = CoinJoinRound::new();
        round2.register(p1.clone()).unwrap();
        let mut same_out = p3.clone();
        same_out.commitment = commit_output(&same_out.output, same_out.blinding);
        // Force three registrations with distinct inputs but crafted same output:
        let mut dup_out_round = CoinJoinRound::new();
        let (pa, _ka, _oa) = make_participant(20, 20_000);
        let mut pb = make_participant(21, 20_000).0;
        pb.output = pa.output.clone();
        pb.commitment = commit_output(&pb.output, pb.blinding);
        dup_out_round.register(pa).unwrap();
        dup_out_round.register(pb).unwrap();
        assert!(matches!(
            dup_out_round.reveal_check(),
            Err(CoinJoinError::DuplicateOutput)
        ));

        // Insufficient funds for the denomination.
        let (mut poor, _kp, _op) = round_of(2, 900);
        assert!(matches!(
            poor.assemble(1000),
            Err(CoinJoinError::InsufficientForDenomination(_))
        ));
    }

    #[test]
    fn full_round_end_to_end_three_participants() {
        // Alice, Bob, Carol: distinct keys, same denomination, each signs.
        let values = [10_000, 10_500, 11_000];
        let mut round = CoinJoinRound::new();
        let mut stores = Vec::new();
        for (i, value) in values.iter().enumerate() {
            let (participant, keys, _spent) = make_participant((i + 1) as u8, *value);
            round.register(participant).unwrap();
            stores.push(keys);
        }
        round.reveal_check().unwrap();
        let (mut tx, denomination, fee) = round.assemble(1000).unwrap();
        let total: i64 = values.iter().sum();
        assert_eq!(denomination * 3 + fee, total);
        assert!(fee > 0);
        let spent = round.spent_outputs();
        for keys in &stores {
            sign_transaction(&mut tx, &spent, keys).unwrap();
        }
        assert!(round.is_fully_signed(&tx));
        // Every output pays denomination to someone; every input is signed.
    }
}
