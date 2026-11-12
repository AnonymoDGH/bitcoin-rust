//! Decentralised CoinJoin rounds (Privacy Plan, Phase 1).
//!
//! N participants contribute one input each and receive one equal-value
//! output. Outputs are indistinguishable, so an observer cannot tell
//! which input paid which output — the cluster built by
//! common-input-ownership in a normal spend dissolves.
//!
//! The protocol is transport-agnostic and coordinator-free:
//!
//! 1. **Register**: each participant submits an outpoint, the script it
//!    spends, its output and a commitment `SHA256(script_pubkey ||
//!    blinding)`. NOTE: in this in-process model the output and blinding
//!    travel with the registration, so the commitment is only checked for
//!    consistency; a networked protocol must split announce and reveal into
//!    two rounds to get real commit-then-reveal hiding.
//! 2. **Reveal check**: commitments are re-verified and all outputs must be
//!    distinct.
//! 3. **Assemble**: one unsigned transaction is built with each
//!    participant's input and one equal-value output each, outputs
//!    sorted by script so position does not correlate with input order.
//! 4. **Sign**: each participant first runs [`CoinJoinRound::verify_for_signing`]
//!    (every output is a registered output at one equal value, my own
//!    output is paid, I lose at most `max_loss`) and then signs only their
//!    own input with their own [`KeyStore`]. A peer that assembles a
//!    different transaction (substituted outputs, skimmed value) gets no
//!    signature.
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
/// Upper bound on round size (keeps assembly and verification bounded).
pub const MAX_PARTICIPANTS: usize = 16;

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
    #[error("round is full ({0} participants)")]
    RoundFull(usize),
    #[error("assembled transaction does not match the round: {0}")]
    TxMismatch(&'static str),
    #[error("my input is not part of this round")]
    NotParticipant,
    #[error("round would cost {loss} sat, more than the {max_loss} sat I accept")]
    UnfairShare { loss: i64, max_loss: i64 },
    #[error("random number generation failed: {0}")]
    Random(#[from] getrandom::Error),
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
    /// `scriptPubKey` of the UTXO being spent (needed for the sighash; it is
    /// *not* the mixed output script).
    pub input_script: ScriptBuf,
    /// Where the mixed output is paid (in cleartext, equal value).
    pub output: ScriptBuf,
    /// Random blinding that hides `output` inside the commitment.
    pub blinding: [u8; 32],
    /// `commit_output(output, blinding)`, announced before reveals.
    pub commitment: [u8; 32],
}

impl Participant {
    /// Registers `input` and a fresh `output`, drawing the blinding from the
    /// OS RNG (never from a fixed or derived value).
    pub fn new(
        input: OutPoint,
        input_value: i64,
        input_script: ScriptBuf,
        output: ScriptBuf,
    ) -> Result<Self, CoinJoinError> {
        let mut blinding = [0u8; 32];
        getrandom::getrandom(&mut blinding)?;
        let commitment = commit_output(&output, blinding);
        Ok(Self { input, input_value, input_script, output, blinding, commitment })
    }
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
        if self.participants.len() >= MAX_PARTICIPANTS {
            return Err(CoinJoinError::RoundFull(self.participants.len()));
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

    /// The spent outputs (in input order) needed by `sign_transaction`:
    /// the UTXOs being consumed (their own scripts), not the mixed outputs.
    pub fn spent_outputs(&self) -> Vec<TxOut> {
        self.participants
            .iter()
            .map(|p| TxOut::new(p.input_value, p.input_script.clone()))
            .collect()
    }

    /// Checks that `tx` is exactly the transaction this round describes and
    /// that signing it costs the participant spending `my_input` at most
    /// `max_loss` satoshis (their fee share). Run this on whatever
    /// transaction a peer hands you *before* signing it:
    ///
    /// * inputs are the registered outpoints, in registration order;
    /// * outputs are exactly the registered output scripts, one each, all
    ///   paying the same value (no skimmed or substituted output);
    /// * `my_input_value - denomination <= max_loss`, so a participant who
    ///   registered a tiny input cannot have the others pay for it.
    pub fn verify_for_signing(
        &self,
        tx: &Tx,
        my_input: &OutPoint,
        max_loss: i64,
    ) -> Result<(), CoinJoinError> {
        let n = self.participants.len();
        self.reveal_check()?;
        if tx.version != TX_VERSION || tx.lock_time != 0 {
            return Err(CoinJoinError::TxMismatch("version or locktime"));
        }
        if tx.vin.len() != n || tx.vout.len() != n {
            return Err(CoinJoinError::TxMismatch("input or output count"));
        }
        for (input, participant) in tx.vin.iter().zip(&self.participants) {
            if input.prevout != participant.input {
                return Err(CoinJoinError::TxMismatch("input outpoints"));
            }
            if input.sequence != SEQUENCE {
                return Err(CoinJoinError::TxMismatch("input sequence"));
            }
        }
        let denomination = tx.vout[0].value;
        if denomination < MIN_DENOMINATION || tx.vout.iter().any(|o| o.value != denomination) {
            return Err(CoinJoinError::TxMismatch("outputs are not equal-valued"));
        }
        let mut expected: Vec<&[u8]> =
            self.participants.iter().map(|p| p.output.as_bytes()).collect();
        let mut actual: Vec<&[u8]> = tx.vout.iter().map(|o| o.script_pubkey.as_bytes()).collect();
        expected.sort_unstable();
        actual.sort_unstable();
        if expected != actual {
            return Err(CoinJoinError::TxMismatch("output scripts"));
        }
        let input_sum: i64 = self.participants.iter().map(|p| p.input_value).sum();
        if denomination.checked_mul(n as i64).is_none_or(|out| out > input_sum) {
            return Err(CoinJoinError::TxMismatch("outputs exceed inputs"));
        }
        let mine = self
            .participants
            .iter()
            .find(|p| p.input == *my_input)
            .ok_or(CoinJoinError::NotParticipant)?;
        let loss = mine.input_value - denomination;
        if loss > max_loss {
            return Err(CoinJoinError::UnfairShare { loss, max_loss });
        }
        Ok(())
    }

    /// Verifies `tx` against the round (see [`verify_for_signing`]
    /// (Self::verify_for_signing)) and then signs only the inputs this
    /// keystore owns. Each participant calls this with their own keystore;
    /// others' inputs stay untouched. Signatures are SIGHASH_ALL.
    pub fn sign_my_inputs(
        &self,
        tx: &mut Tx,
        keys: &KeyStore,
        my_input: &OutPoint,
        max_loss: i64,
    ) -> Result<(), CoinJoinError> {
        self.verify_for_signing(tx, my_input, max_loss)?;
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

    fn p2wpkh(keys: &KeyStore, id: &crate::keys::KeyId) -> ScriptBuf {
        keys.script_pubkeys(id)
            .unwrap()
            .iter()
            .find_map(|(kind, script)| (*kind == ScriptKind::P2wpkh).then_some(script.clone()))
            .unwrap()
    }

    /// Participant with a funded input key and a *different*, fresh output
    /// key (the realistic case: mixed outputs never reuse the input address).
    fn make_participant(i: u8, value: i64) -> (Participant, KeyStore, TxOut) {
        let mut keys = KeyStore::new();
        let in_id = keys.generate().unwrap();
        let out_id = keys.generate().unwrap();
        let input_script = p2wpkh(&keys, &in_id);
        let output = p2wpkh(&keys, &out_id);
        let input = OutPoint::new(bitcoin::Txid::from_slice(&[i; 32]).unwrap(), 0);
        let blinding = [i; 32];
        let participant = Participant {
            input,
            input_value: value,
            input_script: input_script.clone(),
            output,
            blinding,
            commitment: commit_output(&p2wpkh(&keys, &out_id), blinding),
        };
        (participant, keys, TxOut::new(value, input_script))
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
            round2
                .sign_my_inputs(&mut tx, keys, &round2.participants[index].input, 1_000)
                .unwrap();
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
        dup.output = make_participant(8, 10_000).0.output;
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
        let _ = &same_out;
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

    fn assembled(n: usize, value: i64) -> (CoinJoinRound, Vec<KeyStore>, Tx) {
        let (mut round, stores, _spent) = round_of(n, value);
        let (tx, _d, _f) = round.assemble(1000).unwrap();
        (round, stores, tx)
    }

    fn unsigned(tx: &Tx) -> bool {
        tx.vin.iter().all(|i| i.script_sig.as_bytes().is_empty() && i.witness.is_empty())
    }

    /// Audit: `sign_my_inputs` signed whatever transaction it was handed. A
    /// peer that replaced an honest participant's output with its own got a
    /// valid SIGHASH_ALL signature over the theft.
    #[test]
    fn refuses_to_sign_a_substituted_output() {
        let (round, stores, tx) = assembled(3, 10_000);
        let my_input = round.participants[0].input;
        // Evil assembler pays one output to itself instead.
        let mut evil = tx.clone();
        evil.vout[1].script_pubkey = make_participant(99, 10_000).0.output;
        assert!(matches!(
            round.sign_my_inputs(&mut evil, &stores[0], &my_input, 1_000),
            Err(CoinJoinError::TxMismatch("output scripts"))
        ));
        assert!(unsigned(&evil), "nothing may be signed on a rejected tx");
        // The honest transaction is accepted.
        let mut ok = tx;
        round.sign_my_inputs(&mut ok, &stores[0], &my_input, 1_000).unwrap();
    }

    /// Audit: lowering every output value diverts the difference to the miner
    /// (or to whoever mines the coinjoin) and equal outputs still look fine.
    #[test]
    fn refuses_to_sign_when_value_is_skimmed() {
        let (round, stores, mut tx) = assembled(3, 10_000);
        let my_input = round.participants[0].input;
        for out in &mut tx.vout {
            out.value -= 5_000;
        }
        assert!(matches!(
            round.sign_my_inputs(&mut tx, &stores[0], &my_input, 1_000),
            Err(CoinJoinError::UnfairShare { .. })
        ));
        assert!(unsigned(&tx));
    }

    /// Audit: outputs of a round are all `sum(inputs)/n`. A participant who
    /// registers a tiny input is paid the average, funded by the others.
    #[test]
    fn rich_participant_refuses_a_round_with_a_freeloader() {
        let mut round = CoinJoinRound::new();
        let (rich, rich_keys, _) = make_participant(1, 1_000_000);
        let (rich2, _k2, _) = make_participant(2, 1_000_000);
        let (cheap, _k3, _) = make_participant(3, 1_500);
        let rich_input = rich.input;
        for p in [rich, rich2, cheap] {
            round.register(p).unwrap();
        }
        let (mut tx, denom, _fee) = round.assemble(1000).unwrap();
        assert!(denom > 600_000, "freeloader is paid the average");
        assert!(matches!(
            round.sign_my_inputs(&mut tx, &rich_keys, &rich_input, 1_000),
            Err(CoinJoinError::UnfairShare { .. })
        ));
        assert!(unsigned(&tx));
    }

    #[test]
    fn refuses_unequal_outputs_wrong_inputs_and_strangers() {
        let (round, stores, tx) = assembled(3, 10_000);
        let my_input = round.participants[0].input;

        let mut unequal = tx.clone();
        unequal.vout[0].value += 1;
        assert!(matches!(
            round.sign_my_inputs(&mut unequal, &stores[0], &my_input, 1_000),
            Err(CoinJoinError::TxMismatch(_))
        ));
        let mut swapped = tx.clone();
        swapped.vin.swap(0, 1);
        assert!(matches!(
            round.sign_my_inputs(&mut swapped, &stores[0], &my_input, 1_000),
            Err(CoinJoinError::TxMismatch("input outpoints"))
        ));
        let mut extra = tx.clone();
        extra.vout.push(extra.vout[0].clone());
        assert!(matches!(
            round.sign_my_inputs(&mut extra, &stores[0], &my_input, 1_000),
            Err(CoinJoinError::TxMismatch(_))
        ));
        let stranger = OutPoint::new(bitcoin::Txid::from_slice(&[0xee; 32]).unwrap(), 0);
        let mut plain = tx;
        assert!(matches!(
            round.sign_my_inputs(&mut plain, &stores[0], &stranger, 1_000),
            Err(CoinJoinError::NotParticipant)
        ));
    }

    /// Audit: `spent_outputs` used the participant's *mixed output* script as
    /// the script of the UTXO being spent, which only worked when the output
    /// reused the input address. With distinct addresses (the whole point) the
    /// sighash committed to the wrong script and the tx was invalid on chain.
    #[test]
    fn signs_with_the_real_input_script_and_sighash_all() {
        let (round, stores, mut tx) = assembled(2, 20_000);
        let spent = round.spent_outputs();
        for (participant, out) in round.participants.iter().zip(&spent) {
            assert_eq!(out.script_pubkey, participant.input_script);
            assert_ne!(out.script_pubkey, participant.output);
        }
        for (i, keys) in stores.iter().enumerate() {
            let input = round.participants[i].input;
            round.sign_my_inputs(&mut tx, keys, &input, 1_000).unwrap();
        }
        assert!(round.is_fully_signed(&tx));
        for input in &tx.vin {
            let sig = input.witness.nth(0).unwrap();
            assert_eq!(*sig.last().unwrap(), 0x01, "SIGHASH_ALL");
        }
    }

    #[test]
    fn blinding_comes_from_the_os_rng_and_round_size_is_bounded() {
        let key = |i: u8| OutPoint::new(bitcoin::Txid::from_slice(&[i; 32]).unwrap(), 0);
        let script = |i: u8| ScriptBuf::from_bytes(vec![0x51, i]);
        let a = Participant::new(key(1), 5_000, script(1), script(2)).unwrap();
        let b = Participant::new(key(1), 5_000, script(1), script(2)).unwrap();
        assert_ne!(a.blinding, b.blinding);
        assert_ne!(a.commitment, b.commitment);
        assert_eq!(a.commitment, commit_output(&a.output, a.blinding));

        let mut round = CoinJoinRound::new();
        for i in 0..MAX_PARTICIPANTS as u8 {
            round
                .register(Participant::new(key(i), 5_000, script(i), script(100 + i)).unwrap())
                .unwrap();
        }
        let over = Participant::new(key(200), 5_000, script(200), script(250)).unwrap();
        assert!(matches!(round.register(over), Err(CoinJoinError::RoundFull(_))));
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
        let inputs: Vec<OutPoint> = round.participants.iter().map(|p| p.input).collect();
        for (keys, input) in stores.iter().zip(&inputs) {
            round.sign_my_inputs(&mut tx, keys, input, 1_000).unwrap();
        }
        let _ = spent;
        assert!(round.is_fully_signed(&tx));
        // Every output pays denomination to someone; every input is signed.
    }
}
