//! Groth16 value-hiding proofs over pool notes (Privacy Plan, Phase 3+).
//!
//! The hash-note pool reveals every spent value in the witness (the
//! funding ledger bounds it, but it is not private). This module is
//! the SNARK layer that hides spent values: a prover shows, without
//! revealing anything but the public fee, that
//!
//! * the spent note's value commitment opens (`C_old = v_old + h(rcm_old)`),
//! * `v_old` is fully allocated: `v_old = v_new0 + v_new1 + fee`,
//! * every new value is in range and `v_old <= cap` (the issuance
//!   funding cap from `notes::funding_caps_for_block`),
//! * each new commitment opens (`C_new_i = v_new_i + h(rcm_new_i)`).
//!
//! Public inputs: `(fee, cap, C_old, C_new0, C_new1)`. The verifier
//! learns only that a funded note of at most `cap` backs new notes
//! totalling `v_old - fee`.
//!
//! Honest prototype limits: commitments are field elements with the
//! linear stand-in hash (`C = value + rcm`) over BN254's scalar
//! field — binding to the note's `cmu` hash / Pedersen commitment
//! and consensus activation are the next wiring step. Merkle
//! membership and spend authorisation stay with `notes.rs`.

use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use ark_ff::{One, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination, SynthesisError,
    Variable,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

/// Field element type of the value circuit.
pub type Field = Fr;

/// Number of new notes in one value-hiding spend (fixed by the circuit).
pub const NEW_NOTES: usize = 2;

/// Value range bits enforced for every value and for `cap - v_old`.
pub const VALUE_BITS: usize = 64;

/// Algebraic stand-in hash. Prototype uses the identity map (linear
/// commitment `C = value + rcm`); production binds to the note hash
/// / Pedersen commitment. Hiding comes from the secret `rcm`.
fn hash_field(x: Fr) -> Fr {
    x
}

/// Value commitment: `C = value + h(rcm)`, `rcm` read big-endian.
pub fn value_commitment(value: u64, rcm: &[u8; 32]) -> Fr {
    Fr::from(value) + hash_field(Fr::from_be_bytes_mod_order(rcm))
}

/// Public statement of one value-hiding spend.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ValueTranscript {
    /// Public miner fee (sats).
    pub fee: u64,
    /// Funding cap of the spent note (sats, public from the ledger).
    pub cap: u64,
    /// Commitment of the spent note.
    pub c_old: Fr,
    /// Commitments of the two new notes.
    pub c_new: [Fr; NEW_NOTES],
}

/// Private witness for one value-hiding spend.
#[derive(Clone, Copy)]
pub struct ValueWitness {
    pub v_old: u64,
    pub rcm_old: [u8; 32],
    pub v_new: [u64; NEW_NOTES],
    pub rcm_new: [[u8; 32]; NEW_NOTES],
}

struct ValueCircuit {
    transcript: Option<ValueTranscript>,
    witness: Option<ValueWitness>,
}

fn lc_var(var: Variable) -> LinearCombination<Fr> {
    LinearCombination(vec![(Fr::from(1u64), var)])
}

fn one_lc() -> LinearCombination<Fr> {
    lc_var(Variable::One)
}

fn ok<T>(v: Option<T>) -> Result<T, SynthesisError> {
    v.map(Ok).unwrap_or(Err(SynthesisError::AssignmentMissing))
}

impl ConstraintSynthesizer<Fr> for ValueCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
        let t = self.transcript;
        let w = self.witness;
        // Public inputs, in verification order.
        let fee = cs.new_input_variable(|| ok(t.map(|t| Fr::from(t.fee))))?;
        let cap = cs.new_input_variable(|| ok(t.map(|t| Fr::from(t.cap))))?;
        let c_old = cs.new_input_variable(|| ok(t.map(|t| t.c_old)))?;
        let mut c_new = [Variable::One; NEW_NOTES];
        for i in 0..NEW_NOTES {
            c_new[i] = cs.new_input_variable(|| ok(t.map(|t| t.c_new[i])))?;
        }
        // Private inputs.
        let v_old = cs.new_witness_variable(|| ok(w.map(|w| Fr::from(w.v_old))))?;
        let rcm_old =
            cs.new_witness_variable(|| ok(w.map(|w| Fr::from_be_bytes_mod_order(&w.rcm_old))))?;
        let mut v_new = [Variable::One; NEW_NOTES];
        let mut rcm_new = [Variable::One; NEW_NOTES];
        for i in 0..NEW_NOTES {
            v_new[i] = cs.new_witness_variable(|| ok(w.map(|w| Fr::from(w.v_new[i]))))?;
            rcm_new[i] =
                cs.new_witness_variable(|| ok(w.map(|w| Fr::from_be_bytes_mod_order(&w.rcm_new[i]))))?;
        }
        // C_old opens: c_old == v_old + h(rcm_old) with h = identity.
        cs.enforce_constraint(
            lc_var(c_old),
            one_lc(),
            lc_var(v_old) + lc_var(rcm_old),
        )?;
        // Every new commitment opens; values decompose.
        let mut allocated = LinearCombination::<Fr>::default();
        for i in 0..NEW_NOTES {
            cs.enforce_constraint(
                lc_var(c_new[i]),
                one_lc(),
                lc_var(v_new[i]) + lc_var(rcm_new[i]),
            )?;
            decompose(&cs, v_new[i], w.map(|w| w.v_new[i]))?;
            allocated = allocated + lc_var(v_new[i]);
        }
        // v_old == v_new0 + v_new1 + fee.
        cs.enforce_constraint(lc_var(v_old), one_lc(), allocated + lc_var(fee))?;
        // v_old <= cap and v_old >= 0 via bit decomposition of cap - v_old.
        let diff_value = match (t, w) {
            (Some(t), Some(w)) => Some(t.cap.wrapping_sub(w.v_old)),
            _ => None,
        };
        let diff = cs.new_witness_variable(|| {
            let c = t.map(|t| Fr::from(t.cap));
            let v = w.map(|w| Fr::from(w.v_old));
            ok(c.zip(v).map(|(c, v)| c - v))
        })?;
        let neg_v_old = LinearCombination(vec![(-Fr::one(), v_old)]);
        cs.enforce_constraint(lc_var(diff), one_lc(), lc_var(cap) + neg_v_old)?;
        decompose(&cs, diff, diff_value)?;
        // v_old itself decomposes (non-negativity on the nose).
        decompose(&cs, v_old, w.map(|w| w.v_old))?;
        Ok(())
    }
}

/// Enforces `var == sum_i 2^i * bit_i` with boolean bits.
fn decompose(
    cs: &ConstraintSystemRef<Fr>,
    var: Variable,
    value: Option<u64>,
) -> ark_relations::r1cs::Result<()> {
    let mut terms = Vec::with_capacity(VALUE_BITS);
    for i in 0..VALUE_BITS {
        let bit = cs.new_witness_variable(|| ok(value.map(|v| Fr::from((v >> i) & 1))))?;
        // b * b == b.
        let sq = cs.new_witness_variable(|| ok(value.map(|v| Fr::from((v >> i) & 1))))?;
        cs.enforce_constraint(lc_var(bit), lc_var(bit), lc_var(sq))?;
        cs.enforce_constraint(lc_var(sq), one_lc(), lc_var(bit))?;
        terms.push((Fr::from(1u64 << i), bit));
    }
    cs.enforce_constraint(lc_var(var), one_lc(), LinearCombination(terms))?;
    Ok(())
}

struct Keys {
    pk: ark_groth16::ProvingKey<Bn254>,
    pvk: PreparedVerifyingKey<Bn254>,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let empty = ValueCircuit {
            transcript: None,
            witness: None,
        };
        let mut rng = StdRng::seed_from_u64(0xA0C0);
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(empty, &mut rng)
            .expect("Groth16 setup");
        let pvk = prepare_verifying_key(&pk.vk);
        Keys { pvk, pk }
    })
}

/// Checks the statement against a witness without proving it.
/// `false` for inflation / over-cap / bad openings.
pub fn is_statement_satisfiable(transcript: ValueTranscript, witness: ValueWitness) -> bool {
    let circuit = ValueCircuit {
        transcript: Some(transcript),
        witness: Some(witness),
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    if circuit.generate_constraints(cs.clone()).is_err() {
        return false;
    }
    cs.is_satisfied().unwrap_or(false)
}

/// Proves a value-hiding spend. Panics (via the Groth16 prover) if
/// the witness is unsatisfiable — check `is_statement_satisfiable`
/// first for untrusted input.
pub fn prove(
    transcript: ValueTranscript,
    witness: ValueWitness,
) -> ark_relations::r1cs::Result<Proof<Bn254>> {
    let circuit = ValueCircuit {
        transcript: Some(transcript),
        witness: Some(witness),
    };
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &keys().pk, &mut rng)
}

/// Verifies a value-hiding proof against its public transcript.
pub fn verify(transcript: ValueTranscript, proof: &Proof<Bn254>) -> bool {
    let public = [
        Fr::from(transcript.fee),
        Fr::from(transcript.cap),
        transcript.c_old,
        transcript.c_new[0],
        transcript.c_new[1],
    ];
    let prepared = match Groth16::<Bn254>::prepare_inputs(&keys().pvk, &public) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Groth16::<Bn254>::verify_proof_with_prepared_inputs(&keys().pvk, proof, &prepared)
        .unwrap_or(false)
}

/// Encodes a field element in canonical compressed form (32 bytes).
pub fn field_to_bytes(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    f.serialize_compressed(&mut out.as_mut_slice())
        .expect("field element fits");
    out
}

/// Decodes a field element from canonical compressed form.
pub fn bytes_to_field(bytes: &[u8]) -> Fr {
    Fr::deserialize_compressed(bytes).unwrap_or(Fr::default())
}

/// Witness proof encoding: `a (32) || b (64) || c (32)` compressed
/// affine coordinates (x-coordinate only) — 128 bytes total.
pub fn serialize_proof(proof: &Proof<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    proof.a.serialize_compressed(&mut out).expect("G1 fits");
    proof.b.serialize_compressed(&mut out).expect("G2 fits");
    proof.c.serialize_compressed(&mut out).expect("G1 fits");
    debug_assert_eq!(out.len(), 128);
    out
}

/// Decodes a witness proof encoding. `None` on malformed bytes.
pub fn deserialize_proof(bytes: &[u8]) -> Option<Proof<Bn254>> {
    use ark_bn254::{G1Affine, G2Affine};
    if bytes.len() != 128 {
        return None;
    }
    let a = G1Affine::deserialize_compressed(&bytes[0..32]).ok()?;
    let b = G2Affine::deserialize_compressed(&bytes[32..96]).ok()?;
    let c = G1Affine::deserialize_compressed(&bytes[96..128]).ok()?;
    Some(Proof { a, b, c })
}

/// Transcript for a pool-note spend paid to transparent outputs:
/// the single new "note" slot carries the outputs total. Bound to the
/// spent note via `C_old = value_commitment(value, rcm)` (the same
/// `(value, rcm)` the `cmu` hash pins).
pub fn transcript_for_spend(
    note: &crate::notes::Note,
    outputs_total: u64,
    fee: u64,
    cap: u64,
) -> ValueTranscript {
    const DUMMY_RCM: [u8; 32] = [0; 32];
    ValueTranscript {
        fee,
        cap,
        c_old: value_commitment(note.value, &note.rcm),
        c_new: [
            value_commitment(outputs_total, &DUMMY_RCM),
            value_commitment(0, &DUMMY_RCM),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript_and_witness() -> (ValueTranscript, ValueWitness) {
        let rcm_old = [7u8; 32];
        let rcm_new = [[8u8; 32], [9u8; 32]];
        let v_old = 100_000_000u64;
        let v_new = [60_000_000u64, 39_999_000u64];
        let fee = 1_000u64;
        let transcript = ValueTranscript {
            fee,
            cap: v_old,
            c_old: value_commitment(v_old, &rcm_old),
            c_new: [
                value_commitment(v_new[0], &rcm_new[0]),
                value_commitment(v_new[1], &rcm_new[1]),
            ],
        };
        let witness = ValueWitness {
            v_old,
            rcm_old,
            v_new,
            rcm_new,
        };
        (transcript, witness)
    }

    #[test]
    fn valid_value_hiding_proof_verifies() {
        let (transcript, witness) = transcript_and_witness();
        assert!(is_statement_satisfiable(transcript, witness));
        let proof = prove(transcript, witness).expect("valid witness proves");
        assert!(verify(transcript, &proof));
    }

    #[test]
    fn tampered_fee_rejected() {
        let (transcript, witness) = transcript_and_witness();
        let proof = prove(transcript, witness).expect("valid witness proves");
        let mut bad = transcript;
        bad.fee += 1;
        assert!(!verify(bad, &proof));
    }

    #[test]
    fn inflated_values_cannot_prove() {
        let (mut transcript, mut witness) = transcript_and_witness();
        // Claim the new notes are worth more than v_old covers.
        witness.v_new[0] += 50_000_000;
        transcript.c_new[0] = value_commitment(witness.v_new[0], &witness.rcm_new[0]);
        assert!(!is_statement_satisfiable(transcript, witness));
    }

    #[test]
    fn over_cap_cannot_prove() {
        let (mut transcript, witness) = transcript_and_witness();
        // Cap below the spent value.
        transcript.cap = witness.v_old - 1;
        assert!(!is_statement_satisfiable(transcript, witness));
    }

    #[test]
    fn wrong_opening_cannot_prove() {
        let (transcript, mut witness) = transcript_and_witness();
        witness.rcm_old = [1u8; 32];
        assert!(!is_statement_satisfiable(transcript, witness));
    }
}
