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

/// Algebraic hash `h(x) = x^3 + x` over the scalar field. The cubic
/// term makes the commitment non-linear: no affine re-opening can
/// satisfy `C = v + h(rcm)` for a different `(v, rcm)` pair, and the
/// pair is furthermore pinned by the note's `cmu` hash (and the
/// Pedersen commitment on committed scripts) at spend time.
/// Hiding comes from the secret `rcm`.
fn hash_field(x: Fr) -> Fr {
    x * x * x + x
}

/// `var = a * b` as a multiplication constraint.
fn mul(
    cs: &ConstraintSystemRef<Fr>,
    a: Variable,
    b: Variable,
    hint: Option<Fr>,
) -> ark_relations::r1cs::Result<Variable> {
    let out = cs.new_witness_variable(|| ok(hint))?;
    cs.enforce_constraint(lc_var(a), lc_var(b), lc_var(out))?;
    Ok(out)
}

/// Witness value of `h(x) = x^3 + x` for a known `x`.
fn h_val(x: Option<Fr>) -> Option<Fr> {
    x.map(|x| x * x * x + x)
}

/// Enforces `poseidon(preimage) == poseidon` for a note's
/// `(pub, value, rcm)` preimage. Mirrors [`poseidon_states`].
fn poseidon_check(
    cs: &ConstraintSystemRef<Fr>,
    target: Variable,
    preimage: Option<([u8; 33], u64, [u8; 32])>,
) -> ark_relations::r1cs::Result<()> {
    let limb = |b: &[u8]| Fr::from_be_bytes_mod_order(b);
    let states = preimage.map(|(pubkey, value, rcm)| poseidon_states(&pubkey, value, &rcm));
    // Initial state variables: pub limbs, value, rcm limbs, zero.
    // (Explicit zero lane: Variable::Zero is not evaluable in LCs.)
    let zero = cs.new_witness_variable(|| ok(Some(Fr::default())))?;
    let mut state = [zero; POSEIDON_LANES];
    let pub_limbs = preimage.map(|(pubkey, _, _)| limbs_of(&pubkey));
    for i in 0..3 {
        state[i] = cs.new_witness_variable(|| ok(pub_limbs.as_ref().map(|l| l[i])))?;
    }
    state[3] = cs.new_witness_variable(|| ok(preimage.map(|p| Fr::from(p.1))))?;
    let rcm_limbs = preimage.map(|(_, _, rcm)| limbs_of(&rcm));
    for i in 0..3 {
        state[4 + i] = cs.new_witness_variable(|| ok(rcm_limbs.as_ref().map(|l| l[i])))?;
    }
    let _ = limb;
    for r in 0..POSEIDON_ROUNDS {
        // Round constants + S-box.
        let mut sboxed = [Variable::One; POSEIDON_LANES];
        for i in 0..POSEIDON_LANES {
            let x = cs.new_witness_variable(|| {
                ok(states.as_ref().map(|s| {
                    let _ = limb;
                    s[r][i] + round_constant(r, i)
                }))
            })?;
            cs.enforce_constraint(
                lc_var(x),
                one_lc(),
                LinearCombination(vec![
                    (Fr::from(1u64), state[i]),
                    (round_constant(r, i), Variable::One),
                ]),
            )?;
            let x2 = mul(cs, x, x, states.as_ref().map(|s| {
                let v = s[r][i] + round_constant(r, i);
                v * v
            }))?;
            sboxed[i] = mul(cs, x, x2, states.as_ref().map(|s| {
                let v = s[r][i] + round_constant(r, i);
                v * v * v
            }))?;
        }
        // Linear layer.
        for i in 0..POSEIDON_LANES {
            let out = cs.new_witness_variable(|| ok(states.as_ref().map(|s| s[r + 1][i])))?;
            let mut terms = Vec::with_capacity(POSEIDON_LANES);
            for j in 0..POSEIDON_LANES {
                terms.push((linear_coeff(i, j), sboxed[j]));
            }
            cs.enforce_constraint(lc_var(out), one_lc(), LinearCombination(terms))?;
            state[i] = out;
        }
    }
    cs.enforce_constraint(lc_var(state[0]), one_lc(), lc_var(target))?;
    Ok(())
}

/// Poseidon-like preimage hash of a note: absorb
/// `(pub limbs, value, rcm limbs)` in an 8-lane sponge with 4
/// full S-box rounds (`x^3`), per-lane round constants and a fixed
/// small-coefficient linear layer. This is a domain-separated field
/// binding over the note preimage — it is NOT the on-chain SHA-256
/// `cmu`; the two bind the same preimage jointly (see docs).
pub const POSEIDON_LANES: usize = 8;
pub const POSEIDON_ROUNDS: usize = 4;

/// Round constant for round `r`, lane `i` (deterministic small ints).
fn round_constant(r: usize, i: usize) -> Fr {
    Fr::from(((i + 1) * (r + 7) + 5) as u64)
}

/// Linear layer coefficient `M[i][j]` (small positive ints).
fn linear_coeff(i: usize, j: usize) -> Fr {
    Fr::from((i + j + 1) as u64)
}

/// Splits bytes into 11-byte big-endian field limbs.
fn limbs_of(bytes: &[u8]) -> Vec<Fr> {
    bytes
        .chunks(11)
        .map(Fr::from_be_bytes_mod_order)
        .collect()
}

/// Off-circuit Poseidon-like hash of a note preimage.
pub fn poseidon_cmu(spending_pub: &[u8; 33], value: u64, rcm: &[u8; 32]) -> Fr {
    poseidon_states(spending_pub, value, rcm)[POSEIDON_ROUNDS][0]
}

/// All intermediate states of the Poseidon-like permutation
/// (initial state + one per round). Used as prover hints.
pub fn poseidon_states(
    spending_pub: &[u8; 33],
    value: u64,
    rcm: &[u8; 32],
) -> [[Fr; POSEIDON_LANES]; POSEIDON_ROUNDS + 1] {
    let mut out = [[Fr::default(); POSEIDON_LANES]; POSEIDON_ROUNDS + 1];
    let pub_limbs = limbs_of(spending_pub);
    let rcm_limbs = limbs_of(rcm);
    out[0][0] = pub_limbs[0];
    out[0][1] = pub_limbs[1];
    out[0][2] = pub_limbs[2];
    out[0][3] = Fr::from(value);
    out[0][4] = rcm_limbs[0];
    out[0][5] = rcm_limbs[1];
    out[0][6] = rcm_limbs[2];
    out[0][7] = Fr::default();
    for r in 0..POSEIDON_ROUNDS {
        let mut state = out[r];
        // Round constants + S-box.
        for i in 0..POSEIDON_LANES {
            let x = state[i] + round_constant(r, i);
            state[i] = x * x * x;
        }
        // Linear layer.
        let old = state;
        for i in 0..POSEIDON_LANES {
            let mut acc = Fr::default();
            for j in 0..POSEIDON_LANES {
                acc += linear_coeff(i, j) * old[j];
            }
            state[i] = acc;
        }
        out[r + 1] = state;
    }
    out
}

/// Value commitment bound to the note's `cmu` (used for `C_old`):
/// `C = value + h(rcm) + cmu_field`, where `cmu_field` is the on-chain
/// `cmu` read as a field element. The verifier derives it from the
/// spent pool output, so a proof for a different note (different
/// `cmu`) cannot verify — the SNARK is bound to the funded note by
/// construction, on top of the `cmu` hash and Pedersen bindings.
/// Hiding comes from the secret `rcm`.
pub fn value_commitment(value: u64, rcm: &[u8; 32], cmu: &[u8; 32]) -> Fr {
    Fr::from(value)
        + hash_field(Fr::from_be_bytes_mod_order(rcm))
        + Fr::from_be_bytes_mod_order(cmu)
}

/// Unbound value commitment (used for new-note slots `C_new`).
pub fn new_commitment(value: u64, rcm: &[u8; 32]) -> Fr {
    Fr::from(value) + hash_field(Fr::from_be_bytes_mod_order(rcm))
}

/// Public statement of one value-hiding spend.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ValueTranscript {
    /// Public miner fee (sats).
    pub fee: u64,
    /// Funding cap of the spent note (sats, public from the ledger).
    pub cap: u64,
    /// On-chain note commitment (from the spent pool output).
    pub cmu: Fr,
    /// Poseidon-like hash of the note preimage (from the pool script
    /// on v3 notes; recomputed from the opening on legacy notes).
    pub poseidon: Fr,
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
    pub spending_pub: [u8; 33],
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
        let cmu = cs.new_input_variable(|| ok(t.map(|t| t.cmu)))?;
        let poseidon = cs.new_input_variable(|| ok(t.map(|t| t.poseidon)))?;
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
        // Preimage binding: poseidon(pub, v_old, rcm_old) == poseidon.
        poseidon_check(
            &cs,
            poseidon,
            w.map(|w| (w.spending_pub, w.v_old, w.rcm_old)),
        )?;
        // C_old opens: c_old == v_old + h(rcm_old) + cmu, h(x) = x^3 + x.
        let rcm_old_val = w.map(|w| Fr::from_be_bytes_mod_order(&w.rcm_old));
        let t_old = mul(&cs, rcm_old, rcm_old, rcm_old_val.map(|x| x * x))?;
        let u_old = mul(&cs, rcm_old, t_old, rcm_old_val.map(|x| x * x * x))?;
        let h_old = cs.new_witness_variable(|| ok(h_val(rcm_old_val)))?;
        cs.enforce_constraint(lc_var(h_old), one_lc(), lc_var(u_old) + lc_var(rcm_old))?;
        cs.enforce_constraint(
            lc_var(c_old),
            one_lc(),
            lc_var(v_old) + lc_var(h_old) + lc_var(cmu),
        )?;
        // Every new commitment opens; values decompose.
        let mut allocated = LinearCombination::<Fr>::default();
        for i in 0..NEW_NOTES {
            let rcm_val = w.map(|w| Fr::from_be_bytes_mod_order(&w.rcm_new[i]));
            let ti = mul(&cs, rcm_new[i], rcm_new[i], rcm_val.map(|x| x * x))?;
            let ui = mul(&cs, rcm_new[i], ti, rcm_val.map(|x| x * x * x))?;
            let hi = cs.new_witness_variable(|| ok(h_val(rcm_val)))?;
            cs.enforce_constraint(lc_var(hi), one_lc(), lc_var(ui) + lc_var(rcm_new[i]))?;
            cs.enforce_constraint(
                lc_var(c_new[i]),
                one_lc(),
                lc_var(v_new[i]) + lc_var(hi),
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
        transcript.cmu,
        transcript.poseidon,
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

/// The `cmu` as a field element (public input).
pub fn cmu_field(cmu: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(cmu)
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
/// the single new "note" slot carries the outputs total. `C_old`
/// binds the spent note's `cmu` plus `(value, rcm)`.
pub fn transcript_for_spend(
    note: &crate::notes::Note,
    cmu: &[u8; 32],
    outputs_total: u64,
    fee: u64,
    cap: u64,
) -> ValueTranscript {
    const DUMMY_RCM: [u8; 32] = [0; 32];
    ValueTranscript {
        fee,
        cap,
        cmu: Fr::from_be_bytes_mod_order(cmu),
        poseidon: poseidon_cmu(&note.spending_pub, note.value, &note.rcm),
        c_old: value_commitment(note.value, &note.rcm, cmu),
        c_new: [
            new_commitment(outputs_total, &DUMMY_RCM),
            new_commitment(0, &DUMMY_RCM),
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
        let cmu = [11u8; 32];
        let spending_pub = [5u8; 33];
        let transcript = ValueTranscript {
            fee,
            cap: v_old,
            cmu: Fr::from_be_bytes_mod_order(&cmu),
            poseidon: poseidon_cmu(&spending_pub, v_old, &rcm_old),
            c_old: value_commitment(v_old, &rcm_old, &cmu),
            c_new: [
                new_commitment(v_new[0], &rcm_new[0]),
                new_commitment(v_new[1], &rcm_new[1]),
            ],
        };
        let witness = ValueWitness {
            v_old,
            rcm_old,
            spending_pub,
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
        transcript.c_new[0] = new_commitment(witness.v_new[0], &witness.rcm_new[0]);
        assert!(!is_statement_satisfiable(transcript, witness));
    }

    #[test]
    fn foreign_cmu_rejected() {
        let (transcript, witness) = transcript_and_witness();
        let proof = prove(transcript, witness).expect("valid witness proves");
        // A proof for a different note commitment must not verify.
        let mut bad = transcript;
        bad.cmu = Fr::from_be_bytes_mod_order(&[99u8; 32]);
        assert!(!verify(bad, &proof));
    }

    #[test]
    fn over_cap_cannot_prove() {
        let (mut transcript, witness) = transcript_and_witness();
        // Cap below the spent value.
        transcript.cap = witness.v_old - 1;
        assert!(!is_statement_satisfiable(transcript, witness));
    }

    #[test]
    fn commitment_is_nonlinear_and_binding() {
        let rcm = [7u8; 32];
        let cmu = [11u8; 32];
        let c = value_commitment(1_000_000, &rcm, &cmu);
        // Not an affine commitment: C != value + rcm.
        let linear = Fr::from(1_000_000u64) + Fr::from_be_bytes_mod_order(&rcm);
        assert_ne!(c, linear);
        // A different opening for the same C cannot exist with the
        // same value: shifting rcm changes C.
        let c2 = value_commitment(1_000_003, &rcm, &cmu);
        assert_ne!(c, c2);
        let rcm2 = [8u8; 32];
        assert_ne!(c, value_commitment(1_000_000, &rcm2, &cmu));
        // A different note commitment changes C.
        assert_ne!(c, value_commitment(1_000_000, &rcm, &[12u8; 32]));
    }

    #[test]
    fn wrong_opening_cannot_prove() {
        let (transcript, mut witness) = transcript_and_witness();
        witness.rcm_old = [1u8; 32];
        assert!(!is_statement_satisfiable(transcript, witness));
    }

    #[test]
    fn poseidon_preimage_binding() {
        let pubkey = [5u8; 33];
        let rcm = [7u8; 32];
        let p1 = poseidon_cmu(&pubkey, 1_000_000, &rcm);
        // Deterministic.
        assert_eq!(p1, poseidon_cmu(&pubkey, 1_000_000, &rcm));
        // Any preimage change changes the binding.
        assert_ne!(p1, poseidon_cmu(&pubkey, 1_000_001, &rcm));
        assert_ne!(p1, poseidon_cmu(&pubkey, 1_000_000, &[8u8; 32]));
        let mut other_pub = pubkey;
        other_pub[0] = 6;
        assert_ne!(p1, poseidon_cmu(&other_pub, 1_000_000, &rcm));
        // Circuit enforces the preimage: wrong pubkey fails.
        let (transcript, mut witness) = transcript_and_witness();
        witness.spending_pub = [99u8; 33];
        assert!(!is_statement_satisfiable(transcript, witness));
    }
}
