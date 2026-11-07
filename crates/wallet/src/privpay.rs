//! Wallet-side Phase 2 (privacy): confidential amounts and ring signatures.
//!
//! Wraps `btc-chain`'s CT/ring primitives so the wallet can create
//! hidden-amount outputs and authorise spends without revealing the
//! input. Amounts stay hidden until spend time, and ring spends hide
//! which of 16 keys signed.

use btc_chain::confidential::{
    create_commitment, verify_ct_transaction, AmountCommitment, BalanceProof, CtError,
};
use btc_chain::ringsig::{sign_ring, verify_ring, RingSignature, RING_SIZE};

pub use btc_chain::confidential::{commitment_point, verify_range};
pub use btc_chain::ringsig::{RingError, RING_SIZE as RING_SIZE_VALUE};

#[derive(Debug, thiserror::Error)]
pub enum PrivPayError {
    #[error(transparent)]
    Ct(#[from] CtError),
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error("random number generation failed: {0}")]
    Random(#[from] getrandom::Error),
}

/// Creates a confidential output for `value` satoshis with a fresh blinding.
/// Returns the commitment and the blinding (keep it: needed to spend).
pub fn confidential_output(value: u64) -> Result<(AmountCommitment, [u8; 32]), PrivPayError> {
    let mut blinding = [0u8; 32];
    loop {
        getrandom::getrandom(&mut blinding)?;
        if bitcoin::secp256k1::SecretKey::from_slice(&blinding).is_ok() {
            break;
        }
    }
    let commitment = create_commitment(value, blinding)?;
    Ok((commitment, blinding))
}

/// Verifies a full confidential transaction (range + balance proofs).
pub fn verify_confidential(
    inputs: &[AmountCommitment],
    outputs: &[AmountCommitment],
    fee: u64,
    proof: &BalanceProof,
    context: &[u8],
) -> Result<(), PrivPayError> {
    verify_ct_transaction(inputs, outputs, fee, proof, context)?;
    Ok(())
}

/// Signs `message` with `secret`, hiding among `ring` (16 pubkeys).
pub fn sign_privately(
    message: &[u8],
    ring: &[[u8; 33]],
    signer: usize,
    secret: &[u8; 32],
) -> Result<RingSignature, PrivPayError> {
    Ok(sign_ring(message, ring, signer, secret)?)
}

/// Verifies a private ring signature.
pub fn verify_privately(
    message: &[u8],
    ring: &[[u8; 33]],
    sig: &RingSignature,
) -> Result<(), PrivPayError> {
    verify_ring(message, ring, sig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn confidential_round_trip_through_wallet_helpers() {
        let (commitment, _blinding) = confidential_output(1_2500_0000).unwrap();
        verify_range(&commitment.commitment, &commitment.proof).unwrap();
    }

    #[test]
    fn private_ring_spend_round_trip() {
        let secp = Secp256k1::new();
        let mut secrets = Vec::new();
        let mut pubs = Vec::new();
        for i in 1..=RING_SIZE as u8 {
            let mut buf = [0u8; 32];
            buf[0] = i;
            buf[31] = 3;
            let sk = SecretKey::from_slice(&buf).unwrap();
            secrets.push(buf);
            pubs.push(PublicKey::from_secret_key(&secp, &sk).serialize());
        }
        let sighash = [9u8; 32];
        let sig = sign_privately(&sighash, &pubs, 2, &secrets[2]).unwrap();
        verify_privately(&sighash, &pubs, &sig).unwrap();
        assert!(verify_privately(&[8u8; 32], &pubs, &sig).is_err());
    }
}
