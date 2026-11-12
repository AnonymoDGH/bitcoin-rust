//! Single-party Groth16 setup for the value-hiding SNARK, and key loading.
//!
//! `btc-node -snarksetup=<dir>` writes:
//!
//! * `snark_pk.bin`  proving key (compressed, ark-serialize) — keep private to
//!   wallets that spend shielded notes; it is NOT secret in the cryptographic
//!   sense but is large (it is what provers load).
//! * `snark_vk.bin`  verifying key (compressed) — consensus data.
//! * `snark_vk.hex`  hex of the verifying key: paste it into the chain spec as
//!   `"snark_vk": "<hex>"`.
//!
//! # WARNING: single-party setup
//!
//! The process that runs this saw the setup's toxic waste (`alpha, beta,
//! gamma, delta, tau`) in memory. Anybody who obtains it can forge proofs of
//! any statement, i.e. mint unlimited shielded value. A single-party setup
//! is acceptable ONLY for development and test networks. Before a mainnet a
//! multi-party computation ceremony (see `docs/privacy-plan.md`, "SNARK
//! trusted setup") must produce the keys, with at least one honest
//! participant destroying their contribution, and the resulting verifying
//! key hash must be published and pinned in the chain spec.

use std::fs;
use std::path::Path;

use bitcoin::hex::DisplayHex;
use btc_chain::value_snark;

/// Result of a setup run (for logging).
pub struct SetupOutput {
    /// SHA-256 of the verifying key bytes.
    pub vk_sha256: [u8; 32],
    pub vk_hex: String,
}

/// Runs a single-party OS-RNG setup and writes the key files into `dir`.
pub fn run_snark_setup(dir: &Path) -> Result<SetupOutput, String> {
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (pk, vk) = value_snark::generate_parameters_os().map_err(|e| format!("setup failed: {e}"))?;
    let pk_bytes = value_snark::pk_to_bytes(&pk);
    let vk_bytes = value_snark::vk_to_bytes(&vk);
    let vk_hex = vk_bytes.to_lower_hex_string();
    for (name, data) in [
        ("snark_pk.bin", pk_bytes.as_slice()),
        ("snark_vk.bin", vk_bytes.as_slice()),
        ("snark_vk.hex", vk_hex.as_bytes()),
    ] {
        let path = dir.join(name);
        fs::write(&path, data).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(SetupOutput {
        vk_sha256: value_snark::vk_sha256(&vk_bytes),
        vk_hex,
    })
}

/// Loads `snark_pk.bin` from `dir` if present and checks it belongs to the
/// chain-pinned verifying key. `Ok(None)` when there is no file.
pub fn load_proving_key(
    dir: &Path,
    pinned_vk: Option<&[u8]>,
) -> Result<Option<value_snark::SnarkProvingKey>, String> {
    let path = dir.join("snark_pk.bin");
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let pk = value_snark::pk_from_bytes(&bytes)
        .ok_or_else(|| format!("{}: not a valid proving key", path.display()))?;
    match pinned_vk {
        Some(vk) if value_snark::vk_to_bytes(&pk.vk) == vk => Ok(Some(pk)),
        Some(_) => Err(format!(
            "{}: proving key does not match the chain's pinned verifying key",
            path.display()
        )),
        None => Err("a proving key is present but the chain pins no verifying key".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_writes_loadable_matching_keys() {
        let dir = std::env::temp_dir().join(format!("anoncoin-snark-setup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let out = run_snark_setup(&dir).expect("setup");
        let vk_bytes = fs::read(dir.join("snark_vk.bin")).unwrap();
        assert_eq!(value_snark::vk_sha256(&vk_bytes), out.vk_sha256);
        assert_eq!(out.vk_hex, vk_bytes.to_lower_hex_string());
        // Matching pinned vk loads; a different or absent pin is refused.
        assert!(load_proving_key(&dir, Some(&vk_bytes)).unwrap().is_some());
        assert!(load_proving_key(&dir, None).is_err());
        let (_, other) = value_snark::ephemeral_process_parameters();
        assert!(load_proving_key(&dir, Some(&value_snark::vk_to_bytes(other))).is_err());
        let _ = fs::remove_dir_all(&dir);
        assert!(load_proving_key(&dir, Some(&vk_bytes)).unwrap().is_none());
    }
}
