//! Address encoding and decoding. Port of src/key_io.cpp and src/base58.cpp (delegating primitives to rust-bitcoin).
//!
//! Legacy (Base58Check) and SegWit (bech32 for v0, bech32m for v1+) addresses
//! are converted to and from `scriptPubkey`s. Hashing, Base58Check and bech32
//! checksums come from the `bitcoin` crate.

use bitcoin::address::{Address, FromScriptError, NetworkUnchecked, ParseError};
use bitcoin::bech32::{segwit, Fe32, Hrp};
use bitcoin::{Network as BtcNetwork, ScriptBuf};
use thiserror::Error;

/// Networks whose address formats are supported. Prefix values are copied from
/// `CMainParams`, `CTestNetParams` and `CRegTestParams` in `kernel/chainparams.cpp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl Network {
    /// `base58Prefixes[PUBKEY_ADDRESS]`. Testnet and regtest share this prefix.
    pub const fn pubkey_address_prefix(self) -> u8 {
        match self {
            Network::Main => 0x00,
            Network::Test | Network::Regtest => 0x6f,
        }
    }

    /// `base58Prefixes[SCRIPT_ADDRESS]`. Testnet and regtest share this prefix.
    pub const fn script_address_prefix(self) -> u8 {
        match self {
            Network::Main => 0x05,
            Network::Test | Network::Regtest => 0xc4,
        }
    }

    /// `bech32_hrp`.
    pub const fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Main => "bc",
            Network::Test => "tb",
            Network::Regtest => "bcrt",
        }
    }

    fn to_bitcoin(self) -> BtcNetwork {
        match self {
            Network::Main => BtcNetwork::Bitcoin,
            Network::Test => BtcNetwork::Testnet,
            Network::Regtest => BtcNetwork::Regtest,
        }
    }
}

/// Errors from converting between addresses and output scripts.
#[derive(Debug, Error)]
pub enum AddressError {
    /// The script is not P2PKH, P2SH or a witness program (for example P2PK or
    /// bare multisig), so Bitcoin Core would not produce an address for it.
    #[error("script has no address encoding: {0}")]
    UnsupportedScript(#[from] FromScriptError),
    /// The string is not a well-formed address (bad checksum, length, HRP, ...).
    #[error("invalid address: {0}")]
    Parse(#[from] ParseError),
    /// The address is well formed but belongs to a different network.
    #[error("address {address} is not valid on network {network:?}")]
    WrongNetwork { address: String, network: Network },
    #[error("address {0} has another chain's prefix")]
    WrongPrefix(String),
    #[error("malformed address {0}")]
    Malformed(String),
    #[error("invalid bech32 hrp {0}")]
    BadHrp(String),
    #[error("invalid witness program")]
    BadProgram,
    #[error("script has no address encoding")]
    NoAddress,
}

/// Address prefixes of any chain (`base58Prefixes` + `bech32_hrp`), so custom
/// coins can use their own formats.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddressParams {
    pub bech32_hrp: String,
    pub pubkey_prefix: u8,
    pub script_prefix: u8,
}

impl From<Network> for AddressParams {
    fn from(n: Network) -> Self {
        Self {
            bech32_hrp: n.bech32_hrp().to_string(),
            pubkey_prefix: n.pubkey_address_prefix(),
            script_prefix: n.script_address_prefix(),
        }
    }
}

fn base58_payload(prefix: u8, hash: &[u8]) -> String {
    let mut data = Vec::with_capacity(21);
    data.push(prefix);
    data.extend_from_slice(hash);
    bitcoin::base58::encode_check(&data)
}

/// `EncodeDestination` with explicit prefixes.
pub fn encode_address_with(params: &AddressParams, script_pubkey: &ScriptBuf) -> Result<String, AddressError> {
    let b = script_pubkey.as_bytes();
    if script_pubkey.is_p2pkh() {
        return Ok(base58_payload(params.pubkey_prefix, &b[3..23]));
    }
    if script_pubkey.is_p2sh() {
        return Ok(base58_payload(params.script_prefix, &b[2..22]));
    }
    if let Some(version) = script_pubkey.witness_version() {
        let hrp = Hrp::parse(&params.bech32_hrp).map_err(|_| AddressError::BadHrp(params.bech32_hrp.clone()))?;
        let fe = Fe32::try_from(version.to_num()).expect("witness version is 0..=16");
        return segwit::encode(hrp, fe, &b[2..]).map_err(|_| AddressError::BadProgram);
    }
    Err(AddressError::NoAddress)
}

/// `DecodeDestination` with explicit prefixes.
pub fn decode_address_with(params: &AddressParams, s: &str) -> Result<ScriptBuf, AddressError> {
    if let Ok((hrp, version, program)) = segwit::decode(s) {
        if !hrp.as_str().eq_ignore_ascii_case(&params.bech32_hrp) {
            return Err(AddressError::WrongPrefix(s.to_owned()));
        }
        let v = version.to_u8();
        let mut script = vec![if v == 0 { 0x00 } else { 0x50 + v }, program.len() as u8];
        script.extend_from_slice(&program);
        return Ok(ScriptBuf::from_bytes(script));
    }
    let data = bitcoin::base58::decode_check(s).map_err(|_| AddressError::Malformed(s.to_owned()))?;
    if data.len() != 21 {
        return Err(AddressError::Malformed(s.to_owned()));
    }
    let hash = &data[1..];
    let mut script = Vec::with_capacity(25);
    if data[0] == params.pubkey_prefix {
        script.extend_from_slice(&[0x76, 0xa9, 0x14]);
        script.extend_from_slice(hash);
        script.extend_from_slice(&[0x88, 0xac]);
    } else if data[0] == params.script_prefix {
        script.extend_from_slice(&[0xa9, 0x14]);
        script.extend_from_slice(hash);
        script.push(0x87);
    } else {
        return Err(AddressError::WrongPrefix(s.to_owned()));
    }
    Ok(ScriptBuf::from_bytes(script))
}

/// Encode an output script as an address for `network` (`EncodeDestination`).
pub fn encode_address(network: Network, script_pubkey: &ScriptBuf) -> Result<String, AddressError> {
    let address = Address::from_script(script_pubkey, network.to_bitcoin())?;
    Ok(address.to_string())
}

/// Decode an address for `network` into its output script (`DecodeDestination`).
///
/// Base58 addresses are checked against the version byte of the network. As in
/// Bitcoin Core, testnet and regtest share the Base58 prefixes, so a testnet
/// legacy address is accepted on regtest. Bech32 HRPs differ (`tb` vs `bcrt`)
/// and are checked exactly.
pub fn decode_address(network: Network, s: &str) -> Result<ScriptBuf, AddressError> {
    let unchecked: Address<NetworkUnchecked> = s.parse()?;
    let address = unchecked
        .require_network(network.to_bitcoin())
        .map_err(|err| match err {
            ParseError::NetworkValidation(_) => AddressError::WrongNetwork {
                address: s.to_owned(),
                network,
            },
            other => AddressError::Parse(other),
        })?;
    Ok(address.script_pubkey())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{PubkeyHash, ScriptHash, WPubkeyHash};

    #[test]
    fn p2pkh_known_address_round_trip() {
        // hash160 62e907b15cbf27d5425399ebf6f0fb50ebb88f18 (Genesis P2PKH address)
        let hash = PubkeyHash::from_byte_array([
            0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6, 0xf0,
            0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
        ]);
        let script = ScriptBuf::new_p2pkh(&hash);

        let address = encode_address(Network::Main, &script).unwrap();
        assert_eq!(address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

        let payload = bitcoin::base58::decode_check(&address).unwrap();
        assert_eq!(payload[0], Network::Main.pubkey_address_prefix());
        assert_eq!(decode_address(Network::Main, &address).unwrap(), script);
    }

    #[test]
    fn p2sh_round_trip() {
        let script = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([0x11; 20]));

        let address = encode_address(Network::Test, &script).unwrap();
        assert!(address.starts_with('2'));

        let payload = bitcoin::base58::decode_check(&address).unwrap();
        assert_eq!(payload[0], Network::Test.script_address_prefix());
        assert_eq!(decode_address(Network::Test, &address).unwrap(), script);
    }

    #[test]
    fn rejects_address_from_other_network() {
        let mainnet_p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        assert!(matches!(
            decode_address(Network::Test, mainnet_p2pkh),
            Err(AddressError::WrongNetwork { .. })
        ));

        let wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x75; 20]));
        let testnet = encode_address(Network::Test, &wpkh).unwrap();
        assert!(testnet.starts_with("tb1q"));
        assert!(matches!(
            decode_address(Network::Regtest, &testnet),
            Err(AddressError::WrongNetwork { .. })
        ));
        assert!(matches!(
            decode_address(Network::Main, &testnet),
            Err(AddressError::WrongNetwork { .. })
        ));

        // Base58 prefixes are shared by testnet and regtest, so this is accepted.
        let testnet_p2pkh = encode_address(
            Network::Test,
            &ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0x22; 20])),
        )
        .unwrap();
        assert!(decode_address(Network::Regtest, &testnet_p2pkh).is_ok());
    }

    #[test]
    fn custom_prefixes_round_trip_and_match_builtin() {
        let main = AddressParams::from(Network::Main);
        let wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x75; 20]));
        let p2pkh = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0x62; 20]));
        let p2sh = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([0x11; 20]));
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend([0x33; 32]);
        let p2tr = ScriptBuf::from_bytes(p2tr);
        for script in [&wpkh, &p2pkh, &p2sh, &p2tr] {
            let ours = encode_address_with(&main, script).unwrap();
            assert_eq!(ours, encode_address(Network::Main, script).unwrap());
            assert_eq!(&decode_address_with(&main, &ours).unwrap(), script);
        }
        let coin = AddressParams { bech32_hrp: "cx".into(), pubkey_prefix: 65, script_prefix: 10 };
        for script in [&wpkh, &p2pkh, &p2sh, &p2tr] {
            let a = encode_address_with(&coin, script).unwrap();
            assert_eq!(&decode_address_with(&coin, &a).unwrap(), script);
            assert!(decode_address_with(&main, &a).is_err());
        }
        assert!(encode_address_with(&coin, &wpkh).unwrap().starts_with("cx1q"));
        assert!(encode_address_with(&coin, &p2tr).unwrap().starts_with("cx1p"));
        assert!(encode_address_with(&coin, &ScriptBuf::from_bytes(vec![0x6a])).is_err());
    }

    #[test]
    fn p2wpkh_bech32_round_trip() {
        let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x75; 20]));

        let address = encode_address(Network::Main, &script).unwrap();
        assert!(address.starts_with("bc1q"));
        assert_eq!(decode_address(Network::Main, &address).unwrap(), script);

        let regtest = encode_address(Network::Regtest, &script).unwrap();
        assert!(regtest.starts_with("bcrt1q"));
        assert_eq!(decode_address(Network::Regtest, &regtest).unwrap(), script);
    }
}
