//! Address encoding and decoding. Port of src/key_io.cpp and src/base58.cpp (delegating primitives to rust-bitcoin).
//!
//! Legacy (Base58Check) and SegWit (bech32 for v0, bech32m for v1+) addresses
//! are converted to and from `scriptPubkey`s. Hashing, Base58Check and bech32
//! checksums come from the `bitcoin` crate.

use bitcoin::address::{Address, FromScriptError, NetworkUnchecked, ParseError};
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
