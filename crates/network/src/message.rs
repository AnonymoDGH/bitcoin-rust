//! P2P message framing and payloads. Port of src/protocol.h and src/protocol.cpp.
//!
//! Every message is a 24-byte header followed by the payload:
//! `magic (4) | command (12, NUL padded) | payload length (4, LE) | checksum (4)`.
//! The checksum is the first four bytes of `SHA256d(payload)`.

use bitcoin::consensus::encode::{deserialize_partial, serialize, Decodable, Error as ConsensusError};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin_hashes::{sha256d, Hash};
use thiserror::Error;

/// `CMessageHeader::HEADER_SIZE`.
pub const HEADER_SIZE: usize = 24;
/// `MESSAGE_TYPE_SIZE`: width of the NUL-padded command field.
pub const COMMAND_SIZE: usize = 12;
/// `MAX_SIZE`: largest payload accepted from the wire (32 MiB).
pub const MAX_SIZE: u32 = 0x0200_0000;

/// Errors while framing, parsing or verifying a message.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("truncated input: need {needed} bytes, have {got}")]
    Truncated { needed: usize, got: usize },
    #[error("wrong network magic: expected {expected:02x?}, got {got:02x?}")]
    BadMagic { expected: [u8; 4], got: [u8; 4] },
    #[error("command field is not NUL-padded printable ASCII")]
    InvalidCommand,
    #[error("payload of {0} bytes exceeds MAX_SIZE")]
    PayloadTooLarge(u64),
    #[error("header declares {declared} payload bytes but {actual} are present")]
    LengthMismatch { declared: u32, actual: usize },
    #[error("checksum mismatch: header {expected:02x?}, computed {computed:02x?}")]
    ChecksumMismatch { expected: [u8; 4], computed: [u8; 4] },
    #[error("malformed {command} payload")]
    MalformedPayload {
        command: String,
        #[source]
        source: ConsensusError,
    },
}

/// The 24-byte header that precedes every message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    pub magic: [u8; 4],
    /// Raw command field, NUL padded.
    pub command: [u8; COMMAND_SIZE],
    pub length: u32,
    pub checksum: [u8; 4],
}

impl MessageHeader {
    /// Builds the header for `payload`, computing its checksum.
    pub fn new(magic: [u8; 4], command: &str, payload: &[u8]) -> Result<Self, MessageError> {
        let name = command.as_bytes();
        if name.len() > COMMAND_SIZE || !is_printable(name) {
            return Err(MessageError::InvalidCommand);
        }
        let mut field = [0u8; COMMAND_SIZE];
        field[..name.len()].copy_from_slice(name);

        let size = payload.len() as u64;
        if size > u64::from(MAX_SIZE) {
            return Err(MessageError::PayloadTooLarge(size));
        }
        Ok(Self {
            magic,
            command: field,
            length: size as u32,
            checksum: checksum(payload),
        })
    }

    /// Parses a header from the first 24 bytes of `bytes`.
    ///
    /// Checks the magic, the command field and the size limit. The checksum is
    /// checked separately by [`MessageHeader::verify_payload`], once the payload
    /// has been read.
    pub fn decode(expected_magic: [u8; 4], bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() < HEADER_SIZE {
            return Err(MessageError::Truncated {
                needed: HEADER_SIZE,
                got: bytes.len(),
            });
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != expected_magic {
            return Err(MessageError::BadMagic {
                expected: expected_magic,
                got: magic,
            });
        }

        let mut command = [0u8; COMMAND_SIZE];
        command.copy_from_slice(&bytes[4..16]);
        if command_name(&command).is_none() {
            return Err(MessageError::InvalidCommand);
        }

        let length = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        if length > MAX_SIZE {
            return Err(MessageError::PayloadTooLarge(u64::from(length)));
        }

        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&bytes[20..24]);
        Ok(Self {
            magic,
            command,
            length,
            checksum,
        })
    }

    /// The command name with its NUL padding removed.
    pub fn command(&self) -> Result<&str, MessageError> {
        command_name(&self.command).ok_or(MessageError::InvalidCommand)
    }

    /// Serializes the header to its 24 wire bytes.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(&self.magic);
        out[4..16].copy_from_slice(&self.command);
        out[16..20].copy_from_slice(&self.length.to_le_bytes());
        out[20..24].copy_from_slice(&self.checksum);
        out
    }

    /// Checks that `payload` has the declared length and matches the checksum.
    pub fn verify_payload(&self, payload: &[u8]) -> Result<(), MessageError> {
        if payload.len() != self.length as usize {
            return Err(MessageError::LengthMismatch {
                declared: self.length,
                actual: payload.len(),
            });
        }
        let computed = checksum(payload);
        if computed != self.checksum {
            return Err(MessageError::ChecksumMismatch {
                expected: self.checksum,
                computed,
            });
        }
        Ok(())
    }
}

/// First four bytes of `SHA256d(payload)`.
pub fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = sha256d::Hash::hash(payload).to_byte_array();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// A command name is printable ASCII (0x20..=0x7e), as `IsCommandValid` requires.
fn is_printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x20..=0x7e).contains(b))
}

/// Returns the command name if the field is a NUL-padded printable name.
/// Bytes after the first NUL must all be zero.
fn command_name(field: &[u8; COMMAND_SIZE]) -> Option<&str> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(COMMAND_SIZE);
    let (name, padding) = field.split_at(end);
    if padding.iter().any(|&b| b != 0) || !is_printable(name) {
        return None;
    }
    std::str::from_utf8(name).ok()
}

/// A decoded P2P message.
///
/// `Version`, `Verack`, `Ping` and `Pong` are fully parsed. `Inv`, `GetData`,
/// `Headers`, `GetHeaders` and `Addr` keep their raw payload until a handler
/// needs them. Unrecognized commands become `Unknown`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkMessage {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    Inv(Vec<u8>),
    GetData(Vec<u8>),
    Headers(Vec<u8>),
    GetHeaders(Vec<u8>),
    Addr(Vec<u8>),
    Unknown { command: String, payload: Vec<u8> },
}

impl NetworkMessage {
    /// The wire command for this message.
    pub fn command(&self) -> &str {
        match self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::Unknown { command, .. } => command,
        }
    }
}

/// Frames `msg` for the network with the given magic.
///
/// Panics if `msg` is an `Unknown` with an invalid command name or a payload
/// larger than `MAX_SIZE`. Callers must not construct such messages.
pub fn encode_message(magic: [u8; 4], msg: &NetworkMessage) -> Vec<u8> {
    let payload = encode_payload(msg);
    let header = MessageHeader::new(magic, msg.command(), &payload)
        .expect("outbound message has a valid command and fits in MAX_SIZE");

    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&payload);
    out
}

/// Parses one message from the front of `bytes`.
///
/// Returns the message and the number of bytes it occupied, so a buffer holding
/// several frames can be consumed in a loop.
pub fn decode_message(magic: [u8; 4], bytes: &[u8]) -> Result<(NetworkMessage, usize), MessageError> {
    let header = MessageHeader::decode(magic, bytes)?;
    let total = HEADER_SIZE + header.length as usize;
    if bytes.len() < total {
        return Err(MessageError::Truncated {
            needed: total,
            got: bytes.len(),
        });
    }
    let payload = &bytes[HEADER_SIZE..total];
    header.verify_payload(payload)?;
    let msg = decode_payload(header.command()?, payload)?;
    Ok((msg, total))
}

/// Parses a payload whose header has already been validated.
///
/// `version`, `ping` and `pong` are decoded like Core's stream reads: trailing
/// bytes after the expected fields are ignored.
pub fn decode_payload(command: &str, payload: &[u8]) -> Result<NetworkMessage, MessageError> {
    let msg = match command {
        "version" => NetworkMessage::Version(parse_payload(command, payload)?),
        "verack" => NetworkMessage::Verack,
        "ping" => NetworkMessage::Ping(parse_payload(command, payload)?),
        "pong" => NetworkMessage::Pong(parse_payload(command, payload)?),
        "inv" => NetworkMessage::Inv(payload.to_vec()),
        "getdata" => NetworkMessage::GetData(payload.to_vec()),
        "headers" => NetworkMessage::Headers(payload.to_vec()),
        "getheaders" => NetworkMessage::GetHeaders(payload.to_vec()),
        "addr" => NetworkMessage::Addr(payload.to_vec()),
        other => NetworkMessage::Unknown {
            command: other.to_string(),
            payload: payload.to_vec(),
        },
    };
    Ok(msg)
}

fn encode_payload(msg: &NetworkMessage) -> Vec<u8> {
    match msg {
        NetworkMessage::Version(version) => serialize(version),
        NetworkMessage::Ping(nonce) | NetworkMessage::Pong(nonce) => serialize(nonce),
        NetworkMessage::Verack => Vec::new(),
        NetworkMessage::Inv(raw)
        | NetworkMessage::GetData(raw)
        | NetworkMessage::Headers(raw)
        | NetworkMessage::GetHeaders(raw)
        | NetworkMessage::Addr(raw) => raw.clone(),
        NetworkMessage::Unknown { payload, .. } => payload.clone(),
    }
}

fn parse_payload<T: Decodable>(command: &str, payload: &[u8]) -> Result<T, MessageError> {
    deserialize_partial::<T>(payload)
        .map(|(value, _)| value)
        .map_err(|source| MessageError::MalformedPayload {
            command: command.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::p2p::{Address, ServiceFlags};
    use std::net::SocketAddr;

    /// Regtest magic, as in `ChainParams::regtest()`.
    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

    #[test]
    fn ping_round_trip() {
        let msg = NetworkMessage::Ping(0x0102_0304_0506_0708);
        let bytes = encode_message(MAGIC, &msg);

        assert_eq!(bytes.len(), HEADER_SIZE + 8);
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(&bytes[4..8], b"ping");
        assert_eq!(&bytes[16..20], &8u32.to_le_bytes());
        assert_eq!(&bytes[24..32], &[8, 7, 6, 5, 4, 3, 2, 1]);

        let (decoded, used) = decode_message(MAGIC, &bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn verack_matches_mainnet_wire_bytes() {
        // Known mainnet verack: empty payload, checksum 5df6e0e2 = SHA256d("").
        let bytes = encode_message([0xf9, 0xbe, 0xb4, 0xd9], &NetworkMessage::Verack);
        let expected: [u8; 24] = [
            0xf9, 0xbe, 0xb4, 0xd9, // magic
            b'v', b'e', b'r', b'a', b'c', b'k', 0, 0, 0, 0, 0, 0, // command
            0, 0, 0, 0, // length
            0x5d, 0xf6, 0xe0, 0xe2, // checksum
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn version_round_trip() {
        let peer: SocketAddr = "192.0.2.1:18444".parse().unwrap();
        let version = VersionMessage::new(
            ServiceFlags::NONE,
            1_700_000_000,
            Address::new(&peer, ServiceFlags::NONE),
            Address::new(&peer, ServiceFlags::NONE),
            99,
            "/test:0.0.1/".to_string(),
            5,
        );
        let msg = NetworkMessage::Version(version);
        let bytes = encode_message(MAGIC, &msg);
        let (decoded, used) = decode_message(MAGIC, &bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let mut corrupt_payload = encode_message(MAGIC, &NetworkMessage::Ping(42));
        corrupt_payload[HEADER_SIZE] ^= 0x01;
        assert!(matches!(
            decode_message(MAGIC, &corrupt_payload),
            Err(MessageError::ChecksumMismatch { .. })
        ));

        let mut corrupt_checksum = encode_message(MAGIC, &NetworkMessage::Ping(42));
        corrupt_checksum[20] ^= 0xff;
        assert!(matches!(
            decode_message(MAGIC, &corrupt_checksum),
            Err(MessageError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_magic_oversize_truncation_and_bad_command() {
        let bytes = encode_message(MAGIC, &NetworkMessage::Verack);

        assert!(matches!(
            decode_message([0; 4], &bytes),
            Err(MessageError::BadMagic { .. })
        ));

        let mut oversize = bytes.clone();
        oversize[16..20].copy_from_slice(&(MAX_SIZE + 1).to_le_bytes());
        assert!(matches!(
            decode_message(MAGIC, &oversize),
            Err(MessageError::PayloadTooLarge(_))
        ));

        assert!(matches!(
            decode_message(MAGIC, &bytes[..10]),
            Err(MessageError::Truncated { .. })
        ));

        // Non-zero byte after the NUL terminator of the command field.
        let mut bad_command = bytes.clone();
        bad_command[12] = b'x';
        assert!(matches!(
            decode_message(MAGIC, &bad_command),
            Err(MessageError::InvalidCommand)
        ));
    }

    #[test]
    fn unknown_command_is_preserved() {
        let msg = NetworkMessage::Unknown {
            command: "sendcmpct".to_string(),
            payload: vec![1, 2, 3],
        };
        let bytes = encode_message(MAGIC, &msg);
        let (decoded, _) = decode_message(MAGIC, &bytes).unwrap();
        assert_eq!(decoded, msg);
    }
}
