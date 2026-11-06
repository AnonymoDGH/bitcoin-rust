//! Transaction primitives, ported from Bitcoin Core `primitives/transaction.h`.
//!
//! Wire encoding and SHA256D hashing are delegated to `rust-bitcoin` /
//! `bitcoin_hashes`; this module only defines the Core data model.

use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::io::{self, Read, Write};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Txid, Witness, Wtxid};
use bitcoin_hashes::{sha256d, Hash};

/// Amount used by `CTxOut::SetNull()` in Bitcoin Core.
pub const NULL_VALUE: i64 = -1;

/// An input of a transaction: the outpoint it spends, its scriptSig and sequence.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxIn {
    /// The previous output being spent.
    pub prevout: OutPoint,
    /// Unlocking script (scriptSig).
    pub script_sig: ScriptBuf,
    /// Sequence number.
    pub sequence: Sequence,
    /// Witness stack. Only serialized as part of a `Tx`, never on its own.
    pub witness: Witness,
}

impl TxIn {
    /// Setting this on every input disables nLockTime (and fails BIP65/BIP68).
    pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;
    /// Highest sequence that still enables nLockTime.
    pub const MAX_SEQUENCE_NONFINAL: u32 = Self::SEQUENCE_FINAL - 1;
    /// BIP68: sequence is not interpreted as a relative lock-time.
    pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
    /// BIP68: relative lock-time has 512 second units instead of blocks.
    pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
    /// BIP68: mask extracting the relative lock-time value.
    pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
    /// BIP68: granularity of time-based relative lock-times (2^9 seconds).
    pub const SEQUENCE_LOCKTIME_GRANULARITY: i32 = 9;

    /// Creates an input spending `prevout`.
    pub fn new(prevout: OutPoint) -> Self {
        Self {
            prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }
}

impl Default for TxIn {
    fn default() -> Self {
        Self::new(OutPoint::null())
    }
}

impl Encodable for TxIn {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prevout.consensus_encode(w)?;
        len += self.script_sig.consensus_encode(w)?;
        len += self.sequence.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for TxIn {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            prevout: OutPoint::consensus_decode(r)?,
            script_sig: ScriptBuf::consensus_decode(r)?,
            sequence: Sequence::consensus_decode(r)?,
            witness: Witness::new(),
        })
    }
}

/// An output of a transaction: an amount and the scriptPubKey locking it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxOut {
    /// Value in satoshis. `NULL_VALUE` (-1) marks a null output, as in Core.
    pub value: i64,
    /// Locking script (scriptPubKey).
    pub script_pubkey: ScriptBuf,
}

impl TxOut {
    pub fn new(value: i64, script_pubkey: ScriptBuf) -> Self {
        Self { value, script_pubkey }
    }

    /// Mirrors `CTxOut::SetNull()`.
    pub fn set_null(&mut self) {
        self.value = NULL_VALUE;
        self.script_pubkey = ScriptBuf::new();
    }

    /// Mirrors `CTxOut::IsNull()`.
    pub fn is_null(&self) -> bool {
        self.value == NULL_VALUE
    }
}

impl Default for TxOut {
    fn default() -> Self {
        Self {
            value: NULL_VALUE,
            script_pubkey: ScriptBuf::new(),
        }
    }
}

impl Encodable for TxOut {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.value.consensus_encode(w)?;
        len += self.script_pubkey.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for TxOut {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            value: i64::consensus_decode(r)?,
            script_pubkey: ScriptBuf::consensus_decode(r)?,
        })
    }
}

/// The basic transaction broadcast on the network and contained in blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

impl Tx {
    /// Default transaction version (Core `CTransaction::CURRENT_VERSION`).
    pub const CURRENT_VERSION: u32 = 2;

    pub fn new(version: u32, vin: Vec<TxIn>, vout: Vec<TxOut>, lock_time: u32) -> Self {
        Self {
            version,
            vin,
            vout,
            lock_time,
        }
    }

    /// True when both the input and output lists are empty.
    pub fn is_null(&self) -> bool {
        self.vin.is_empty() && self.vout.is_empty()
    }

    /// A coinbase has a single input spending the null outpoint.
    pub fn is_coin_base(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].prevout.is_null()
    }

    /// True if any input carries a non-empty witness stack.
    pub fn has_witness(&self) -> bool {
        self.vin.iter().any(|input| !input.witness.is_empty())
    }

    /// Sum of output values, in satoshis.
    pub fn value_out(&self) -> i64 {
        self.vout.iter().map(|out| out.value).sum()
    }

    /// Total serialized size in bytes, including witness data (BIP141).
    pub fn total_size(&self) -> usize {
        self.encode_to_vec(true).len()
    }

    /// Legacy transaction id: SHA256D of the non-witness serialization.
    pub fn txid(&self) -> Txid {
        let bytes = self.encode_to_vec(false);
        Txid::from_byte_array(sha256d::Hash::hash(&bytes).to_byte_array())
    }

    /// Witness transaction id: SHA256D of the full serialization.
    pub fn wtxid(&self) -> Wtxid {
        let bytes = self.encode_to_vec(true);
        Wtxid::from_byte_array(sha256d::Hash::hash(&bytes).to_byte_array())
    }

    fn encode_to_vec(&self, with_witness: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_with(&mut buf, with_witness)
            .expect("in-memory writers cannot fail");
        buf
    }

    /// Core-style serialization, optionally omitting witness data
    /// (`TransactionSerParams`).
    pub fn encode_with<W: Write + ?Sized>(
        &self,
        w: &mut W,
        with_witness: bool,
    ) -> Result<usize, io::Error> {
        let include_witness = with_witness && self.has_witness();
        let mut len = self.version.consensus_encode(w)?;
        if include_witness {
            // BIP144 marker (0x00) and flag (0x01).
            len += 0u8.consensus_encode(w)?;
            len += 1u8.consensus_encode(w)?;
        }
        len += encode_vec(&self.vin, w)?;
        len += encode_vec(&self.vout, w)?;
        if include_witness {
            for input in &self.vin {
                len += input.witness.consensus_encode(w)?;
            }
        }
        len += self.lock_time.consensus_encode(w)?;
        Ok(len)
    }
}

impl Default for Tx {
    fn default() -> Self {
        Self::new(Self::CURRENT_VERSION, Vec::new(), Vec::new(), 0)
    }
}

impl Encodable for Tx {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.encode_with(w, true)
    }
}

impl Decodable for Tx {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u32::consensus_decode(r)?;

        // The first vector may be the witness dummy (empty vin).
        let mut vin: Vec<TxIn> = decode_vec(r)?;
        let mut vout: Vec<TxOut> = Vec::new();
        let mut flags = 0u8;

        if vin.is_empty() {
            // The byte we just read may be the vout count of a legacy tx.
            flags = u8::consensus_decode(r)?;
            if flags != 0 {
                vin = decode_vec(r)?;
                vout = decode_vec(r)?;
            }
        } else {
            vout = decode_vec(r)?;
        }

        if flags & 1 != 0 {
            for input in &mut vin {
                input.witness = Witness::consensus_decode(r)?;
            }
            flags ^= 1;
            if !vin.iter().any(|input| !input.witness.is_empty()) {
                return Err(encode::Error::ParseFailed("superfluous witness record"));
            }
        }
        if flags != 0 {
            return Err(encode::Error::ParseFailed("unknown transaction optional data"));
        }

        let lock_time = u32::consensus_decode(r)?;
        Ok(Self {
            version,
            vin,
            vout,
            lock_time,
        })
    }
}

pub(crate) fn encode_vec<T: Encodable, W: Write + ?Sized>(
    items: &[T],
    w: &mut W,
) -> Result<usize, io::Error> {
    let mut len = encode::VarInt(items.len() as u64).consensus_encode(w)?;
    for item in items {
        len += item.consensus_encode(w)?;
    }
    Ok(len)
}

pub(crate) fn decode_vec<T: Decodable, R: Read + ?Sized>(
    r: &mut R,
) -> Result<Vec<T>, encode::Error> {
    let len = encode::VarInt::consensus_decode(r)?.0 as usize;
    if len > encode::MAX_VEC_SIZE {
        return Err(encode::Error::ParseFailed("oversized vector"));
    }
    let mut items = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        items.push(T::consensus_decode(r)?);
    }
    Ok(items)
}
