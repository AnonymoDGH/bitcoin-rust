//! Script number encoding. Port of CScriptNum in src/script/script.h.
//! Values are held in i64. Operand size limits are enforced by the caller through `max_len`.

use crate::error::ScriptError;

pub const DEFAULT_MAX_NUM_SIZE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptNum(i64);

impl ScriptNum {
    pub const fn new(v: i64) -> Self {
        Self(v)
    }

    pub const fn value(self) -> i64 {
        self.0
    }

    /// Decodes a little-endian sign-magnitude number.
    /// Fails with ScriptError::ScriptNum when the input is longer than `max_len`, or when
    /// `require_minimal` is set and the encoding has a redundant byte.
    pub fn from_bytes(bytes: &[u8], require_minimal: bool, max_len: usize) -> Result<Self, ScriptError> {
        if bytes.len() > max_len {
            return Err(ScriptError::ScriptNum);
        }
        if require_minimal && !bytes.is_empty() {
            let last = bytes[bytes.len() - 1];
            // A trailing 0x00 or 0x80 is only needed to hold the sign of the byte before it.
            if last & 0x7f == 0 && (bytes.len() <= 1 || bytes[bytes.len() - 2] & 0x80 == 0) {
                return Err(ScriptError::ScriptNum);
            }
        }
        Ok(Self(decode(bytes)))
    }

    /// Minimal little-endian sign-magnitude encoding of `v`.
    pub fn encode(v: i64) -> Vec<u8> {
        if v == 0 {
            return Vec::new();
        }
        let neg = v < 0;
        let mut abs = v.unsigned_abs();
        let mut out = Vec::new();
        while abs > 0 {
            out.push((abs & 0xff) as u8);
            abs >>= 8;
        }
        let last = out.len() - 1;
        if out[last] & 0x80 != 0 {
            out.push(if neg { 0x80 } else { 0x00 });
        } else if neg {
            out[last] |= 0x80;
        }
        out
    }

    pub fn to_bytes(self) -> Vec<u8> {
        Self::encode(self.0)
    }
}

fn decode(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let mut result: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        result |= (*b as u64) << (8 * i);
    }
    let last = bytes[bytes.len() - 1];
    if last & 0x80 != 0 {
        let shift = 8 * (bytes.len() - 1);
        let magnitude = result & !(0x80u64 << shift);
        -(magnitude as i64)
    } else {
        result as i64
    }
}
