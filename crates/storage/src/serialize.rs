//! Core's VARINT (`serialize.h` WriteVarInt/ReadVarInt) and CompactSize.

use std::io::{self, Read, Write};

use bitcoin::consensus::encode::{self, Decodable, Encodable, VarInt};

/// Core `MAX_SIZE`: upper bound for CompactSize-prefixed lengths.
pub const MAX_SIZE: u64 = 0x0200_0000;

pub(crate) fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub fn write_varint<W: Write>(w: &mut W, mut n: u64) -> io::Result<()> {
    let mut tmp = [0u8; 10];
    let mut len = 0;
    loop {
        let continuation = if len > 0 { 0x80 } else { 0x00 };
        tmp[len] = (n & 0x7f) as u8 | continuation;
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    loop {
        w.write_all(&[tmp[len]])?;
        if len == 0 {
            return Ok(());
        }
        len -= 1;
    }
}

pub fn read_varint<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut n: u64 = 0;
    loop {
        let mut byte = [0u8; 1];
        r.read_exact(&mut byte)?;
        if n > (u64::MAX >> 7) {
            return Err(invalid("ReadVarInt(): size too large"));
        }
        n = (n << 7) | u64::from(byte[0] & 0x7f);
        if byte[0] & 0x80 == 0 {
            return Ok(n);
        }
        if n == u64::MAX {
            return Err(invalid("ReadVarInt(): size too large"));
        }
        n += 1;
    }
}

/// CompactSize through rust-bitcoin's `VarInt`. That codec is bound to
/// `bitcoin_io`, so it runs on a concrete buffer rather than the generic stream.
pub fn write_compact_size<W: Write>(w: &mut W, n: u64) -> io::Result<()> {
    let mut buf = Vec::with_capacity(9);
    VarInt(n)
        .consensus_encode(&mut buf)
        .expect("writing to a Vec cannot fail");
    w.write_all(&buf)
}

pub fn read_compact_size<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 9];
    r.read_exact(&mut buf[..1])?;
    let len = match buf[0] {
        0xfd => 3,
        0xfe => 5,
        0xff => 9,
        _ => 1,
    };
    r.read_exact(&mut buf[1..len])?;
    let n = VarInt::consensus_decode(&mut &buf[..len])
        .map_err(encode_error)?
        .0;
    if n > MAX_SIZE {
        return Err(invalid("ReadCompactSize(): size too large"));
    }
    Ok(n)
}

fn encode_error(err: encode::Error) -> io::Error {
    invalid(&err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_vectors_from_core() {
        let cases: [(u64, &str); 6] = [
            (0x00, "00"),
            (0x7f, "7f"),
            (0x80, "8000"),
            (0x1234, "a334"),
            (0xffff, "82fe7f"),
            (0x123456, "c7e756"),
        ];
        for (n, hex) in cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, n).unwrap();
            let encoded: String = buf.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(encoded, hex, "encoding {n:#x}");
            assert_eq!(read_varint(&mut buf.as_slice()).unwrap(), n);
        }
    }

    #[test]
    fn varint_roundtrip_edges() {
        for n in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, n).unwrap();
            assert_eq!(read_varint(&mut buf.as_slice()).unwrap(), n);
        }
    }

    #[test]
    fn compact_size_matches_bitcoin_encoding() {
        for n in [
            0u64,
            0xfc,
            0xfd,
            0xffff,
            0x1_0000,
            MAX_SIZE,
            0xffff_ffff,
            0x1_0000_0000,
        ] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, n).unwrap();
            assert_eq!(buf, bitcoin::consensus::serialize(&VarInt(n)));
        }
        for n in [0u64, 0xfc, 0xfd, 0xffff, 0x1_0000, MAX_SIZE] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, n).unwrap();
            assert_eq!(read_compact_size(&mut buf.as_slice()).unwrap(), n);
        }
        let mut buf = Vec::new();
        write_compact_size(&mut buf, MAX_SIZE + 1).unwrap();
        assert!(read_compact_size(&mut buf.as_slice()).is_err());
    }

    #[test]
    fn truncated_varint_is_unexpected_eof() {
        let err = read_varint(&mut [0x80u8].as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
