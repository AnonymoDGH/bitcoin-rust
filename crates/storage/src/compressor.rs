//! Amount and script compression. Port of `src/compressor.{h,cpp}`.

use std::io::{self, Read, Write};

use bitcoin::secp256k1::PublicKey;
use bitcoin::ScriptBuf;
use btc_primitives::TxOut;

use crate::serialize::{invalid, read_varint, write_varint};

const OP_RETURN: u8 = 0x6a;
const OP_DUP: u8 = 0x76;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;

/// Core `MAX_SCRIPT_SIZE`.
const MAX_SCRIPT_SIZE: u64 = 10_000;
/// Core `CScriptCompressor::nSpecialScripts`.
const N_SPECIAL_SCRIPTS: u64 = 6;

/// Core `CompressAmount`. Arithmetic wraps on out-of-range input instead of panicking.
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e = 0u64;
    while n.is_multiple_of(10) && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        n /= 10;
        1u64.wrapping_add(n.wrapping_mul(9).wrapping_add(d - 1).wrapping_mul(10))
            .wrapping_add(e)
    } else {
        1u64.wrapping_add(n.wrapping_sub(1).wrapping_mul(10))
            .wrapping_add(9)
    }
}

/// Core `DecompressAmount`.
pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let e = x % 10;
    x /= 10;
    let mut n = if e < 9 {
        let d = x % 9 + 1;
        x /= 9;
        x.wrapping_mul(10).wrapping_add(d)
    } else {
        x.wrapping_add(1)
    };
    for _ in 0..e {
        n = n.wrapping_mul(10);
    }
    n
}

/// Core `CompressScript`: the special-form encoding (tag byte first), if the script has one.
fn compress_script(script: &[u8]) -> Option<Vec<u8>> {
    if script.len() == 25
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == 20
        && script[23] == OP_EQUALVERIFY
        && script[24] == OP_CHECKSIG
    {
        return Some(with_tag(0x00, &script[3..23]));
    }
    if script.len() == 23 && script[0] == OP_HASH160 && script[1] == 20 && script[22] == OP_EQUAL {
        return Some(with_tag(0x01, &script[2..22]));
    }
    if script.len() == 35
        && script[0] == 33
        && script[34] == OP_CHECKSIG
        && (script[1] == 0x02 || script[1] == 0x03)
    {
        return Some(with_tag(script[1], &script[2..34]));
    }
    if script.len() == 67 && script[0] == 65 && script[66] == OP_CHECKSIG && script[1] == 0x04 {
        // Only fully valid points are compressible.
        PublicKey::from_slice(&script[1..66]).ok()?;
        let parity = script[65] & 0x01;
        return Some(with_tag(0x04 | parity, &script[2..34]));
    }
    None
}

fn with_tag(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(tag);
    out.extend_from_slice(payload);
    out
}

fn special_script_size(tag: u64) -> usize {
    match tag {
        0 | 1 => 20,
        2..=5 => 32,
        _ => 0,
    }
}

/// Core `DecompressScript`. `None` if a compressed public key is not on the curve.
fn decompress_script(tag: u64, payload: &[u8]) -> Option<Vec<u8>> {
    match tag {
        0x00 => {
            let mut s = vec![OP_DUP, OP_HASH160, 20];
            s.extend_from_slice(&payload[..20]);
            s.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
            Some(s)
        }
        0x01 => {
            let mut s = vec![OP_HASH160, 20];
            s.extend_from_slice(&payload[..20]);
            s.push(OP_EQUAL);
            Some(s)
        }
        0x02 | 0x03 => {
            let mut s = vec![33, tag as u8];
            s.extend_from_slice(&payload[..32]);
            s.push(OP_CHECKSIG);
            Some(s)
        }
        0x04 | 0x05 => {
            let mut compressed = vec![(tag - 2) as u8];
            compressed.extend_from_slice(&payload[..32]);
            let key = PublicKey::from_slice(&compressed).ok()?;
            let mut s = vec![65];
            s.extend_from_slice(&key.serialize_uncompressed());
            s.push(OP_CHECKSIG);
            Some(s)
        }
        _ => None,
    }
}

/// Core `CScriptCompressor::Serialize`.
pub fn write_script_compressed<W: Write>(w: &mut W, script: &[u8]) -> io::Result<()> {
    match compress_script(script) {
        Some(compressed) => w.write_all(&compressed),
        None => {
            write_varint(w, script.len() as u64 + N_SPECIAL_SCRIPTS)?;
            w.write_all(script)
        }
    }
}

/// Core `CScriptCompressor::Unserialize`. Overlong scripts come back as a bare `OP_RETURN`.
pub fn read_script_compressed<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let tag = read_varint(r)?;
    if tag < N_SPECIAL_SCRIPTS {
        let mut payload = vec![0u8; special_script_size(tag)];
        r.read_exact(&mut payload)?;
        return decompress_script(tag, &payload)
            .ok_or_else(|| invalid("compressed script holds an invalid public key"));
    }
    let len = tag - N_SPECIAL_SCRIPTS;
    if len > MAX_SCRIPT_SIZE {
        let skipped = io::copy(&mut (&mut *r).take(len), &mut io::sink())?;
        if skipped != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        return Ok(vec![OP_RETURN]);
    }
    let mut script = vec![0u8; len as usize];
    r.read_exact(&mut script)?;
    Ok(script)
}

/// Core `TxOutCompression`: compressed amount followed by the compressed script.
pub fn write_txout_compressed<W: Write>(w: &mut W, txout: &TxOut) -> io::Result<()> {
    write_varint(w, compress_amount(txout.value as u64))?;
    write_script_compressed(w, txout.script_pubkey.as_bytes())
}

pub fn read_txout_compressed<R: Read>(r: &mut R) -> io::Result<TxOut> {
    let value = decompress_amount(read_varint(r)?) as i64;
    let script = read_script_compressed(r)?;
    Ok(TxOut::new(value, ScriptBuf::from_bytes(script)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn uncompressed_key(secret_byte: u8) -> [u8; 65] {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk).serialize_uncompressed()
    }

    fn compressed_key(secret_byte: u8) -> [u8; 33] {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[secret_byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk).serialize()
    }

    fn roundtrip_script(script: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        write_script_compressed(&mut buf, script).unwrap();
        read_script_compressed(&mut buf.as_slice()).unwrap()
    }

    #[test]
    fn amount_vectors_from_core() {
        assert_eq!(compress_amount(0), 0);
        assert_eq!(compress_amount(100_000_000), 9);
        assert_eq!(compress_amount(5_000_000_000), 50);
        assert_eq!(compress_amount(2_100_000_000_000_000), 21_000_000);
        assert_eq!(decompress_amount(0), 0);
        assert_eq!(decompress_amount(9), 100_000_000);
        assert_eq!(decompress_amount(50), 5_000_000_000);
        assert_eq!(decompress_amount(21_000_000), 2_100_000_000_000_000);
    }

    #[test]
    fn amount_roundtrip() {
        let mut values: Vec<u64> = (0..2_000u64).collect();
        for shift in 0..55 {
            let base = 1u64 << shift;
            values.extend([base - 1, base, base + 1, base * 3, base * 10]);
        }
        values.extend([
            0x1234_5678_9abc,
            2_100_000_000_000_000,
            2_099_999_999_999_999,
        ]);
        values.extend((1..=17u64).map(|e| 10u64.pow(e as u32) * 7 + 3));
        for v in values {
            assert_eq!(decompress_amount(compress_amount(v)), v, "amount {v}");
        }
    }

    #[test]
    fn script_special_forms_roundtrip_and_tag() {
        let mut p2pkh = vec![OP_DUP, OP_HASH160, 20];
        p2pkh.extend([0xab; 20]);
        p2pkh.extend([OP_EQUALVERIFY, OP_CHECKSIG]);
        let mut buf = Vec::new();
        write_script_compressed(&mut buf, &p2pkh).unwrap();
        assert_eq!(buf.len(), 21);
        assert_eq!(buf[0], 0x00);
        assert_eq!(roundtrip_script(&p2pkh), p2pkh);

        let mut p2sh = vec![OP_HASH160, 20];
        p2sh.extend([0xcd; 20]);
        p2sh.push(OP_EQUAL);
        assert_eq!(roundtrip_script(&p2sh), p2sh);

        for prefix in [0x02u8, 0x03] {
            let mut key = compressed_key(7);
            key[0] = prefix;
            let mut p2pk = vec![33];
            p2pk.extend_from_slice(&key);
            p2pk.push(OP_CHECKSIG);
            let mut buf = Vec::new();
            write_script_compressed(&mut buf, &p2pk).unwrap();
            assert_eq!(buf.len(), 33);
            assert_eq!(buf[0], prefix);
            assert_eq!(roundtrip_script(&p2pk), p2pk);
        }
    }

    #[test]
    fn uncompressed_p2pk_roundtrips_both_parities() {
        for secret in [1u8, 2, 3, 0x55] {
            let key = uncompressed_key(secret);
            let mut script = vec![65];
            script.extend_from_slice(&key);
            script.push(OP_CHECKSIG);
            let mut buf = Vec::new();
            write_script_compressed(&mut buf, &script).unwrap();
            assert_eq!(buf.len(), 33);
            assert!(buf[0] == 0x04 || buf[0] == 0x05);
            assert_eq!(buf[0] & 1, key[64] & 1);
            assert_eq!(roundtrip_script(&script), script);
        }
    }

    #[test]
    fn invalid_uncompressed_key_is_stored_raw() {
        let mut script = vec![65, 0x04];
        script.extend([0u8; 64]);
        script.push(OP_CHECKSIG);
        let mut buf = Vec::new();
        write_script_compressed(&mut buf, &script).unwrap();
        assert_eq!(buf[0], (script.len() as u64 + N_SPECIAL_SCRIPTS) as u8);
        assert_eq!(roundtrip_script(&script), script);
    }

    #[test]
    fn raw_and_empty_scripts_roundtrip() {
        assert_eq!(roundtrip_script(&[]), Vec::<u8>::new());
        assert_eq!(roundtrip_script(&[0x51]), vec![0x51]);
        let long: Vec<u8> = (0..MAX_SCRIPT_SIZE as usize).map(|i| i as u8).collect();
        assert_eq!(roundtrip_script(&long), long);
    }

    #[test]
    fn overlong_script_becomes_op_return() {
        let long = vec![0x51u8; MAX_SCRIPT_SIZE as usize + 1];
        let mut buf = Vec::new();
        write_script_compressed(&mut buf, &long).unwrap();
        buf.extend_from_slice(&[0x99]);
        let mut cursor = buf.as_slice();
        assert_eq!(
            read_script_compressed(&mut cursor).unwrap(),
            vec![OP_RETURN]
        );
        assert_eq!(cursor, &[0x99]);
    }

    #[test]
    fn txout_roundtrip() {
        let txout = TxOut::new(50_000, ScriptBuf::from_bytes(vec![0x00, 0x14, 1, 2, 3]));
        let mut buf = Vec::new();
        write_txout_compressed(&mut buf, &txout).unwrap();
        assert_eq!(read_txout_compressed(&mut buf.as_slice()).unwrap(), txout);
    }
}
