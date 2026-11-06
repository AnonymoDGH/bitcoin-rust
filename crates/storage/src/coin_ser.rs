//! Coin and undo serialization. Port of `Coin::Serialize` (`coins.h`) and the
//! `TxInUndoFormatter`, `CTxUndo` and `CBlockUndo` encodings (`undo.h`).

use std::io::{self, Read, Write};

use btc_validation::coins::Coin;
use btc_validation::undo::{BlockUndo, TxUndo};

use crate::compressor::{read_txout_compressed, write_txout_compressed};
use crate::serialize::{invalid, read_compact_size, read_varint, write_compact_size, write_varint};

fn code_of(coin: &Coin) -> u64 {
    (u64::from(coin.height) << 1) | u64::from(coin.is_coinbase)
}

fn read_code<R: Read>(r: &mut R) -> io::Result<u32> {
    u32::try_from(read_varint(r)?).map_err(|_| invalid("coin height/coinbase code out of range"))
}

/// Core `Coin::Serialize`: VARINT(height * 2 + coinbase) then the compressed TxOut.
pub fn write_coin<W: Write>(w: &mut W, coin: &Coin) -> io::Result<()> {
    write_varint(w, code_of(coin))?;
    write_txout_compressed(w, &coin.txout)
}

pub fn read_coin<R: Read>(r: &mut R) -> io::Result<Coin> {
    let code = read_code(r)?;
    let txout = read_txout_compressed(r)?;
    Ok(Coin {
        txout,
        height: code >> 1,
        is_coinbase: code & 1 == 1,
    })
}

/// Core `TxInUndoFormatter::Ser`. Coins above height 0 carry a zero dummy byte
/// that older versions used for the spending transaction's version.
pub fn write_undo_coin<W: Write>(w: &mut W, coin: &Coin) -> io::Result<()> {
    write_varint(w, code_of(coin))?;
    if coin.height > 0 {
        write_varint(w, 0)?;
    }
    write_txout_compressed(w, &coin.txout)
}

pub fn read_undo_coin<R: Read>(r: &mut R) -> io::Result<Coin> {
    let code = read_code(r)?;
    let height = code >> 1;
    if height > 0 {
        read_varint(r)?;
    }
    let txout = read_txout_compressed(r)?;
    Ok(Coin {
        txout,
        height,
        is_coinbase: code & 1 == 1,
    })
}

/// Core `CTxUndo`: CompactSize count followed by undo coins.
pub fn write_tx_undo<W: Write>(w: &mut W, tx: &TxUndo) -> io::Result<()> {
    write_compact_size(w, tx.prevout.len() as u64)?;
    for coin in &tx.prevout {
        write_undo_coin(w, coin)?;
    }
    Ok(())
}

pub fn read_tx_undo<R: Read>(r: &mut R) -> io::Result<TxUndo> {
    let count = read_compact_size(r)?;
    let mut prevout = Vec::new();
    for _ in 0..count {
        prevout.push(read_undo_coin(r)?);
    }
    Ok(TxUndo { prevout })
}

/// Core `CBlockUndo`: CompactSize count followed by one `CTxUndo` per non-coinbase transaction.
pub fn write_block_undo<W: Write>(w: &mut W, undo: &BlockUndo) -> io::Result<()> {
    write_compact_size(w, undo.vtxundo.len() as u64)?;
    for tx in &undo.vtxundo {
        write_tx_undo(w, tx)?;
    }
    Ok(())
}

pub fn read_block_undo<R: Read>(r: &mut R) -> io::Result<BlockUndo> {
    let count = read_compact_size(r)?;
    let mut vtxundo = Vec::new();
    for _ in 0..count {
        vtxundo.push(read_tx_undo(r)?);
    }
    Ok(BlockUndo { vtxundo })
}

/// Encodes block undo data into a fresh buffer.
pub fn encode_block_undo(undo: &BlockUndo) -> Vec<u8> {
    let mut buf = Vec::new();
    write_block_undo(&mut buf, undo).expect("writing to a Vec cannot fail");
    buf
}

/// Decodes block undo data that must consume the whole slice.
pub fn decode_block_undo(bytes: &[u8]) -> io::Result<BlockUndo> {
    let mut cursor = bytes;
    let undo = read_block_undo(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(invalid("trailing bytes after block undo data"));
    }
    Ok(undo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    use btc_primitives::TxOut;

    fn coin(value: i64, height: u32, is_coinbase: bool) -> Coin {
        Coin {
            txout: TxOut::new(value, ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x02])),
            height,
            is_coinbase,
        }
    }

    #[test]
    fn coin_roundtrip() {
        for c in [
            coin(1, 0, false),
            coin(50 * 100_000_000, 700_000, true),
            coin(0, 1, false),
        ] {
            let mut buf = Vec::new();
            write_coin(&mut buf, &c).unwrap();
            assert_eq!(read_coin(&mut buf.as_slice()).unwrap(), c);
        }
    }

    #[test]
    fn coin_code_matches_core_layout() {
        let mut buf = Vec::new();
        write_coin(&mut buf, &coin(0, 1, true)).unwrap();
        assert_eq!(buf[0], 0x03);
    }

    #[test]
    fn undo_coin_adds_dummy_only_above_height_zero() {
        let mut with_height = Vec::new();
        write_undo_coin(&mut with_height, &coin(5, 10, false)).unwrap();
        let mut no_height = Vec::new();
        write_undo_coin(&mut no_height, &coin(5, 0, false)).unwrap();
        assert_eq!(with_height.len(), no_height.len() + 1);
        assert_eq!(with_height[1], 0x00);

        let c = coin(5, 10, true);
        let mut buf = Vec::new();
        write_undo_coin(&mut buf, &c).unwrap();
        assert_eq!(read_undo_coin(&mut buf.as_slice()).unwrap(), c);
        let c = coin(5, 0, false);
        let mut buf = Vec::new();
        write_undo_coin(&mut buf, &c).unwrap();
        assert_eq!(read_undo_coin(&mut buf.as_slice()).unwrap(), c);
    }

    #[test]
    fn block_undo_roundtrip() {
        let undo = BlockUndo {
            vtxundo: vec![
                TxUndo {
                    prevout: vec![coin(10, 3, false), coin(20, 0, true)],
                },
                TxUndo { prevout: vec![] },
                TxUndo {
                    prevout: vec![coin(30, 999, false)],
                },
            ],
        };
        let bytes = encode_block_undo(&undo);
        assert_eq!(bytes[0], 3);
        assert_eq!(decode_block_undo(&bytes).unwrap(), undo);
        assert_eq!(
            decode_block_undo(&encode_block_undo(&BlockUndo::default())).unwrap(),
            BlockUndo::default()
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_block_undo(&trailing).is_err());
    }
}
