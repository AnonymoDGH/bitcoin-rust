#![allow(dead_code)]

use std::sync::Mutex;

use bitcoin::{Network, OutPoint, TxMerkleNode, WPubkeyHash};
use bitcoin_hashes::Hash;
use btc_primitives::{Block, BlockHash, BlockHeader, ScriptBuf, Tx, TxIn, TxOut, Txid};
use btc_rpc::{BlockchainInfo, MempoolInfo, RpcBackend};
use btc_wallet::address::{encode_address, Network as WalletNetwork};

/// In-memory node state. `blocks[h]` is the active chain at height `h`.
pub struct Chain {
    pub blocks: Vec<Block>,
    /// Blocks not in the active chain, with their heights.
    pub stale: Vec<(Block, u32)>,
    pub mempool: Vec<Tx>,
    pub utxos: Vec<(OutPoint, TxOut, u32, bool)>,
    pub stopped: bool,
    pub reject_tx: Option<String>,
    pub reject_block: Option<String>,
}

pub struct MockBackend {
    chain: Mutex<Chain>,
}

impl MockBackend {
    /// Three-block regtest chain. Block 2 spends block 1's coinbase, the mempool
    /// holds a spend of block 0's coinbase, and block 2's coinbase is unspent.
    pub fn new() -> Self {
        let coinbase0 = coinbase(p2wpkh_script(0x11), 50_0000_0000, 0);
        let block0 = make_block(BlockHash::all_zeros(), 1_000, vec![coinbase0.clone()]);
        let coinbase1 = coinbase(p2wpkh_script(0x22), 50_0000_0000, 1);
        let block1 = make_block(block0.block_hash(), 1_001, vec![coinbase1.clone()]);
        let coinbase2 = coinbase(p2wpkh_script(0x33), 50_0000_0000, 2);
        let spend_tx = spend(
            OutPoint {
                txid: coinbase1.txid(),
                vout: 0,
            },
            49_0000_0000,
            p2wpkh_script(0x44),
        );
        let block2 = make_block(
            block1.block_hash(),
            1_002,
            vec![coinbase2.clone(), spend_tx],
        );
        let utxo = (
            OutPoint {
                txid: coinbase2.txid(),
                vout: 0,
            },
            coinbase2.vout[0].clone(),
            1,
            true,
        );
        let mempool_spend = spend_of(&coinbase0);
        Self {
            chain: Mutex::new(Chain {
                blocks: vec![block0, block1, block2],
                stale: Vec::new(),
                mempool: vec![mempool_spend],
                utxos: vec![utxo],
                stopped: false,
                reject_tx: None,
                reject_block: None,
            }),
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Chain) -> R) -> R {
        f(&mut self.chain.lock().unwrap())
    }
}

fn tip_height(chain: &Chain) -> u32 {
    (chain.blocks.len() - 1) as u32
}

impl RpcBackend for MockBackend {
    fn get_block_count(&self) -> u32 {
        self.with(|c| tip_height(c))
    }

    fn get_best_block_hash(&self) -> BlockHash {
        self.with(|c| c.blocks.last().unwrap().block_hash())
    }

    fn get_block_hash(&self, height: u32) -> Option<BlockHash> {
        self.with(|c| c.blocks.get(height as usize).map(Block::block_hash))
    }

    fn get_block(&self, hash: &BlockHash) -> Option<(Block, u32, i64)> {
        self.with(|c| {
            if let Some(height) = c.blocks.iter().position(|b| &b.block_hash() == hash) {
                let confirmations = i64::from(tip_height(c)) - height as i64 + 1;
                return Some((c.blocks[height].clone(), height as u32, confirmations));
            }
            c.stale
                .iter()
                .find(|(b, _)| &b.block_hash() == hash)
                .map(|(b, height)| (b.clone(), *height, -1))
        })
    }

    fn get_block_header(&self, hash: &BlockHash) -> Option<(BlockHeader, u32, i64)> {
        self.get_block(hash)
            .map(|(block, height, conf)| (block.header, height, conf))
    }

    fn get_blockchain_info(&self) -> BlockchainInfo {
        self.with(|c| {
            let tip = c.blocks.last().unwrap();
            BlockchainInfo {
                chain: "regtest".into(),
                blocks: tip_height(c),
                headers: tip_height(c),
                bestblockhash: tip.block_hash(),
                difficulty: 4.656_542_373_906_925e-10,
                mediantime: i64::from(tip.header.time),
                chainwork: format!("{:064x}", 3 * (tip_height(c) + 1)),
            }
        })
    }

    fn get_raw_mempool(&self) -> Vec<Txid> {
        self.with(|c| c.mempool.iter().map(Tx::txid).collect())
    }

    fn get_mempool_info(&self) -> MempoolInfo {
        self.with(|c| MempoolInfo {
            size: c.mempool.len() as u64,
            bytes: c.mempool.iter().map(|tx| tx.total_size() as u64).sum(),
        })
    }

    fn get_raw_transaction(&self, txid: &Txid) -> Option<Tx> {
        self.with(|c| {
            c.mempool
                .iter()
                .chain(c.blocks.iter().flat_map(|b| b.txdata.iter()))
                .find(|tx| &tx.txid() == txid)
                .cloned()
        })
    }

    fn send_raw_transaction(&self, tx: Tx) -> Result<Txid, String> {
        self.with(|c| {
            if let Some(reason) = &c.reject_tx {
                return Err(reason.clone());
            }
            let txid = tx.txid();
            c.mempool.push(tx);
            Ok(txid)
        })
    }

    fn submit_block(&self, block: Block) -> Result<(), String> {
        self.with(|c| {
            if let Some(reason) = &c.reject_block {
                return Err(reason.clone());
            }
            c.blocks.push(block);
            Ok(())
        })
    }

    fn generate_to_script(&self, n: u32, script: ScriptBuf) -> Result<Vec<BlockHash>, String> {
        self.with(|c| {
            let mut hashes = Vec::new();
            for _ in 0..n {
                let height = c.blocks.len() as u32;
                let prev = c.blocks.last().unwrap().block_hash();
                let cb = coinbase(script.clone(), 50_0000_0000, height);
                let block = make_block(prev, 2_000 + height, vec![cb]);
                hashes.push(block.block_hash());
                c.blocks.push(block);
            }
            Ok(hashes)
        })
    }

    fn get_tx_out(&self, outpoint: &OutPoint) -> Option<(TxOut, u32, bool)> {
        self.with(|c| {
            c.utxos
                .iter()
                .find(|(op, ..)| op == outpoint)
                .map(|(_, out, conf, cb)| (out.clone(), *conf, *cb))
        })
    }

    fn network(&self) -> Network {
        Network::Regtest
    }

    fn stop(&self) {
        self.with(|c| c.stopped = true);
    }
}

pub fn p2wpkh_script(seed: u8) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20]))
}

pub fn regtest_address(script: &ScriptBuf) -> String {
    encode_address(WalletNetwork::Regtest, script).unwrap()
}

pub fn coinbase(script: ScriptBuf, value: i64, height: u32) -> Tx {
    let mut input = TxIn::new(OutPoint {
        txid: Txid::all_zeros(),
        vout: u32::MAX,
    });
    input.script_sig = ScriptBuf::from_bytes(vec![0x01, height as u8]);
    Tx::new(2, vec![input], vec![TxOut::new(value, script)], 0)
}

pub fn spend(prevout: OutPoint, value: i64, script: ScriptBuf) -> Tx {
    Tx::new(
        2,
        vec![TxIn::new(prevout)],
        vec![TxOut::new(value, script)],
        0,
    )
}

fn spend_of(tx: &Tx) -> Tx {
    spend(
        OutPoint {
            txid: tx.txid(),
            vout: 0,
        },
        49_0000_0000,
        p2wpkh_script(0x55),
    )
}

pub fn make_block(prev: BlockHash, time: u32, txdata: Vec<Tx>) -> Block {
    let header = BlockHeader::new(
        0x2000_0000,
        prev,
        TxMerkleNode::all_zeros(),
        time,
        0x207f_ffff,
        time,
    );
    Block::new(header, txdata)
}
