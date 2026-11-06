//! Node core: chainstate + mempool + fee estimator behind one lock.
//! Port of the glue in `node/context.h` and `validationinterface`.
//!
//! CONTRACT: RPC and P2P layers use only these public items.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use btc_chain::chainstate::{BlockStore, ChainEvent, Chainstate};
use btc_chain::mempool_accept::{accept_to_mempool, update_mempool_for_events, MempoolReject};
use btc_chain::miner::generate_block;
use btc_chain::{IndexId, ValidationError};
use btc_consensus::ChainParams;
use btc_primitives::{Block, BlockHash, BlockHeader, ScriptBuf, Tx, Txid};
use btc_validation::coins::CoinsViewWrite;
use btc_validation::fees::FeeEstimator;
use btc_validation::mempool::Mempool;

/// Default `-maxmempool` expressed as an entry cap.
pub const DEFAULT_MEMPOOL_ENTRIES: usize = 50_000;

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub struct Node {
    pub params: ChainParams,
    pub chainstate: Chainstate,
    pub mempool: Mempool,
    pub fees: FeeEstimator,
    /// Hashes of blocks connected since the last `take_new_tips` (for relay).
    new_tips: Vec<BlockHash>,
    /// Txids accepted since the last `take_new_txs` (for relay).
    new_txs: Vec<Txid>,
}

pub type SharedNode = Arc<Mutex<Node>>;

impl Node {
    pub fn new(
        params: ChainParams,
        genesis: Block,
        coins: Box<dyn CoinsViewWrite + Send>,
        store: Box<dyn BlockStore>,
    ) -> Result<Self, ValidationError> {
        let chainstate = Chainstate::new(params.clone(), genesis, coins, store)?;
        Ok(Self {
            params,
            chainstate,
            mempool: Mempool::new(DEFAULT_MEMPOOL_ENTRIES),
            fees: FeeEstimator::new(),
            new_tips: Vec::new(),
            new_txs: Vec::new(),
        })
    }

    pub fn shared(self) -> SharedNode {
        Arc::new(Mutex::new(self))
    }

    fn after_chain_change(&mut self) {
        let events = self.chainstate.take_events();
        if events.is_empty() {
            return;
        }
        update_mempool_for_events(&self.chainstate, &mut self.mempool, &events);
        for event in &events {
            if let ChainEvent::BlockConnected { hash, height } = event {
                if let Some(block) = self.chainstate.get_block(hash) {
                    let txids: Vec<Txid> = block.txdata.iter().map(|t| t.txid()).collect();
                    self.fees.process_block(*height, &txids);
                }
                self.new_tips.push(*hash);
            }
        }
    }

    /// `ProcessNewBlock` + mempool/fee updates. Ok(true) if new.
    pub fn submit_block(&mut self, block: &Block) -> Result<bool, ValidationError> {
        let result = self.chainstate.process_new_block(block, now_secs());
        self.after_chain_change();
        result
    }

    pub fn submit_headers(&mut self, headers: &[BlockHeader]) -> Result<IndexId, ValidationError> {
        self.chainstate.process_new_block_headers(headers, now_secs())
    }

    /// `AcceptToMemoryPool` + fee tracking.
    pub fn submit_tx(&mut self, tx: Tx) -> Result<Txid, MempoolReject> {
        let txid = accept_to_mempool(&self.chainstate, &mut self.mempool, tx)?;
        if let Some(entry) = self.mempool.get(&txid) {
            let rate = entry.fee as f64 * 1000.0 / entry.vsize as f64;
            self.fees.process_transaction(txid, self.chainstate.height(), rate);
        }
        self.new_txs.push(txid);
        Ok(txid)
    }

    /// Mine `n` blocks to `script` (regtest-style `generatetoaddress`).
    pub fn generate(&mut self, n: u32, script: &ScriptBuf) -> Result<Vec<BlockHash>, ValidationError> {
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let hash = generate_block(&mut self.chainstate, &self.mempool, script.clone(), now_secs())?;
            self.after_chain_change();
            out.push(hash);
        }
        Ok(out)
    }

    pub fn take_new_tips(&mut self) -> Vec<BlockHash> {
        std::mem::take(&mut self.new_tips)
    }

    pub fn take_new_txs(&mut self) -> Vec<Txid> {
        std::mem::take(&mut self.new_txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_chain::chainstate::MemBlockStore;
    use btc_validation::coins::CoinsViewMemory;

    #[test]
    fn generate_extends_regtest_chain() {
        let params = ChainParams::regtest();
        let genesis = btc_consensus::regtest_genesis_block();
        let mut node = Node::new(params, genesis, Box::new(CoinsViewMemory::new()), Box::<MemBlockStore>::default()).unwrap();
        let hashes = node.generate(5, &ScriptBuf::from_bytes(vec![0x51])).unwrap();
        assert_eq!(hashes.len(), 5);
        assert_eq!(node.chainstate.height(), 5);
        assert_eq!(node.take_new_tips(), hashes);
    }
}
