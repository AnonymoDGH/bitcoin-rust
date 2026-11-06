//! Chainstate survives a restart on disk-backed storage.

use btc_chain::chainstate::Chainstate;
use btc_chain::miner::generate_block;
use btc_consensus::{regtest_genesis_block, ChainParams};
use btc_primitives::ScriptBuf;
use btc_storage::{CoinsDb, DiskBlockStore};
use btc_validation::mempool::Mempool;

fn open(dir: &std::path::Path) -> Chainstate {
    let params = ChainParams::regtest();
    let coins = CoinsDb::open(dir.join("chainstate")).unwrap();
    let store = DiskBlockStore::open(dir.join("blocks"), params.magic).unwrap();
    Chainstate::new(params, regtest_genesis_block(), Box::new(coins), Box::new(store)).unwrap()
}

#[test]
fn tip_and_utxos_persist_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let script = ScriptBuf::from_bytes(vec![0x51]);
    let (tip, height) = {
        let mut cs = open(dir.path());
        let pool = Mempool::new(10);
        let mut now = 1_700_000_000;
        for _ in 0..12 {
            now += 600;
            generate_block(&mut cs, &pool, script.clone(), now).unwrap();
        }
        (cs.tip_hash(), cs.height())
    };
    assert_eq!(height, 12);

    let mut cs = open(dir.path());
    assert_eq!(cs.height(), 12);
    assert_eq!(cs.tip_hash(), tip);
    let coinbase = cs.get_block(&cs.block_hash_at(5).unwrap()).unwrap().txdata[0].txid();
    let op = btc_primitives::OutPoint { txid: coinbase, vout: 0 };
    assert!(cs.coins_view().get_coin(&op).is_some());

    // The reloaded chain keeps extending and can still reorg via undo data.
    let pool = Mempool::new(10);
    generate_block(&mut cs, &pool, script, 1_700_100_000).unwrap();
    assert_eq!(cs.height(), 13);
    let at8 = cs.block_hash_at(8).unwrap();
    cs.invalidate_block(&at8).unwrap();
    assert_eq!(cs.height(), 7);
}
