//! End-to-end confidential payments between wallets through a real
//! chainstate: shield, pay a stealth recipient, recipient recovers the
//! hidden value, spends it onwards. Blocks come from the real block
//! assembler; every CT transaction passes `accept_to_mempool` and
//! `ConnectBlock` (range proofs, balance proof, owner signatures).

use std::fs;
use std::path::PathBuf;

use bitcoin::hashes::Hash as _;
use bitcoin::{BlockHash, OutPoint, ScriptBuf, TxMerkleNode};
use btc_chain::chainstate::{Chainstate, MemBlockStore};
use btc_chain::mempool_accept::accept_to_mempool;
use btc_chain::miner::generate_block;
use btc_consensus::ChainParams;
use btc_primitives::{Block, BlockHeader, Tx, TxIn, TxOut};
use btc_validation::block_verify::block_merkle_root;
use btc_validation::coins::CoinsViewMemory;
use btc_validation::mempool::Mempool;
use btc_wallet::wallet::scan_ct_output;
use btc_wallet::{ScriptKind, Wallet};

const NOW: i64 = 2_000_000_000;
const COIN: u64 = 100_000_000;

struct TestFile(PathBuf);

impl TestFile {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("btc-wallet-cte2e-{}-{name}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        TestFile(path)
    }
}

impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn regtest_genesis() -> Block {
    const TIMESTAMP: &[u8] = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const PUBKEY: &str = "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";
    let mut script_sig = vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, TIMESTAMP.len() as u8];
    script_sig.extend_from_slice(TIMESTAMP);
    let mut script_pubkey = vec![0x41];
    script_pubkey.extend((0..PUBKEY.len()).step_by(2).map(|i| u8::from_str_radix(&PUBKEY[i..i + 2], 16).unwrap()));
    script_pubkey.push(0xac);
    let mut input = TxIn::new(OutPoint::null());
    input.script_sig = ScriptBuf::from_bytes(script_sig);
    let coinbase = Tx::new(1, vec![input], vec![TxOut::new(50 * 100_000_000, ScriptBuf::from_bytes(script_pubkey))], 0);
    let mut block = Block::new(
        BlockHeader::new(1, BlockHash::all_zeros(), TxMerkleNode::all_zeros(), 1_296_688_602, 0x207fffff, 2),
        vec![coinbase],
    );
    block.header.merkle_root = block_merkle_root(&block).0;
    block
}

fn ct_chain() -> Chainstate {
    let mut params = ChainParams::regtest();
    params.ct_enabled = true;
    Chainstate::new(
        params,
        regtest_genesis(),
        Box::new(CoinsViewMemory::new()),
        Box::new(MemBlockStore::default()),
    )
    .expect("regtest genesis loads")
}

fn new_wallet(file: &TestFile) -> Wallet {
    Wallet::create(&file.0).unwrap()
}

/// Mines one block from `pool` paying `payout`, and feeds it to `wallets`.
fn mine(cs: &mut Chainstate, pool: &Mempool, payout: &ScriptBuf, wallets: &mut [&mut Wallet]) -> Block {
    let hash = generate_block(cs, pool, payout.clone(), NOW).expect("block accepted");
    let block = cs.get_block(&hash).expect("block stored");
    let height = cs.height();
    for wallet in wallets.iter_mut() {
        wallet.block_connected(&block, height).unwrap();
    }
    block
}

/// Flips one bit of the value ciphertext of the first CT output.
fn tamper_value_enc(tx: &Tx) -> Tx {
    let mut bad = tx.clone();
    let mut bytes = bad.vout[0].script_pubkey.as_bytes().to_vec();
    bytes[88] ^= 0x01; // v_enc offset, see CtOutputData
    bad.vout[0].script_pubkey = ScriptBuf::from_bytes(bytes);
    bad
}

#[test]
fn ct_payment_is_recovered_and_respent_by_recipient() {
    let (fa, fb, fc, fd) = (TestFile::new("a"), TestFile::new("b"), TestFile::new("c"), TestFile::new("d"));
    let (mut a, mut b, mut c, mut d) = (new_wallet(&fa), new_wallet(&fb), new_wallet(&fc), new_wallet(&fd));
    let mut cs = ct_chain();

    // A mines 101 blocks to a P2PKH script so the first coinbase is
    // mature for the hybrid shield.
    let a_payout = a.new_script(ScriptKind::P2pkh).unwrap();
    for _ in 0..101 {
        mine(&mut cs, &Mempool::new(100), &a_payout, &mut [&mut a, &mut b, &mut c, &mut d]);
    }
    assert_eq!(cs.height(), 101);

    // 1. A shields. The CT output is addressed to A's own stealth
    //    address, so A's wallet recovers it by scanning (no manual
    //    record_ct_coin).
    let subsidy = ChainParams::regtest().block_subsidy(1) as u64;
    let shield_fee = 10_000u64;
    let shield_amount = subsidy - shield_fee;
    let (shield_tx, shield_info, shield_op) =
        a.create_hybrid_ct(cs.height(), shield_amount, shield_fee as i64).unwrap();
    let mut pool = Mempool::new(100);
    accept_to_mempool(&cs, &mut pool, shield_tx.clone()).expect("shield accepted to mempool");
    a.commit_transaction(&shield_tx).unwrap();
    assert_eq!(shield_info.value, shield_amount);
    mine(&mut cs, &pool, &a_payout, &mut [&mut a, &mut b, &mut c, &mut d]);
    assert_eq!(cs.height(), 102);
    assert_eq!(a.ct_balance(cs.height()), shield_amount as i64);
    assert_eq!(
        a.coins_snapshot().get(&shield_op).and_then(|coin| coin.ct.as_ref()).map(|i| i.value),
        Some(shield_amount)
    );

    // 2. A pays B 30 coins confidentially (B's stealth address). Before
    //    the genuine tx exists, a tampered copy with a flipped v_enc must
    //    not be adopted by B (commitment check), and neither D nor A
    //    sees the output as theirs.
    let b_addr = b.stealth_address().unwrap();
    let pay_fee = 20_000i64;
    let (pay_tx, a_outputs) = a
        .create_ct_payment(cs.height(), &[(b_addr, 30 * COIN)], pay_fee)
        .unwrap();
    // Only the change output belongs to A.
    assert_eq!(a_outputs.len(), 1);
    assert_eq!(a_outputs[0].0, OutPoint::new(pay_tx.txid(), 1));
    assert_eq!(a_outputs[0].1.value, shield_amount - 30 * COIN - pay_fee as u64);

    let tampered = tamper_value_enc(&pay_tx);
    b.tx_added_to_mempool(&tampered).unwrap();
    assert_eq!(b.ct_balance(cs.height()), 0, "tampered v_enc must be rejected by the commitment check");
    assert!(b.coins_snapshot().is_empty() || b.coins_snapshot().keys().all(|op| op.txid != tampered.txid()));
    assert!(scan_ct_output(&b.stealth_keys().unwrap(), tampered.vout[0].script_pubkey.as_bytes(), 0).is_none());
    // The genuine output opens for B only.
    let genuine = scan_ct_output(&b.stealth_keys().unwrap(), pay_tx.vout[0].script_pubkey.as_bytes(), 0)
        .expect("recipient recovers the opening");
    assert_eq!(genuine.value, 30 * COIN);
    assert!(scan_ct_output(&d.stealth_keys().unwrap(), pay_tx.vout[0].script_pubkey.as_bytes(), 0).is_none());
    assert!(scan_ct_output(&c.stealth_keys().unwrap(), pay_tx.vout[0].script_pubkey.as_bytes(), 0).is_none());
    // Wrong output index: derivation is bound to the position.
    assert!(scan_ct_output(&b.stealth_keys().unwrap(), pay_tx.vout[0].script_pubkey.as_bytes(), 1).is_none());

    let mut pool = Mempool::new(100);
    accept_to_mempool(&cs, &mut pool, pay_tx.clone()).expect("CT payment accepted to mempool");
    a.commit_transaction(&pay_tx).unwrap();
    mine(&mut cs, &pool, &a_payout, &mut [&mut a, &mut b, &mut c, &mut d]);
    assert_eq!(cs.height(), 103);

    // B recovered the hidden value from the chain and can spend it.
    assert_eq!(b.ct_balance(cs.height()), (30 * COIN) as i64);
    assert_eq!(d.ct_balance(cs.height()), 0, "a stranger recovers nothing");
    assert_eq!(c.ct_balance(cs.height()), 0);
    assert_eq!(
        a.ct_balance(cs.height()),
        (shield_amount - 30 * COIN - pay_fee as u64) as i64,
        "A holds only its change"
    );
    assert!(d.coins_snapshot().values().all(|coin| coin.ct.is_none()));

    // 3. B spends the received coin to C (and keeps change).
    let c_addr = c.stealth_address().unwrap();
    let (spend_tx, b_change) = b
        .create_ct_payment(cs.height(), &[(c_addr, 10 * COIN)], pay_fee)
        .expect("B can spend the CT output it received");
    assert_eq!(b_change.len(), 1);
    assert_eq!(b_change[0].1.value, 20 * COIN - pay_fee as u64);
    let mut pool = Mempool::new(100);
    accept_to_mempool(&cs, &mut pool, spend_tx.clone()).expect("B's CT spend accepted to mempool");
    b.commit_transaction(&spend_tx).unwrap();
    mine(&mut cs, &pool, &a_payout, &mut [&mut a, &mut b, &mut c, &mut d]);
    assert_eq!(cs.height(), 104);
    assert_eq!(c.ct_balance(cs.height()), (10 * COIN) as i64);
    assert_eq!(b.ct_balance(cs.height()), (20 * COIN - pay_fee as u64) as i64);
    assert_eq!(d.ct_balance(cs.height()), 0);

    // 4. C can spend onwards too (back to A).
    let a_addr = a.stealth_address().unwrap();
    let (back_tx, c_change) = c
        .create_ct_payment(cs.height(), &[(a_addr, 5 * COIN)], pay_fee)
        .expect("C can spend what B sent");
    assert_eq!(c_change[0].1.value, 5 * COIN - pay_fee as u64);
    let mut pool = Mempool::new(100);
    accept_to_mempool(&cs, &mut pool, back_tx.clone()).unwrap();
    c.commit_transaction(&back_tx).unwrap();
    let a_before = a.ct_balance(cs.height());
    mine(&mut cs, &pool, &a_payout, &mut [&mut a, &mut b, &mut c, &mut d]);
    assert_eq!(a.ct_balance(cs.height()), a_before + (5 * COIN) as i64);

    // The recovered coin state survives a wallet restart.
    drop(b);
    let b = Wallet::open(&fb.0).unwrap();
    assert_eq!(b.ct_balance(cs.height()), (20 * COIN - pay_fee as u64) as i64);
}

/// A recipient wallet that was offline sees the payment only through
/// block scanning of the connected block (no mempool step): the same
/// recovery path as `block_connected` on a freshly started node.
#[test]
fn recipient_recovers_from_block_scan_only() {
    let (fa, fb) = (TestFile::new("scan-a"), TestFile::new("scan-b"));
    let (mut a, mut b) = (new_wallet(&fa), new_wallet(&fb));
    let mut cs = ct_chain();
    let a_payout = a.new_script(ScriptKind::P2pkh).unwrap();
    for _ in 0..101 {
        mine(&mut cs, &Mempool::new(100), &a_payout, &mut [&mut a]);
    }
    let subsidy = ChainParams::regtest().block_subsidy(1) as u64;
    let (shield_tx, _, _) = a.create_hybrid_ct(cs.height(), subsidy - 10_000, 10_000).unwrap();
    let mut pool = Mempool::new(100);
    accept_to_mempool(&cs, &mut pool, shield_tx.clone()).unwrap();
    a.commit_transaction(&shield_tx).unwrap();
    mine(&mut cs, &pool, &a_payout, &mut [&mut a]);

    let b_addr = b.stealth_address().unwrap();
    let (pay_tx, _) = a.create_ct_payment(cs.height(), &[(b_addr, 7 * COIN), (b_addr, 3 * COIN)], 20_000).unwrap();
    let mut pool = Mempool::new(100);
    accept_to_mempool(&cs, &mut pool, pay_tx.clone()).unwrap();
    a.commit_transaction(&pay_tx).unwrap();
    // B never saw the mempool; it learns of the payment from the block.
    mine(&mut cs, &pool, &a_payout, &mut [&mut a, &mut b]);
    assert_eq!(b.ct_balance(cs.height()), (10 * COIN) as i64, "both outputs recovered, each at its own index");
    let values: Vec<u64> = {
        let mut v: Vec<u64> = b
            .coins_snapshot()
            .values()
            .filter_map(|coin| coin.ct.as_ref().map(|i| i.value))
            .collect();
        v.sort();
        v
    };
    assert_eq!(values, vec![3 * COIN, 7 * COIN]);
}
