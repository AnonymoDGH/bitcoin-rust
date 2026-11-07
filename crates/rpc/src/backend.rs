//! The node interface the RPC layer is written against.

use bitcoin::Network;
use btc_wallet::address::{AddressParams, Network as WalletNetwork};
use btc_primitives::{Block, BlockHash, BlockHeader, OutPoint, ScriptBuf, Tx, TxOut, Txid};

/// Subset of `getblockchaininfo` the RPC layer renders.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub bestblockhash: BlockHash,
    pub difficulty: f64,
    pub mediantime: i64,
    pub chainwork: String,
}

/// Subset of `getmempoolinfo` the RPC layer renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MempoolInfo {
    pub size: u64,
    pub bytes: u64,
}

/// Everything the JSON-RPC methods need from the node.
///
/// Errors from the mutating methods carry the rejection reason verbatim, which
/// the RPC layer forwards to the client as Core does.
pub trait RpcBackend: Send + Sync + 'static {
    fn get_block_count(&self) -> u32;
    fn get_best_block_hash(&self) -> BlockHash;
    fn get_block_hash(&self, height: u32) -> Option<BlockHash>;
    /// Returns the block, its height and its confirmations (-1 when not in the active chain).
    fn get_block(&self, hash: &BlockHash) -> Option<(Block, u32, i64)>;
    /// Returns the header, its height and its confirmations (-1 when not in the active chain).
    fn get_block_header(&self, hash: &BlockHash) -> Option<(BlockHeader, u32, i64)>;
    fn get_blockchain_info(&self) -> BlockchainInfo;
    fn get_raw_mempool(&self) -> Vec<Txid>;
    fn get_mempool_info(&self) -> MempoolInfo;
    fn get_raw_transaction(&self, txid: &Txid) -> Option<Tx>;
    fn send_raw_transaction(&self, tx: Tx) -> Result<Txid, String>;
    /// `Ok(())` when the block was accepted, otherwise the BIP22 rejection reason.
    fn submit_block(&self, block: Block) -> Result<(), String>;
    fn generate_to_script(&self, n: u32, script: ScriptBuf) -> Result<Vec<BlockHash>, String>;
    /// Returns the output, its confirmations and whether it is a coinbase output.
    fn get_tx_out(&self, outpoint: &OutPoint) -> Option<(TxOut, u32, bool)>;
    fn network(&self) -> Network;
    /// Address prefixes of this chain. Custom coins override this.
    fn address_params(&self) -> AddressParams {
        let n = match self.network() {
            Network::Bitcoin => WalletNetwork::Main,
            Network::Regtest => WalletNetwork::Regtest,
            _ => WalletNetwork::Test,
        };
        AddressParams::from(n)
    }
    /// The loaded wallet, if any (`-disablewallet` = None).
    fn wallet(&self) -> Option<&dyn WalletRpc> {
        None
    }
    fn stop(&self);
}

/// One wallet-owned unspent output (`listunspent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletUtxo {
    pub outpoint: OutPoint,
    pub script_pubkey: ScriptBuf,
    pub amount: i64,
    pub confirmations: u32,
    pub spendable: bool,
}

/// `getwalletinfo` fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletInfo {
    pub name: String,
    pub balance: i64,
    pub unconfirmed_balance: i64,
    pub immature_balance: i64,
    pub tx_count: usize,
    pub keypool_size: usize,
    pub encrypted: bool,
    /// Unix time the wallet relocks at; 0 = locked (only when encrypted).
    pub unlocked_until: u64,
}

/// One `listtransactions` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletTx {
    pub txid: Txid,
    /// "send", "receive", "generate" or "immature".
    pub category: String,
    /// Net amount in satoshis (negative for sends).
    pub amount: i64,
    pub fee: Option<i64>,
    pub script_pubkey: Option<ScriptBuf>,
    /// -1 / 0 = unconfirmed, conflicted handled as 0.
    pub confirmations: i64,
    pub blockhash: Option<BlockHash>,
    pub time: i64,
}

/// Wallet methods (`src/wallet/rpc/*.cpp`). Amounts are satoshis; errors are
/// Core-style messages forwarded to the client.
pub trait WalletRpc: Send + Sync {
    /// `kind`: "legacy", "p2sh-segwit", "bech32" (default), "bech32m".
    fn get_new_address(&self, kind: Option<&str>) -> Result<ScriptBuf, String>;
    fn get_balance(&self, minconf: u32) -> i64;
    fn list_unspent(&self, minconf: u32, maxconf: u32) -> Vec<WalletUtxo>;
    /// Builds, signs and broadcasts. `fee_rate` in sat/kvB (None = estimate or fallback).
    fn send_to(&self, script: ScriptBuf, amount: i64, fee_rate: Option<i64>, subtract_fee: bool) -> Result<Txid, String>;
    fn dump_privkey(&self, script: &ScriptBuf) -> Result<String, String>;
    fn import_privkey(&self, wif: &str) -> Result<(), String>;
    fn wallet_info(&self) -> WalletInfo;
    /// Newest last, like Core: skip `skip` newest then return up to `count`.
    fn list_transactions(&self, count: usize, skip: usize) -> Vec<WalletTx>;
    fn encrypt_wallet(&self, passphrase: &str) -> Result<(), String>;
    fn wallet_passphrase(&self, passphrase: &str, timeout_secs: u64) -> Result<(), String>;
    fn wallet_lock(&self) -> Result<(), String>;

    /// Reusable stealth invitation address, hex of 66 bytes
    /// (spending_pub || scan_pub). Payments to it derive a fresh
    /// one-time address per sender, so they cannot be linked.
    fn get_stealth_address(&self) -> Result<String, String>;

    /// Scans blocks and the mempool for stealth payments to this wallet:
    /// transactions carrying a marker output (`OP_RETURN <ephemeral_pub>`)
    /// whose other outputs match the derived one-time addresses.
    fn list_stealth_utxos(&self, minconf: u32, max_blocks: u32) -> Vec<WalletUtxo>;
}
