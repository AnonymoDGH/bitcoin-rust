# bitcoin-rust

Rust translation of **Bitcoin Core** (`github.com/bitcoin/bitcoin`, reference at commit `6996cf7`),
organized as a workspace of 10 crates that mirror `src/`:

| Crate | Role |
|---|---|
| `btc-primitives` | `Tx` / `Block` / `TxIn` / `TxOut` data model (wire encoding via `rust-bitcoin`) |
| `btc-consensus` | Chain params, block-PoW, halving subsidies, compact-target math |
| `btc-validation` | UTXO set, `CheckTransaction` / `CheckTxInputs`, block-merkle checks, `Policy`, mempool |
| `btc-network` | P2P message framing (magic/checksum), async peer handshake, `AddrMan` |
| `btc-wallet` | Addresses, keys/WIF, signing (P2PKH/P2WPKH/P2SH-P2WPKH/P2TR), coin selection, tx builder |
| `btc-node` | Daemon: config, node core, RPC backend, P2P manager, custom-coin chain spec |
| `btc-script` | **Script interpreter**: full opcode dispatch, legacy/BIP143/BIP341 sighash — all Bitcoin Core `script_tests.json` vectors pass |
| `btc-chain` | Block index + skip list, contextual checks, `ConnectBlock`/`DisconnectBlock`, reorgs, `AcceptToMemoryPool`, block assembler/miner |
| `btc-storage` | `blk*.dat`/`rev*.dat` flat files, Core coin compression, crash-safe UTXO db |
| `btc-rpc` | JSON-RPC HTTP server (cookie/basic auth), Core error codes |

## Status

- Phase 1 — `btc-primitives`, `btc-consensus`: data model and consensus math, 15 unit tests pass.
- Phase 2 — `btc-validation`, `btc-network`, `btc-wallet`, `btc-node`: UTXO set, tx/block checks, P2P framing and handshake, addresses, coin selection, config resolution. All compile, 45+ tests pass.
- Phase 3 — `btc-script`: full `EvalScript` dispatch ported from `interpreter.cpp`.
  **1280/1280 vectors of Core's `script_tests.json` pass** (`cargo test --test script_vectors`).

- Phase 4 — chainstate: block index, contextual checks, ConnectBlock/DisconnectBlock with undo,
  reorgs and invalidation, mempool acceptance, fee estimator, miner, headers-first sync, disk storage.
- Phase 5 — node: `btc-node` runs a full node with RPC, P2P sync and on-disk chain; custom coins via JSON spec.
- Group 1 — wallet + discovery: persistent encrypted wallet (Core CCrypter), wallet RPCs, coin-specific
  address prefixes, DNS/seed nodes, addr relay, `peers.dat`. 361 workspace tests pass.

## Run your own coin

```bash
cargo build --release -p btc-node
./target/release/btc-node -printchainspec > mycoin.json   # edit name, magic, ports, reward, spacing…
./target/release/btc-node -chainspec=mycoin.json -datadir=./node1 -rpcuser=u -rpcpassword=p
./target/release/btc-node -chainspec=mycoin.json -datadir=./node2 -port=19002 -rpcport=19102 \
  -rpcuser=u -rpcpassword=p -connect=127.0.0.1:18555
curl -u u:p -d '{"method":"getnewaddress"}' http://127.0.0.1:18556/
curl -u u:p -d '{"method":"generatetoaddress","params":[101,"<address>"]}' http://127.0.0.1:18556/
curl -u u:p -d '{"method":"sendtoaddress","params":["<other address>", 12.5]}' http://127.0.0.1:18556/
```

Wallet RPCs: `getnewaddress`, `getbalance`, `getbalances`, `listunspent`, `sendtoaddress`, `getwalletinfo`,
`listtransactions`, `dumpprivkey`, `importprivkey`, `encryptwallet`, `walletpassphrase`, `walletlock`,
`validateaddress`. Flags: `-wallet=<file>`, `-disablewallet`, `-seednode`, `-addnode`, `-dnsseed`,
`-externalip`, `-maxconnections`. Add `"seeds": ["host:port", ...]` to the chain spec for discovery.

Mining: `generatetoaddress <n> <address>` for explicit blocks, or `-gen -genaddress=<address|script hex>`
to mine in the background. `-gen` hashes until a block is found and immediately starts the next template;
add `-blockinterval=<secs>` to throttle (old fixed-interval behaviour) and `-maxblocks=<n>` to stop after
n blocks. On regtest that is roughly 90 blocks/s, so use `-maxblocks` when leaving it unattended.

### Difficulty

Custom chains start hard and can only get harder: `pow_limit` equals the genesis target, so the minimum
difficulty is the launch difficulty, and retargeting every `target_timespan / target_spacing` blocks
(2016 by default, 600 s spacing) pushes the target towards the spacing as hash power changes.

| Preset | `genesis_bits` | Expected hashes/block | Time/block (1 CPU core, release) |
|---|---|---|---|
| `chains/hardcoin.json` | `1e00ffff` | ~16.7 M | ~40–200 s |
| `-printchainspec` default | `1e00ffff` | ~16.7 M | ~40–200 s |
| `chains/satoshibtc.json` | `1d00ffff` (Bitcoin initial difficulty) | ~4.3 B | ~3 h |

Halving the mantissa doubles the difficulty: `1e003fff` ≈ 67 M hashes, `1e001fff` ≈ 134 M.
Barely-harder than current defaults: `1f00ffff` ≈ 65 k hashes (~0.5 s).

```bash
cargo build --release -p btc-node
./target/release/btc-node -chainspec=chains/hardcoin.json -datadir=./node1 \
  -gen -genaddress=<address-or-script-hex> -maxblocks=10
# mining genesis block for hardcoin (bits 0x1e00ffff, expected ~16777472 hashes, ...)
```

Warning: genesis is mined synchronously at startup, so a `1d00ffff`-class spec does not start
for hours. Freeze the spec (`chainspec`) after launch — changing `genesis_bits`, `magic` or ports
afterwards produces a different genesis hash and orphans the chain.

Pending: DoS scoring/banning, mempool ancestor limits + RBF + persistence, UTXO cache (coins db is fully
in RAM), per-candidate best-chain index, header-only index on disk, compact blocks, BIP324, descriptors/PSBT.

Reference clone: `bitcoin-core-reference/` (excluded; use `git clone --depth 1 https://github.com/bitcoin/bitcoin.git`).

## Build

```bash
cargo check --workspace
cargo test --workspace
```

## Layout

```
crates/
  primitives/   block + transaction data model
  consensus/    chain params, PoW, subsidies, custom genesis
  validation/   UTXO set, tx/block checks, mempool, policy
  chain/        chainstate, reorgs, connect/disconnect, miner, validation
  storage/      flat block/undo files, hash index, coins log
  network/      P2P framing, handshake, address manager
  wallet/       addresses, coin selection, signing, encrypted wallet
  rpc/          JSON-RPC HTTP server, dispatch, cookie auth
  node/         daemon entry point: wires chain, storage, P2P, RPC, wallet
  script/       script interpreter (full dispatch, all Core script vectors pass)
```
