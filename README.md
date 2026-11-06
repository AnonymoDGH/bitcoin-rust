# bitcoin-rust

Rust translation of **Bitcoin Core** (`github.com/bitcoin/bitcoin`, reference at commit `6996cf7`),
organized as a workspace of 7 crates that mirror `src/`:

| Crate | Role |
|---|---|
| `btc-primitives` | `Tx` / `Block` / `TxIn` / `TxOut` data model (wire encoding via `rust-bitcoin`) |
| `btc-consensus` | Chain params, block-PoW, halving subsidies, compact-target math |
| `btc-validation` | UTXO set, `CheckTransaction` / `CheckTxInputs`, block-merkle checks, `Policy`, mempool |
| `btc-network` | P2P message framing (magic/checksum), async peer handshake, `AddrMan` |
| `btc-wallet` | Addresses (Base58Check + bech32/bech32m), coin selection (BnB / knapsack) |
| `btc-node` | `bitcoind` argument/config resolution ported from `args.cpp` |
| `btc-script` | **Script interpreter**: errors, flags, opcodes, script numbers, execution context, full opcode dispatch — all Bitcoin Core `script_tests.json` vectors pass |

## Status

- Phase 1 — `btc-primitives`, `btc-consensus`: data model and consensus math, 15 unit tests pass.
- Phase 2 — `btc-validation`, `btc-network`, `btc-wallet`, `btc-node`: UTXO set, tx/block checks, P2P framing and handshake, addresses, coin selection, config resolution. All compile, 45+ tests pass.
- Phase 3 — `btc-script`: full `EvalScript` dispatch ported from `interpreter.cpp`.
  **1280/1280 vectors of Core's `script_tests.json` pass** (`cargo test --test script_vectors`).

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
  consensus/    chain params, PoW, subsidies
  validation/   UTXO set, tx/block checks, mempool, policy
  network/      P2P framing, handshake, address manager
  wallet/       addresses, coin selection
  node/         argument parsing, config resolution
  script/       script interpreter (full dispatch, all Core script vectors pass)
```
