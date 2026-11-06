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
| `btc-script` | **Script interpreter**: errors, flags, opcodes, script numbers, execution context |

## Status

- ✅ Phase 1 — `btc-primitives`, `btc-consensus`: fully ported, 15 unit tests pass.
- ✅ Phase 2 — `btc-validation`, `btc-network`, `btc-wallet`, `btc-node`: ported, all compile, 40+ tests pass.
- 🚧 Phase 3 — `btc-script`: shared contracts + opcode/limits/ScriptNum/sighash parsing are real code
  (BIP143 / BIP341 hashes), DER/pubkey-encoding stubs and the full `EvalScript` dispatch are ported inline
  and verified via `cargo check -p btc-script` + `cargo test -p btc-script --lib sighash`.

Reference clone: `bitcoin-core-reference/` (excluded; use `git clone --depth 1 https://github.com/bitcoin/bitcoin.git`).

## Build

```bash
cargo check --workspace
cargo test  --workspace
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
  script/       script interpreter (in progress)
```
