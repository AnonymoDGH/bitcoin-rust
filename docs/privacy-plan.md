# AnonCoin (ANC) — Privacy Plan

AnonCoin is built to be **anonymous and untraceable by default**, not
pseudonymous. Bitcoin's design is pseudonymous: the ledger is public
forever, amounts are in cleartext, and addresses are linkable. This
document analyses how original Bitcoin fails at privacy, how large
money movers are deanonymised in practice (including by the FBI and
chain-analytics firms), and the phased plan to fix it in AnonCoin.

## 1. How original Bitcoin works — and where privacy breaks

### 1.1 The design
A public append-only ledger of UTXOs. Each output is
`hash(pubkey) -> amount`; inputs reveal the predecessor outputs and
signatures. Addresses are `hash160` of a public key; reusing them (or
not) is the user's problem. Amounts are plaintext. The P2P layer
broadcasts transactions in cleartext.

### 1.2 Failure modes that big money movers hit
- **Common-input-ownership**: spending two inputs together clusters
  them under one owner. Every consolidation groups more history.
- **Change detection**: the change output is often identifiable
  (rounding, position, script type), so the "peel chain" is followed.
- **Address reuse**: merges clusters and makes amount-flow trivial.
- **KYC ramps**: exchange deposits link cluster -> name -> bank -> IP
  -> email. Almost every major deanonymisation goes through a ramp.
- **Network layer**: the first announcement of a transaction leaks
  IP <-> address unless the client routes via Tor/I2P *and* the
  relay behaviour is correct.
- **Metadata outside the chain**: shipping addresses, photos, social
  posts, e-mail, timing. Silk Road, the Bitfinex-hack recovery
  (2022) and most mixer cases trace this way, not by breaking SHA-256.
- **Centralised mixers/coordinators**: Tornado Cash (sanctions),
  Samourai Wallet (2024 indictment of the CoinJoin coordinator),
  BTC-e, ChipMixer. The *operator*, not the maths, is the weak point.
- **Dusting and amount fingerprinting**: unique amounts (13.37 BTC)
  are globally correlatable; dust groups UTXOs when spent together.
- **Opt-in privacy**: Zcash shielded usage is a minority, so its
  anonymity set is small and entry/exit correlation is practical.

### 1.3 How the FBI / chain analytics actually work
1. Start from a known seed: an exchange account, a seized device, a
   counterparty, a public post.
2. Cluster addresses with the heuristics above.
3. Join with off-chain data: KYC records, exchange subpoenas,
   IP logs, device seizures, informants, undercover purchases.
4. Correlate in time and amount: unique values + timestamps are
   unique in the world.
5. Look for the custodian: every central service (mixer, exchange,
   coordinator) keeps logs or can be compelled.

Conclusion: anonymity is lost at the **edges** (ramps, network,
habits, custodians), not in the middle of the ledger. AnonCoin
protects the middle; the edges must be designed for too.

## 2. Design principles for AnonCoin

1. **Privacy by default, never opt-in.** A feature only used when
   "moving a lot of money" has a tiny anonymity set and betrays itself.
2. **No custodian, no coordinator.** Decentralised coordination only;
   a central operator is a subpoena target.
3. **Fixed anonymity parameters.** Ring size, mix size and broadcast
   jitter are constant, not user-tunable into identifiable shapes.
4. **No reusable addresses.** Stealth or disposable addresses only.
5. **No inflation, provably.** Every privacy feature ships with a
   zero-knowledge proof that inputs = outputs (no silent minting).
6. **Network privacy as a first-class citizen.** Tor/I2P and
   relay-decoy behaviour, not an afterthought plugin.
7. **Honest limits.** The README says what is and is not protected:
   KYC at ramps, compromised devices and a global passive network
   adversary are out of scope and still break anonymity.

## 3. Phased plan

### Phase 1 — unlinkable payments (this phase, in progress)
- **Stealth addresses** (BIP47-style, `crates/wallet/src/stealth.rs`):
  a reusable invitation address `(spending_pub, scan_pub)` that
  derives a fresh one-time address per sender via ECDH. Observers
  cannot link payments to the same recipient, the recipient can scan
  and recover the one-time secret.
- **Decentralised CoinJoin**: P2P coordination, fixed mix size,
  equal-value outputs, jittered broadcast. No coordinator server.
- **Network**: Tor/I2P for RPC and P2P, Dandelion++-style relay
  decoys, encrypted `peers.dat`.
- Amounts remain visible in this phase (documented limitation);
  the address graph is already broken.

### Phase 2 - hidden amounts and ambiguous sender (implemented, consensus-active)
- **Confidential Transactions**: Pedersen commitments `C(v,r) = v*G + r*H`
  (`H = SHA256("AnonCoin-H-v1")*G`) with 64-bit range proofs (binary
  Schnorr disjunctions) and Schnorr balance proofs proving
  `sum_in - sum_out - fee` consistent without revealing amounts.
  Activated in consensus behind the `ct_enabled` chain parameter
  (`-chainspec` field, on for AnonCoin): `ConnectBlock` and
  `AcceptToMemoryPool` verify CT transactions (range proofs, balance
  proof, per-input ring signatures), CT outputs are spendable UTXOs
  (value 0 in the ledger), and the CT output script
  `OP_RETURN 0x01 <commitment> <pubkey_hash> <range_proof>` is defined
  in `crates/chain/src/confidential.rs`.
  Bootstrap note: CT transactions must be all-CT (all inputs and
  outputs confidential) — mixing plaintext inputs/outputs is rejected
  by the value ledger (`InputsBelowOutputs`, 0 vs >0). Hybrid shield
  spends are the supported entry point: the wallet's `shieldtoct` RPC
  spends a mature P2PKH coin, carrying the input blinding + balance
  proof in a shield marker (`OP_RETURN 0x51 | r_in | balance`, 106-byte
  payload; the CT context zeroes its balance bytes, breaking the
  fixed-point), and runs script checks only for plaintext inputs.
  wallet `create_ct_spend`) are authorised by 16-key ring
  signatures over the on-chain keys. First CT liquidity therefore
  enters via the wallet shield itself.
- **Shielded pool active in consensus** (`crates/chain/src/notes.rs` +
  `Chainstate`): pool note outputs (`OP_RETURN 0x02 <cmu>`) are inserted
  into the commitment tree by `refresh_pool()` on every activation and
  startup; per-tip anchors and the nullifier double-spend registry are
  live. Note spends in `ConnectBlock` verify membership, spend
  authorisation and fee accounting through `verify_note_tx_block`
  (witness layouts: note, auth+anchor+index, path).
- **Anti-inflation without a SNARK (funding ledger).** Note values are
  revealed at spend, so the chain pins every spend to the value locked
  at issuance: `funding_caps_for_block` records, per `cmu`, the amount
  `inputs - non-pool outputs` locked by the creating tx (split evenly
  across co-created notes, replayed by `Chainstate::refresh_pool`).
  `verify_note_tx_block_with_caps` rejects any spend claiming more than
  its cap. Value-committed scripts (`OP_RETURN PUSHDATA1(65) cmu||C`,
  `C = value*G + rcm*H`) add a Pedersen opening check on top of the
  hash binding. Multi-note creations are conservative (even split).
- **Pool notes end to end.** Wallet `create_pool_note` /
  `create_note_spend` with persisted `NoteCoinInfo`; RPC
  `createpoolnote`/`spendnote`/`listnotes`/`exportviewkey` (view key =
  `SHA256(scan_secret || "anon-view")` for blind audit scans);
  `getpoolinfo` exposes anchor/height/note count. Mempool E2E tests
  cover append-accept and spend-accept+mine; the funding cap rejects
  inflated spends (unit tested).
- **Miner inclusion (fees fixed).** The block assembler includes
  mempool note spends and pays their real fee
  (`note.value - outputs`) to the coinbase; pool-creating txs carry
  no miner fee — the locked value transfers into the pool's ledger
  (funding cap), it is not coinbase revenue. Without that
  subtraction the note value would be minted twice (as fee and as
  later spend). Covered by `miner_includes_mempool_note_spend_and_pays_its_fee`.
- **Miner fee for CT (fixed).** The only sound miner fee for CT txs is
  the balance-proof public fee prefix (`ct_public_fee`): the proof
  ties `inputs - hidden_outputs - fee = 0`, while the plaintext ledger
  fee overstates by the hidden amounts (paying it would mint shielded
  values twice — the same double-mint class as pool creation).
  ConnectBlock, mempool entry fees and the block assembler all use
  the prefix fee. Covered end to end by
  `miner_includes_ct_spend_and_pays_public_fee` (shield at 102,
  all-CT ring spend at 103, coinbase = subsidy + prefix fee).
- **Remaining limits (honest):** spent note values are transparent
  at spend (a SNARK/Orchard-style upgrade would hide them); onion
  inbound P2P is not supported (outbound SOCKS5 only).

### Phase 3 — shielded pool
**Implemented now (pre-zk milestone):** `crates/chain/src/notes.rs` —
notes with `cmu = SHA256("AnonCoin-NOTE-v1" || pub || value || rcm)`,
32-level Merkle anchors, hashed nullifiers (`nf = SHA256("AnonCoin-NF-v1"
|| rcm)`), and Schnorr spend authorisation bound to the note's own
spending key. `Chainstate` keeps the active pool state: `refresh_pool`
replays the active chain to rebuild the commitment tree and per-tip
anchors on every activation and at startup, and `pool_spent`/
`register_nullifier` form the double-spend registry. `btc-wallet`
creates, recovers (by spending secret) and authorises note spends.
Pool output scripts come in two forms: legacy
`OP_RETURN PUSHDATA1(32) cmu` and value-committed
`OP_RETURN PUSHDATA1(65) cmu||C` (`C = value*G + rcm*H`, published by
the wallet at creation). Inflation is bounded by the funding ledger
(see §3), not by the hash: issuance locks real UTXO value behind
each `cmu` and spends may claim at most that cap.
**TODO before lane-ready:** hide spent values with an Orchard-style
SNARK over the same note definition, CT miner inclusion, onion
inbound P2P.

## 4. Threat model (explicit)

| Adversary | Phase 1 | Phase 2 | Phase 3 |
|---|---|---|---|
| Casual ledger observer | protected (unlinkable addresses) | protected | protected |
| Chain analytics (clustering) | largely protected | protected | protected |
| Passive network observer | Tor/I2P required | Tor/I2P required | Tor/I2P required |
| Exchange with KYC | **not protected** (ramp links name) | not protected | not protected |
| Compromised device / CCTV | not protected | not protected | not protected |
| Global passive adversary | reduced, not eliminated | reduced | reduced |

## 5. Implementation map

| Area | Crate | Work |
|---|---|---|
| Stealth addresses + scan | `btc-wallet` (`stealth.rs`) | done in Phase 1 first step |
| CoinJoin coordination | `btc-wallet` / `btc-network` | P2P rounds, fixed sizes |
| Relay privacy | `btc-network` / `btc-node` | Tor, Dandelion++, cover traffic |
| Confidential amounts + rings | `btc-consensus` / `btc-chain` | new validity rules + proofs |
| Shielded notes + zk | `btc-chain` / `btc-wallet` | notes, nullifiers, view keys |
| RPC | `btc-rpc` / `btc-node` | `getnewstealthaddress`, `shielded_transfer` |

## 6. Legal note

Privacy is a legitimate property (fungibility, personal safety,
financial freedom). Operating a **centralised** mixer or coordinator
carries real regulatory risk in the US/EU; this design is therefore
protocol-only and non-custodial, and the limits above are documented
in the README rather than hidden.
