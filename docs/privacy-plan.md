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
- **Decentralised CoinJoin** (`crates/wallet/src/coinjoin.rs`):
  library-level round logic only (equal-value outputs, commitments,
  sorted outputs, per-signer verification of the assembled transaction).
  There is **no P2P transport** for rounds yet, mix size is bounded
  (2..=16) but not fixed, there is no coordinator server and no
  broadcast jitter specific to CoinJoin. Inputs are averaged into one
  denomination, so each signer states the loss it accepts
  (`max_loss`); change outputs are not produced.
- **Network (honest status)**: implemented: outbound SOCKS5 proxy
  (`-proxy`, e.g. Tor's SOCKS port; no inbound listener and no
  cleartext DNS seeding while it is set) and a uniform random relay
  delay of up to 2 s per peer (OS RNG), enabled only when `-proxy` is
  set. **Not implemented**: I2P, onion (inbound / `.onion`) peers,
  Tor for RPC, Dandelion++ stem/fluff relay or relay decoys, cover
  traffic, encrypted `peers.dat`. Without `-proxy` the node relays
  transactions to all peers immediately and exposes the node's IP.
- Amounts remain visible in this phase (documented limitation);
  the address graph is already broken.

### Phase 2 - hidden amounts (implemented, consensus-active; sender ambiguity NOT provided)
- **Confidential Transactions**: Pedersen commitments `C(v,r) = v*G + r*H`
  (`H` = NUMS point, try-and-increment hash-to-curve of `"AnonCoin-H-v2"`; no known dlog) with 64-bit range proofs (binary
  Schnorr disjunctions) and Schnorr balance proofs proving
  `sum_in - sum_out - fee` consistent without revealing amounts.
  Activated in consensus behind the `ct_enabled` chain parameter
  (`-chainspec` field, on for AnonCoin): `ConnectBlock` and
  `AcceptToMemoryPool` verify CT transactions (range proofs, balance
  proof, per-input owner signatures), CT outputs are spendable UTXOs
  (value 0 in the ledger), and the CT output script
  `OP_RETURN 0x01 <commitment:33> <pubkey_hash:20> <E:33> <v_enc:8>
  PUSHDATA2(<range_proof:8256>)` (fixed 8355 bytes, <= MAX_SCRIPT_SIZE)
  is defined in `crates/chain/src/confidential.rs`.
- **CT recipient recovery (fixed: received CT coins were unspendable).**
  The blinding used to be chosen by the sender and never communicated,
  so only the sender could build the balance proof. Now every CT output
  is addressed to a stealth address: the sender draws a fresh ephemeral
  `e`, publishes `E = e*G` in the output, and derives
  `s = SHA256(ECDH(e, scan_pub))`. The one-time owner key is the stealth
  key for output index `idx` (hash160 in `pubkey_hash`), the blinding is
  `r = H("AnonCoin/ct-blind/v1" || s || idx)` (re-hashed until a valid
  scalar) and the amount is `v_enc = v XOR
  H("AnonCoin/ct-value/v1" || s || idx)[..8]`. The recipient's wallet
  (block scan, mempool) recognises the output via its scan key, recomputes
  `(v, r)` and adopts it ONLY if `C == v*G + r*H`; the ciphertext is never
  trusted on its own (tampered `v_enc`, wrong recipient, wrong index are
  all rejected). Consensus only requires `E` to be a curve point. Senders
  learn the recipient's scan key from the stealth address
  (`getnewstealthaddress`); `sendct <stealth_address> <amount> [fee]`
  pays it from CT coins, change goes to the sender's own stealth address,
  `shieldtoct` shields into the wallet's own stealth address and
  `getctbalance` shows recovered CT coins. Limitation: an encrypted
  wallet that is locked cannot derive its scan key, so CT payments that
  arrive while it is locked are not recognised until the blocks are
  rescanned.
- **Cheap parsing, single range verification (fixed DoS).**
  `decode_ct_script` / `is_ct_script` only check structure (exact length,
  tag, point prefixes, PUSHDATA2 header); they never verify proofs and are
  called freely. Range proofs are verified exactly once per input and
  output inside `verify_ct_transaction` (via `verify_ct_tx_block`), which
  both ConnectBlock and `accept_to_mempool` call for every tx that has a
  CT-shaped input or output. CT inputs are re-verified at spend because a
  coinbase may carry unverified CT-shaped outputs. A well-formed script
  with a corrupted proof is rejected by both paths (tests).
  Bootstrap note: CT transactions must be all-CT (all inputs and
  outputs confidential) — mixing plaintext inputs/outputs is rejected
  by the value ledger (`InputsBelowOutputs`, 0 vs >0). Hybrid shield
  spends are the supported entry point: the wallet's `shieldtoct` RPC
  spends a mature P2PKH coin, carrying the input blinding + balance
  proof in a shield marker (`OP_RETURN 0x51 | r_in | balance`, 106-byte
  payload; the CT context zeroes its balance bytes, breaking the
  fixed-point), and runs script checks only for plaintext inputs.
  wallet `create_ct_spend`) are authorised by an **owner signature**
  (see below). First CT liquidity therefore enters via the wallet
  shield itself.
- **CT input authorisation (fixed, was a critical bug).** A CT input
  names its prevout explicitly, and that prevout's script embeds the
  owner's `pubkey_hash`. The first implementation additionally asked
  for a 16-key ring signature over keys listed in the witness, accepting
  it when exactly one ring key hashed to the `pubkey_hash`. That was
  unsound: a ring signature proves knowledge of the secret of *some*
  ring member, not of the owner, so an attacker could list the
  victim's (public) key plus his own among 16 keys, sign with his own
  key, and spend any CT output (given the output's blinding for the
  balance proof, which e.g. the original sender knows). Consensus now requires a BIP340 Schnorr
  signature by the key whose `hash160` equals the spent output's
  `pubkey_hash`, over `ct_input_sighash = SHA256(tag || ct_context ||
  input_index || len || spent_script)`. `ct_context` commits to the
  version, locktime, every input outpoint and sequence and every output
  (scriptSigs and witnesses stripped, shield-marker balance bytes
  zeroed because the balance proof, itself bound to `ct_context`,
  carries them); the sighash additionally binds the input slot and the
  exact spent output, so signatures cannot be replayed onto another
  transaction, input or output. Witness layout: input 0 is
  `[balance_proof, sig(64), pubkey(33)]`, every other CT input is
  `[sig(64), pubkey(33)]`; item counts and sizes are exact. Ring
  signatures (`ringsig.rs`) are retained as library code only and are
  not accepted by consensus. Tests: theft variants rejected, owner spend
  accepted, wrong pubkey / wrong signature / replay to another tx / wrong
  input slot rejected, at the `verify_ct_tx_block`, `ConnectBlock` and
  mempool level.
- **Sender ambiguity is NOT provided.** Because inputs name their
  prevout explicitly, observers see exactly which output is spent;
  hidden amounts are the only privacy gained by CT today. The ring
  that used to be in the witness hid nothing (the prevout was already
  public) and has been removed. Receiver unlinkability still comes from
  stealth/one-time addresses, not from CT inputs.
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
  65 bytes `scan_secret || spending_pubkey`: it recognises every stealth
  payment to the wallet but holds no spending secret; share it only
  with a trusted auditor, since it reveals the wallet's incoming
  payments);
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
  all-CT owner-signed spend at 103, coinbase = subsidy + prefix fee).
- **SNARK layer (prototype, `crates/chain/src/value_snark.rs`).**
  Groth16/BN254 value-hiding circuit over the pool note definition:
  proves `C_old` opens, `v_old = v_new0 + v_new1 + fee`, values in
  range and `v_old <= funding cap` without revealing values (public
  inputs: fee, cap, commitments). Tests prove+verify a valid spend
  and reject tampered fee / inflation / over-cap / bad opening
  witnesses. Wired into consensus verification: an optional Groth16
  proof in `witness[3]` of a note spend is verified by
  `verify_note_tx_block_with_caps` (ConnectBlock + mempool) with the
  transcript reconstructed from the note opening, the tx outputs
  and the funding cap; present-but-invalid proofs are rejected.
  **Joint binding:** the SNARK commitment is `C = v + h(rcm)` with
  the non-linear field hash `h(x) = x^3 + x` (multiplication
  constraints in-circuit), and the verifier derives `C_old` from the
  spent note's own `(value, rcm)` opening — the same pair the
  `cmu` hash pins and, on committed scripts, the Pedersen
  commitment opens. A forged `(v', rcm')` pair cannot satisfy the
  `cmu`, the Pedersen opening, the funding cap and `C_old`
  simultaneously; the test
  `commitment_is_nonlinear_and_binding` locks the non-linearity.
  Moreover `C_old` now binds the on-chain `cmu` itself as a public
  input (`C = v + h(rcm) + cmu_field`): a proof issued for a
  different note cannot verify against this transcript. **Poseidon
  preimage binding is wired too**: the circuit absorbs the note's
  `(pub, value, rcm)` preimage in a Poseidon-like sponge (8 lanes,
  4 full S-box rounds, domain constants) and checks the digest
  against the `poseidon` public input. Pool scripts v3
  (`OP_RETURN PUSHDATA1(97) cmu || poseidon || Pedersen C`) carry
  that digest on-chain; on legacy scripts the verifier recomputes
  it from the revealed opening. The permutation is a simplified
  Poseidon-like construction (not the production Poseidon
  parameters); the SHA-256 `cmu` tree leaf is unchanged.
  Wallet generation is wired too: `create_note_spend` takes the
  on-chain funding cap, proves the spend and attaches `witness[3]`
  (RPC `spendnote` supplies the cap from the ledger). **Shielded
  outputs are wired**: `create_note_spend_shielded` (RPC
  `shieldspendnote`) spends a note into a single new pool note —
  public fee + new commitments travel in `witness[4]`, the miner
  fee is the public one, and the funding ledger records the new
  note with `spent value - fee` (hidden values flow through the
  proof, not the ledger). Prototype limits: the Poseidon-like
  permutation is simplified (production parameters + `C_new`
  binding remain); multiple new notes per spend are not yet
  supported (conservative single-note rule).
- **SNARK trusted setup, keys and hash (security fix).** The original
  prototype derived its Groth16 parameters from the public RNG seed
  `0xA0C0` and proved with the fixed seed `0xC0FFEE`: the toxic waste
  was public (any proof forgeable) and proofs were not zero-knowledge.
  Both are gone. Consensus never creates or trusts a key: it verifies
  only against `ChainParams::snark_vk` (chain spec `"snark_vk": "<hex>"`,
  compressed `ark-serialize` verifying key; sha256 is logged at startup
  and when the spec loads). **With no key configured every SNARK proof is
  rejected** — a spend that carries `witness[3]` is invalid in
  ConnectBlock (`verify_note_tx_block_with_snark`) and non-standard in
  the mempool (`snark-proof-no-vk`); in particular the shielded mode,
  whose fee and new commitments come from the proof, cannot be used.
  Plain note spends (no proof) are unaffected and stay bounded by the
  funding ledger. Provers draw fresh OS randomness for every proof.
  The value-circuit hash is now real Poseidon over BN254 `Fr`
  (`ark-crypto-primitives` sponge + R1CS gadget): width 3, S-box `x^5`
  (a permutation since `gcd(5, p-1) = 1`), 8 full + 57 partial rounds
  (the paper's 128-bit instance for `t = 3`), constants and Cauchy MDS
  from the reference Grain-LFSR (`find_poseidon_ark_and_mds`), fixed
  input lengths and leading domain tags (note digest 1, old commitment 2,
  new commitment 3). Commitments are now Poseidon commitments
  (`Poseidon(tag, value, rcm[, cmu])`) instead of the algebraic
  `v + h(rcm)` stand-in, which was not binding. The circuit also ties
  `v_old` and `rcm_old` to the Poseidon preimage inputs and range-checks
  the public fee. A known-answer test pins the parameters (changing them
  forks consensus).
  *Setup tooling:* `btc-node -snarksetup=<dir>` runs a **single-party**
  OS-RNG setup and writes `snark_pk.bin` / `snark_vk.bin` / `snark_vk.hex`
  (loud warning: that machine saw the toxic waste; development networks
  only). A node that finds `<datadir>/snark_pk.bin` matching the pinned
  verifying key uses it for wallet proofs (`spendnote` attaches a proof,
  `shieldspendnote` requires it).
  *Ceremony required before mainnet:* run a multi-party Groth16 phase-2
  ceremony for this exact circuit (e.g. a Powers-of-Tau phase-1 transcript
  such as the Perpetual / Hermez BN254 ptau, then a circuit-specific
  phase 2 with many independent contributors, each destroying their
  randomness, a public random beacon, and published transcript + hash
  verifiable by anyone); pin the final verifying key hash in the chain
  spec and in the release notes. Any change to the circuit (including the
  Poseidon parameters) invalidates the keys and needs a new ceremony.
- **Remaining limits (honest):** spent note values are transparent
  at spend under the active (hash-note) scheme; onion inbound P2P
  is not supported (outbound SOCKS5 only).

#### Future work: real sender ambiguity (Monero-style)
Needed to actually hide the sender, none of it implemented yet:
1. Inputs must not name one prevout but reference a **ring of outputs**
   (fixed size, e.g. 16, chosen from the UTXO set with a sound decoy
   distribution), each with its one-time public key and amount
   commitment.
2. A linkable ring signature (LSAG, or CLSAG which also proves the
   pseudo-output commitment differs from the real input commitment by a
   commitment to zero) with a **key image** `I = x * Hp(P)`; the
   amount side uses pseudo-output commitments so the balance proof does
   not reveal which ring member is spent.
3. A **key-image registry** in the chainstate (insert on connect, remove
   on disconnect, checked in the mempool and across a block) to detect
   double spends; this replaces the "prevout is spent" rule for these
   inputs.
4. Strictly consensus-checked ring composition (distinct members, valid
   outputs, coinbase maturity) and wallet-side decoy selection, plus
   one-time-key outputs so the key image cannot be linked to a public
   address. `ringsig.rs` is the starting point for the non-linkable
   core only; it lacks key images and the commitment layer.

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
| Passive network observer | Tor required (`-proxy`); I2P unsupported | Tor required | Tor required |
| Exchange with KYC | **not protected** (ramp links name) | not protected | not protected |
| Compromised device / CCTV | not protected | not protected | not protected |
| Global passive adversary | reduced, not eliminated | reduced | reduced |

## 5. Implementation map

| Area | Crate | Work |
|---|---|---|
| Stealth addresses + scan | `btc-wallet` (`stealth.rs`) | done in Phase 1 first step |
| CoinJoin coordination | `btc-wallet` / `btc-network` | P2P rounds, fixed sizes |
| Relay privacy | `btc-network` / `btc-node` | Tor, Dandelion++, cover traffic |
| Confidential amounts (rings: future work) | `btc-consensus` / `btc-chain` | new validity rules + proofs |
| Shielded notes + zk | `btc-chain` / `btc-wallet` | notes, nullifiers, view keys |
| RPC | `btc-rpc` / `btc-node` | `getnewstealthaddress`, `shielded_transfer` |

## 6. Legal note

Privacy is a legitimate property (fungibility, personal safety,
financial freedom). Operating a **centralised** mixer or coordinator
carries real regulatory risk in the US/EU; this design is therefore
protocol-only and non-custodial, and the limits above are documented
in the README rather than hidden.
