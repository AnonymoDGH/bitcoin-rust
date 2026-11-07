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

### Phase 2 - hidden amounts and ambiguous sender (implemented, primitives-level)
- **Confidential Transactions**: Pedersen commitments `C(v,r) = v*G + r*H`
  (`H = SHA256("AnonCoin-H-v1")*G`) with 64-bit range proofs (binary
  Schnorr OR-proofs) and Schnorr balance proofs proving
  `sum_in - sum_out - fee = 0` without revealing amounts. Implemented
  and tested in `crates/chain/src/confidential.rs`; wallet helpers in
  `crates/wallet/src/privpay.rs`. Consensus activation (new output
  type in `ConnectBlock`) is the next step.
- **Ring signatures** (Monero-style, fixed ring size 16): 1-out-of-16
  Schnorr ring (`crates/chain/src/ringsig.rs`), tested. Spending
  authorisation through rings is the next step.
- **Fungibility**: identical-looking outputs; no tainted-coin
  signalling at the protocol level.

### Phase 3 — shielded pool
- zk-SNARK notes (Orchard/Halo2-style, no trusted setup): sender,
  receiver and amount hidden with a balance proof.
- **View keys** for selective audit: prove a payment to a third
  party without opening the rest.
- Mobile-friendly proving (recursive/aggregated proofs later).

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
