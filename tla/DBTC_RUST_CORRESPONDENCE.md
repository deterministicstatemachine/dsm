# dBTC Rust ↔ Formal Trust Correspondence

This note is the theorem boundary between the formal dBTC trust artifacts and
the current Rust verifier path.

It does **not** claim a proof of Bitcoin PoW / Nakamoto consensus from first
principles. It claims only that the Rust verifier is structured so that, on
mainnet, a successful dBTC settlement acceptance implies the formal predicate
named in the proof artifacts.

## Formal names

The proof artifacts use these names:

- `tla/DSM_dBTC_TrustReduction.tla`
  - `MainnetFinalityAssumption`
  - `FinalBurnActionRequiresMainnet`
- `lean4/DSM_dBTC_TrustReduction.lean`
  - `RustVerifierAccepted`
  - `MainnetFinalityAssumption`

In Rust, the matching code-side names are now in:

- `dsm/src/bitcoin/trust.rs`
  - `BitcoinSettlementObservation`
  - `RustVerifierAcceptedEvidence`
  - `RustVerifierAcceptedEvidence::rust_verifier_accepted()`

## Predicate mapping

### 1. `bitcoinSpend`

Meaning:

- the settlement transaction is observed as confirmed on Bitcoin.

Rust path:

- `dsm_sdk/src/handlers/bitcoin_invoke_routes.rs`
  - `bitcoin.deposit.await_and_complete`
  - `bitcoin.exit.complete`
  - `resolve_pending_withdrawals_with_client`

These routes build a `BitcoinSettlementObservation` from `mempool.tx_status()`
and the derived confirmation depth.

### 2. `confDepth ≥ dmin`

Meaning:

- the observed confirmation depth meets the policy threshold.

Rust path:

- `BitcoinSettlementObservation::meets_confirmation_gate()`
- enforced in:
  - `bitcoin.deposit.await_and_complete`
  - `bitcoin.exit.complete`
  - `resolve_pending_withdrawals_with_client`
  - `LimboVault::verify_bitcoin_htlc`

### 3. `spvValid`

Meaning:

- the txid is proven in the block’s Merkle root.

Rust path:

- `dsm/src/bitcoin/spv.rs`
  - `verify_spv_proof()`
- consumed explicitly in:
  - `dsm/src/vault/limbo_vault.rs::verify_bitcoin_htlc()`

### 4. `powValid`

Meaning:

- the block header satisfies Bitcoin proof-of-work.

Rust path:

- `dsm/src/bitcoin/spv.rs`
  - `verify_block_header_work()`
- consumed explicitly in:
  - `dsm/src/vault/limbo_vault.rs::verify_bitcoin_htlc()`

### 5. `checkpointed`

Meaning:

- the exit/deposit block is rooted to a known checkpoint chain.

Rust path:

- `dsm/src/bitcoin/header_chain.rs`
  - `verify_header_chain()`
- mapped into formal evidence in:
  - `dsm/src/vault/limbo_vault.rs::verify_bitcoin_htlc()`

Important boundary:

- on **mainnet**, `checkpointed = true` only if checkpoint-rooted validation ran;
- on **signet/testnet**, runtime may still accept, but the formal mainnet
  predicate is **not** established because checkpoint enforcement is bypassed.

### 6. `sameChain`

Meaning:

- the exit anchor chains from the cached entry anchor.

Rust path:

- `dsm/src/bitcoin/header_chain.rs`
  - `verify_entry_anchor()`
- mapped into formal evidence in:
  - `dsm/src/vault/limbo_vault.rs::verify_bitcoin_htlc()`

Boundary rule:

- if no prior entry anchor exists, `sameChain` is vacuously true;
- on signet/testnet, bypassed entry-anchor checks mean runtime acceptance is
  weaker than the formal mainnet predicate.

## Code-level theorem boundary

For a `RustVerifierAcceptedEvidence` value `e`:

- `e.runtime_accepts()` = current runtime policy
- `e.rust_verifier_accepted()` = formal mainnet predicate

The intended code-level theorem is:

> If `e.observation.network == Mainnet` and `e.runtime_accepts()` is true,
> then `e.rust_verifier_accepted()` is true.

This is encoded by:

- `RustVerifierAcceptedEvidence::runtime_acceptance_implies_formal_mainnet()`

and guarded in the main verifier by:

- `dsm/src/vault/limbo_vault.rs::verify_bitcoin_htlc()`

## What is still weaker on signet/testnet

The current repo intentionally keeps a development shortcut:

- `verify_header_chain()` bypasses checkpoint enforcement on signet/testnet
- `verify_entry_anchor()` bypasses same-chain enforcement on signet/testnet
- dBTC params use reduced confirmation depth there

Therefore the honest claim is:

- **mainnet:** Rust acceptance is structured to imply the formal trust predicate;
- **signet/testnet:** runtime behavior is weaker and should be treated as dev/test only.