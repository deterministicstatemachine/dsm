# DeTFi Cookbook

**Deterministic Finance on DSM — Working Examples & Developer Guide**

DeTFi is the financial application layer built directly on DSM protocol primitives.
It is not a separate crate or blockchain — it composes existing DSM capabilities
(Deterministic Limbo Vaults, external commitments, fulfillment conditions, token
conservation) into sovereign financial instruments: escrows, Bitcoin-backed vaults,
conditional multi-party releases, and more.

This directory contains working example specifications you can validate, generate
typed client code from, and use as templates for your own DeTFi applications.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [DSM Invariants](#dsm-invariants)
3. [Examples Index](#examples-index)
4. [Walkthrough: Your First Vault](#walkthrough-your-first-vault)
5. [Walkthrough: Generate Client Code](#walkthrough-generate-client-code)
6. [Walkthrough: Bitcoin-Backed Vault](#walkthrough-bitcoin-backed-vault)
7. [Walkthrough: Composed Conditions](#walkthrough-composed-conditions)
8. [Walkthrough: Transfer Policies](#walkthrough-transfer-policies)
9. [Walkthrough: Compile to Base32 Blob](#walkthrough-compile-to-base32-blob)
10. [Pattern Reference](#pattern-reference)
11. [Building Your Own](#building-your-own)
12. [Fulfillment Condition Reference](#fulfillment-condition-reference)
13. [FAQ](#faq)

---

## Quick Start

```bash
# 1. Validate a vault spec
cargo run -p dsm-gen -- validate examples/detfi/vaults/01-simple-escrow.yaml

# 2. Generate TypeScript + Kotlin client code
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang ts,kotlin

# 3. Run all DeTFi example tests
cargo test -p dsm-gen --test detfi_examples
```

---

## DSM Invariants

Every DeTFi spec must respect these hard protocol rules:

| # | Invariant | What It Means |
|---|-----------|---------------|
| 1 | **Protobuf-only at runtime** | YAML is dev-time only. `dsm-gen` compiles it into typed builders that emit protobuf. No YAML or JSON ever reaches the core state machine. |
| 2 | **No `serde_json::Value`** | All parameters use strongly-typed structs or `HashMap<String, String>`. No arbitrary JSON blobs. |
| 3 | **Base32 Crockford for bytes** | Binary fields (keys, hashes, pubkeys) are `String` in YAML specs, encoded as Base32 Crockford. |
| 4 | **No wall-clock time** | DSM is clockless. Timeouts use `duration_iterations` (hash-chain tick counts), never seconds or timestamps. |

---

## Examples Index

### Vaults

| File | Pattern | Fulfillment Type | Difficulty |
|------|---------|-----------------|------------|
| `vaults/01-simple-escrow.yaml` | Payment escrow | `payment` | Beginner |
| `vaults/02-bitcoin-backed-vault.yaml` | dBTC tap deposit | `bitcoin_htlc` | Intermediate |
| `vaults/03-conditional-multisig.yaml` | Loan disbursement | `and(multi_signature, crypto_condition)` | Advanced |
| `vaults/04-oracle-attested-release.yaml` | Insurance payout | `or(crypto_condition, state_reference)` | Advanced |

### Policies

| File | Pattern | Rule Types | Difficulty |
|------|---------|-----------|------------|
| `policies/01-stablecoin-transfer.yaml` | Compliance guardrails | blacklist, signature, amount_limit, iteration_window | Beginner |
| `policies/02-tiered-approval.yaml` | Corporate treasury | custom, whitelist, signature, amount_limit | Intermediate |

---

## Walkthrough: Your First Vault

This walkthrough creates a simple payment escrow. Alice locks 500 DSM tokens;
Bob claims them by proving payment.

### Step 1: Understand the Spec Structure

Every vault YAML has this structure:

```yaml
type: "vault"              # Must be "vault" (or "policy" for policies)
name: "MyVaultName"        # Used to generate class names (e.g., MyVaultNameVaultClient)
version: "1.0.0"           # Semantic version
description: "..."         # Human-readable description

fulfillment_condition:     # What must happen to unlock the vault
  type: "payment"          # One of: payment, bitcoin_htlc, multi_signature,
                           #   crypto_condition, state_reference,
                           #   random_walk_verification, and, or
  # ... condition-specific fields

assets:                    # What the vault holds
  - asset_id: "DSM"
    amount: 500

tick_lock:                 # Optional: clockless expiry
  duration_iterations: 14400
  tick_lock_action:
    type: "return_to_owner"

recovery:                  # Optional: recovery mechanism
  mechanism:
    type: "social_recovery"
    # ...

metadata:                  # Optional: arbitrary string key-value pairs
  key: "value"
```

### Step 2: Read the Simple Escrow Example

Open `vaults/01-simple-escrow.yaml`. Key points:

- **Fulfillment**: `type: "payment"` — Bob proves a 500 DSM payment to Alice's device
- **Tick Lock**: After 14400 chain iterations with no unlock, tokens auto-return to Alice
- **Recovery**: 2-of-3 social recovery via trusted devices

### Step 3: Validate It

```bash
cargo run -p dsm-gen -- validate examples/detfi/vaults/01-simple-escrow.yaml
```

Expected output:
```
Validating specification: "examples/detfi/vaults/01-simple-escrow.yaml"
  Type: Vault
  Name: SimpleEscrow
  Version: 1.0.0
✓ Specification is valid
```

If you get an error, the YAML doesn't match the schema. Check field names and
indentation against the structure above.

### Step 4: Generate Client Code

```bash
# Generate TypeScript client
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang ts

# Generate for all languages at once
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang ts,kotlin,swift,rust
```

This produces a file like `01-simple-escrow_client.ts` containing:

- `SimpleEscrowVaultClient` class with `create()`, `unlock()`, `status()` methods
- Type-safe `FulfillmentCondition` discriminated union
- `VaultLifecycle` enum (LIMBO, ACTIVE, UNLOCKED, CLAIMED, INVALIDATED)

### Step 5: Use the Generated Code

The generated client connects to your DSM SDK:

```typescript
import { DsmSdk } from '@dsm/sdk';
import { SimpleEscrowVaultClient } from './01-simple-escrow_client';

// Initialize SDK (already set up in your app)
const sdk = new DsmSdk(/* config */);

// Create the vault
const vault = await SimpleEscrowVaultClient.create(sdk, {
  assets: [{ assetId: 'DSM', amount: BigInt(500) }],
  fulfillmentCondition: {
    type: 'payment',
    amount: BigInt(500),
    tokenId: 'DSM',
    recipient: aliceDeviceId,
    verificationState: genesisHash,
  },
  tickLock: { durationIterations: BigInt(14400) },
});

// Check status
const status = await vault.status();
console.log(status.lifecycle); // 'limbo'

// Bob unlocks with payment proof
const unlocked = await vault.unlock(paymentProofBytes);
```

---

## Walkthrough: Generate Client Code

`dsm-gen` supports four target languages. Here is how each one works.

### TypeScript

```bash
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang ts
```

Generates: `SimpleEscrowVaultClient` class, async/await, `@dsm/sdk` imports, `bigint` for amounts.

### Kotlin (Android)

```bash
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang kotlin
```

Generates: `sealed class FulfillmentCondition`, `SimpleEscrowVaultClient`, `Result<T>` error handling, `BigInteger` for amounts.

### Swift (iOS)

```bash
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang swift
```

Generates: `indirect enum FulfillmentCondition`, `SimpleEscrowVaultClient`, `throws`-based errors, `UInt64` for amounts.

### Rust

```bash
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang rust
```

Generates: `enum FulfillmentCondition` with serde derives, `SimpleEscrowVaultClient<S: DsmSdk>` generic over SDK trait.

### Factory Mode

Add `--factory` to generate a multi-instance vault manager:

```bash
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang ts --factory
```

This adds a `SimpleEscrowVaultFactory` class that can create and track multiple vault instances.

### Test Vectors

Add `--test-vectors` to embed golden test data for CI:

```bash
cargo run -p dsm-gen -- client examples/detfi/vaults/01-simple-escrow.yaml --lang rust --test-vectors
```

---

## Walkthrough: Bitcoin-Backed Vault

This walkthrough creates a dBTC tap vault — the Bitcoin HTLC pattern from
dBTC spec sections 6.2-6.4.

### Step 1: Understand the Bitcoin HTLC Fulfillment

The `bitcoin_htlc` fulfillment condition locks a vault until a Bitcoin HTLC
is fulfilled on-chain. It requires:

| Field | Type | Description |
|-------|------|-------------|
| `hash_lock` | Base32 string | SHA256(secret_key) — the preimage hash |
| `refund_hash_lock` | Base32 string | SHA256(refund_key) — the refund preimage hash |
| `refund_iterations` | u64 | Chain iterations before refund activates |
| `bitcoin_pubkey` | Base32 string | Counterparty's 33-byte compressed BTC pubkey |
| `expected_btc_amount_sats` | u64 | Expected deposit in satoshis |
| `network` | string | `mainnet`, `testnet`, or `signet` |
| `min_confirmations` | u64 | Required confirmation depth (canonical: 100) |

### Step 2: Look at the Example

Open `vaults/02-bitcoin-backed-vault.yaml`. This vault:

1. Waits for a Bitcoin HTLC deposit of 100,000 sats on testnet
2. Requires 100 confirmations (SPV proof + header chain)
3. If the preimage is revealed, the vault unlocks and dBTC is minted 1:1
4. If no deposit after 1,000 iterations, refund path activates
5. Overall expiry at 50,000 iterations returns to owner

### Step 3: Validate and Generate

```bash
# Validate
cargo run -p dsm-gen -- validate examples/detfi/vaults/02-bitcoin-backed-vault.yaml

# Generate Rust client
cargo run -p dsm-gen -- client examples/detfi/vaults/02-bitcoin-backed-vault.yaml --lang rust
```

### Step 4: Flow in Practice

The generated `BitcoinBackedVaultClient` integrates with `BitcoinTapSdk`:

1. **Open Tap**: Create the DLV with BitcoinHTLC condition
2. **Fund**: User sends BTC to the generated P2WSH HTLC address
3. **Wait for confirmations**: 100 blocks on testnet
4. **Draw Tap**: SDK verifies SPV proof + preimage, unlocks vault, mints dBTC
5. **Or Refund**: After `refund_iterations`, the refund hash-lock activates

---

## Walkthrough: Composed Conditions

DSM supports AND/OR composition of fulfillment conditions. This is how you
build multi-party, multi-condition financial instruments.

### AND Composition (All Conditions Required)

Open `vaults/03-conditional-multisig.yaml`. This vault requires BOTH:

1. A 2-of-3 multi-signature (borrower + lender + arbiter)
2. A crypto-condition proof (collateral posting hash)

```yaml
fulfillment_condition:
  type: "and"
  conditions:
    - type: "multi_signature"
      public_keys:
        - "BORROWERSPHINCSKEY..."
        - "LENDERSPHINCSKEY..."
        - "ARBITERSPHINCSKEY..."
      threshold: 2

    - type: "crypto_condition"
      condition_hash: "COLLATERALPROOFHASH..."
      public_params: "COLLATERALPARAMS..."
```

The generated client requires both proofs to unlock:
```typescript
const unlocked = await vault.unlock(combinedProofBytes);
// combinedProofBytes must satisfy BOTH the multi-sig AND the crypto-condition
```

### OR Composition (Any Condition Sufficient)

Open `vaults/04-oracle-attested-release.yaml`. This vault unlocks if EITHER:

1. An oracle provides a signed attestation (crypto-condition preimage)
2. A specific DSM state is reached (state-reference)

```yaml
fulfillment_condition:
  type: "or"
  conditions:
    - type: "crypto_condition"
      condition_hash: "ORACLEATTESTATIONHASH..."
      public_params: "ORACLEVERIFIERPARAMS..."

    - type: "state_reference"
      reference_states:
        - "TARGETSTATEHASH1..."
        - "TARGETSTATEHASH2..."
      parameters: "STATEVERIFYPARAMS..."
```

### Nesting

AND and OR can be nested arbitrarily:
```yaml
fulfillment_condition:
  type: "and"
  conditions:
    - type: "or"
      conditions:
        - type: "payment"
          # ...
        - type: "crypto_condition"
          # ...
    - type: "multi_signature"
      # ...
```

---

## Walkthrough: Transfer Policies

Policies define rules for token transfers (CPTA — Content-Addressed Token Policy).

### Step 1: Understand Policy Structure

```yaml
type: "policy"
name: "MyPolicyName"
version: "1.0.0"

rules:
  - name: "rule_name"
    condition:
      condition_type: "amount_limit"    # One of: amount_limit, iteration_window,
                                        #   whitelist, blacklist, signature_required, custom
      parameters:
        max_amount: "10000"             # All values are strings
        currency: "DSM"
    action:
      type: "allow"                     # One of: allow, deny, require_approval, delay
    priority: 100                       # Higher = evaluated first
```

### Step 2: Rule Evaluation Order

Rules are evaluated by **priority** (highest first). The first matching rule
determines the outcome:

1. **priority: 300** — Blacklist check (deny) ← evaluated first
2. **priority: 200** — High-value review (require_approval)
3. **priority: 100** — Standard limit (allow)
4. **priority: 75** — Off-hours delay

### Step 3: Available Condition Types

| Type | Parameters | Use Case |
|------|-----------|----------|
| `amount_limit` | `max_amount`, `currency`, `window_iterations` | Cap transfer amounts |
| `iteration_window` | `start_iteration`, `end_iteration`, `amount_threshold` | Restrict by chain position |
| `whitelist` | `partners`, `match_field` | Allow trusted parties |
| `blacklist` | `jurisdictions`, `check_type` | Block restricted parties |
| `signature_required` | `count`, `reason`, `threshold_amount` | Require approvals |
| `custom` | arbitrary key-value | Application-specific logic |

### Step 4: Available Actions

| Action | Effect |
|--------|--------|
| `allow` | Transfer proceeds |
| `deny` | Transfer blocked |
| `require_approval` | Transfer queued for manual approval |
| `delay` | Transfer delayed by `iterations` chain ticks |

### Step 5: Generate and Use

```bash
cargo run -p dsm-gen -- client examples/detfi/policies/01-stablecoin-transfer.yaml --lang kotlin
```

Generates a `StablecoinTransferPolicyClient` with `evaluateTransaction()` that
applies all rules in priority order and returns the verdict.

---

## Walkthrough: Compile to Base32 Blob

The `dsm-gen compile` command converts a YAML spec into a Base32 protobuf blob
that can be pasted directly into the DSM phone app.

### Step 1: Compile a Vault

```bash
# Compile to Base32 (output to stdout)
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml

# Compile with explicit mode
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml --mode posted
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml --mode local

# Compile to file
dsm-gen compile examples/detfi/vaults/01-simple-escrow.yaml --output escrow.b32
```

### Step 2: Understand the Blob

The blob is a 3-byte header + protobuf payload, Base32 Crockford encoded:

| Byte | Field | Values |
|------|-------|--------|
| 0 | Version | `1` (current) |
| 1 | Mode | `0` = local, `1` = posted |
| 2 | Type | `0` = vault, `1` = policy |
| 3+ | Proto | `DlvCreateV3` or `TokenPolicyV3` bytes |

### Step 3: Paste into the Phone

1. Copy the Base32 string from stdout or the `.b32` file
2. Open the DSM app → Settings → Developer Options → DeTFi Launch
3. Paste the blob
4. The app auto-detects the type (vault/policy) and mode (posted/local)
5. Tap "Launch" — the app fills in your device identity and creates the vault

### Step 4: Compile a Policy

```bash
dsm-gen compile examples/detfi/policies/01-stablecoin-transfer.yaml
```

Policies are always posted (they're content-addressed and immutable).
The blob contains the full policy definition. Paste it into the app
to publish the policy and get its anchor hash.

---

## Pattern Reference

### Escrow
Lock tokens until a payment is proven. Simple 2-party pattern.
**Example**: `01-simple-escrow.yaml`

### dBTC Tap
Lock a vault against a Bitcoin HTLC. Preimage reveal mints dBTC 1:1.
**Example**: `02-bitcoin-backed-vault.yaml`

### Conditional Release
Require multiple conditions (AND) — e.g., signatures + collateral proof.
**Example**: `03-conditional-multisig.yaml`

### Oracle Attestation
Accept either an external attestation or on-chain state proof (OR).
**Example**: `04-oracle-attested-release.yaml`

### Compliance Policy
Rule-based transfer governance with priority-ordered evaluation.
**Examples**: `01-stablecoin-transfer.yaml`, `02-tiered-approval.yaml`

---

## Building Your Own

### Step 1: Copy a Template

```bash
cp examples/detfi/vaults/01-simple-escrow.yaml my-vault.yaml
```

### Step 2: Edit the Spec

Change the `name`, `fulfillment_condition`, `assets`, and other fields.
Refer to the [Fulfillment Condition Reference](#fulfillment-condition-reference)
for available condition types and their fields.

### Step 3: Validate

```bash
cargo run -p dsm-gen -- validate my-vault.yaml
```

Fix any errors until validation passes.

### Step 4: Generate

```bash
cargo run -p dsm-gen -- client my-vault.yaml --lang ts,kotlin,swift,rust
```

### Step 5: Integrate

Drop the generated client into your app. The client class has:
- `create()` — create the vault on-chain
- `unlock(proof)` — attempt to unlock with fulfillment proof
- `status()` — query current vault state
- `metadata()` — read vault metadata

### Step 6: Initialize a Full Project (Optional)

```bash
cargo run -p dsm-gen -- init my-detfi-project
```

This creates a project skeleton with `vaults/`, `policies/`, `docs/`, and `ci/`
directories plus sample YAML files.

---

## Fulfillment Condition Reference

### `payment`
Unlock by proving a token payment.

```yaml
fulfillment_condition:
  type: "payment"
  amount: 500                  # Token amount required
  token_id: "DSM"              # Token identifier
  recipient: "BASE32..."       # Recipient device ID (Base32 Crockford)
  verification_state: "BASE32..."  # Reference state hash (Base32 Crockford)
```

### `bitcoin_htlc`
Unlock by fulfilling a Bitcoin HTLC on-chain (dBTC tap).

```yaml
fulfillment_condition:
  type: "bitcoin_htlc"
  hash_lock: "BASE32..."           # SHA256(preimage) — Base32 Crockford
  refund_hash_lock: "BASE32..."    # SHA256(refund_key) — Base32 Crockford
  refund_iterations: 1000          # Chain ticks before refund activates
  bitcoin_pubkey: "BASE32..."      # 33-byte compressed BTC pubkey
  expected_btc_amount_sats: 100000 # Expected deposit in satoshis
  network: "testnet"               # mainnet | testnet | signet
  min_confirmations: 100           # Required confirmation depth
```

### `multi_signature`
Unlock by providing k-of-n SPHINCS+ signatures.

```yaml
fulfillment_condition:
  type: "multi_signature"
  public_keys:                 # SPHINCS+ public keys (Base32 Crockford)
    - "SIGNER1..."
    - "SIGNER2..."
    - "SIGNER3..."
  threshold: 2                 # Minimum signatures required
```

### `crypto_condition`
Unlock by revealing a hash preimage.

```yaml
fulfillment_condition:
  type: "crypto_condition"
  condition_hash: "BASE32..."  # BLAKE3 hash of the expected preimage
  public_params: "BASE32..."   # Public parameters for verification
```

### `state_reference`
Unlock when specific DSM states are reached.

```yaml
fulfillment_condition:
  type: "state_reference"
  reference_states:            # Target state hashes (Base32 Crockford)
    - "STATEHASH1..."
    - "STATEHASH2..."
  parameters: "BASE32..."     # Verification parameters
```

### `random_walk_verification`
Unlock by providing a random-walk ZK proof.

```yaml
fulfillment_condition:
  type: "random_walk_verification"
  verification_key: "BASE32..."  # Random-walk verification key
  statement: "description..."    # Human-readable statement
```

### `and` (All Required)
Unlock when ALL nested conditions are satisfied.

```yaml
fulfillment_condition:
  type: "and"
  conditions:
    - type: "multi_signature"
      # ...
    - type: "crypto_condition"
      # ...
```

### `or` (Any Sufficient)
Unlock when ANY nested condition is satisfied.

```yaml
fulfillment_condition:
  type: "or"
  conditions:
    - type: "crypto_condition"
      # ...
    - type: "state_reference"
      # ...
```

---

## FAQ

**Q: Is YAML used at runtime?**
No. YAML is a developer specification format only. `dsm-gen` compiles it into
typed builders that emit protobuf. The core state machine never sees YAML or JSON.

**Q: What are the placeholder keys in the examples?**
Keys like `ALICEDEVICEID000...` are readable placeholders that intentionally use
characters outside the Base32 Crockford alphabet (e.g., `I`, `L`, `O`). They
pass YAML schema validation (the schema stores them as `String`) but will fail
at runtime. Replace them with real SPHINCS+ public keys, BLAKE3 hashes, or
Bitcoin pubkeys encoded as Base32 Crockford before use. The valid Crockford
alphabet is: `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.

**Q: Can I nest AND/OR conditions?**
Yes, arbitrarily deep. Each level uses `type: "and"` or `type: "or"` with a
`conditions` array.

**Q: Why `duration_iterations` instead of seconds?**
DSM is clockless (Invariant #4). All timeouts are measured in hash-chain
iterations, never wall-clock time. This ensures deterministic behavior
regardless of real-world timing.

**Q: How do I test my spec?**
Run `cargo test -p dsm-gen --test detfi_examples` to see how the existing
examples are tested. Copy the pattern for your own specs.

**Q: Where does the generated code go in my app?**
The generated client classes import from your platform's DSM SDK (`@dsm/sdk`
for TypeScript, `com.dsm.vault.client` for Kotlin, etc.). Drop them into
your app's source tree and instantiate with your SDK instance.
