# SoFi Two-Device Playbook

End-to-end runbook for exercising the SoFi pipeline on two real
phones over a real storage node. After this, the claim
"SoFi works on my phone" is defensible from a clean device.

The playbook orchestrates the on-device dev screens that ship in
the wallet's Settings → Developer area. No CLI commands run on
the phone; everything is through the UI.

---

## Prereqs

### 1. Storage node up

A reachable `dsm_storage_node` instance is on the critical path —
without it the AMM advertisement won't publish and the trader's
Quote returns empty.

From the repo root:

```bash
cd dsm_storage_node
cargo run --release -- --bind 0.0.0.0:8080
```

Verify it answers:

```bash
curl -fsS http://localhost:8080/health
```

For two-phone testing the node must be reachable from each device's
network — bind to `0.0.0.0` and use the host's LAN IP in the wallet
config (not `127.0.0.1`).

### 2. Build + install the wallet

From the repo root:

```bash
cd dsm_client/frontend
npm run build:full-deploy
```

That bundles the React app, copies it into the Android assets, and
builds a debug APK at:

```
dsm_client/android/app/build/outputs/apk/debug/app-debug.apk
```

Install the APK on both phones. ADB:

```bash
adb -s <DEVICE_A_SERIAL> install -r app-debug.apk
adb -s <DEVICE_B_SERIAL> install -r app-debug.apk
```

### 3. Wallet bootstrap on both phones

Open the wallet on each device. Walk through wallet creation /
recovery so each phone has its own SPHINCS+ signing key. Confirm
the bootstrap completed by visiting Settings → and seeing the
device id rendered.

Each device's storage-node endpoint configuration must point at
the host's LAN IP (e.g. `http://192.168.1.50:8080`).

---

## Scenario A — AMM swap end-to-end

### Device A (Bob — vault owner)

1. Open Settings → scroll to Developer area → tap **AMM VAULT (DEV)**.
2. Fill in the form:
   - `token_a` = `DEMO_AAA`
   - `token_b` = `DEMO_BBB`
   - `reserve_a` = `1000000`
   - `reserve_b` = `1000000`
   - `fee` = `30`
   - `policy_anchor` — paste a published policy anchor in Base32
     Crockford. The DevPolicyScreen ("POLICY TOOLS" button) can
     publish a policy and surface its anchor; copy the resulting
     id and paste here.
3. Tap **Create AMM vault**. Status reads `Vault created. id=…`.
   Capture the vault id Base32 — you'll verify it on Device B.
4. Tap **Publish routing ad**. Status reads `Advertisement
   published. vaultId=…`.
5. Navigate back to Settings → tap **AMM VAULT MONITOR (DEV)**.
   Verify the just-created vault appears with the expected
   reserves, fee, and `routing ad: ✓ published (state_number=1)`.

### Device B (Alice — trader)

1. Open Settings → scroll to Developer area → tap **AMM TRADE (DEV)**.
2. Fill in the form:
   - `input token` = `DEMO_AAA`
   - `output token` = `DEMO_BBB`
   - `input amount` = `10000`
3. Tap **Quote**. Status reads `1 vault(s) discovered`. The
   discovered-vaults panel shows Bob's vault with the published
   reserves and fee. The vault auto-selects.
4. Tap **Execute trade**. Watch the pipeline panel advance:
   - `1. Sync local DLVManager from routing keyspace ✓`
   - `2. Find + bind best path (unsigned RouteCommit) ✓`
   - `3. Sign the RouteCommit (wallet pk + SPHINCS+) ✓`
   - `4. Compute external commitment X ✓`
   - `5. Publish anchor at defi/extcommit/X ✓`
   - `6. Execute unlockRouted on selected vault ✓`
5. Status reads `Trade settled. Reserves refreshed.` The discovered-
   vaults panel re-renders with post-trade reserves
   (`(1010000, 990129)` for the default 10000 input @ 30 bps fee).

### Verification on Device A

1. Return to **AMM VAULT MONITOR (DEV)** and tap **Refresh**.
2. Confirm the same vault now shows:
   - reserves = `(1010000, 990129)`
   - `routing ad: ✓ published (state_number=2)`

The state_number bump from 1 → 2 confirms the republish-on-settled
chain fired — Bob's storage-node advertisement reflects post-trade
state.

---

## Scenario B — Posted-DLV send + claim

### Get Alice's Kyber pk

On Device B (Alice), tap **POSTED DLV INBOX (DEV)** in Settings.
The inbox displays the device's Kyber pk (or copy it from the
wallet bootstrap output). It's a Base32 Crockford string of
~2500 chars (Kyber-1024 public key is 1568 bytes).

### Device A (Bob — sender)

1. Settings → tap **POSTED DLV SEND (DEV)**.
2. Paste Alice's Kyber pk into the Recipient textarea.
3. Paste a 32-byte policy anchor into the Policy anchor field
   (same one used for the AMM vault works).
4. Optionally set `token_id` and `locked amount` for a balance-
   locked vault, or leave both empty for a content-only DLV.
5. Edit the Content textarea to whatever message / payload Bob
   wants Alice to receive.
6. Tap **Send posted DLV**. Status reads
   `Posted DLV created. id=…`.

The Track B Rust path on `dlv.create` published the advertisement
to `dlv/posted/{alice_kyber_pk}/{vault_id}` automatically when it
saw `intended_recipient` non-empty.

### Device B (Alice — receiver)

1. Settings → tap **POSTED DLV INBOX (DEV)**.
2. Tap **Refresh inbox**. Status reads `1 pending DLV(s)` (or
   higher if there were prior unsynced ones).
3. Tap **Sync all**. The row state advances `pending → syncing
   → mirrored`.
4. Tap **Claim** on the row. State advances `mirrored → claiming
   → claimed ✓`.
5. Status reads `Claimed <vault_id>`. If the DLV had a balance
   lock, Alice's wallet balance should reflect the credit (verify
   via the main wallet screen).

---

## Common failure modes

### Storage node unreachable

Symptom: trader's Quote returns `0 vault(s) discovered` even after
Bob published.

Verify the storage node URL in each wallet's config. The
storage-node `health` endpoint must answer from each phone's
network.

### Network partition mid-trade

Symptom: pipeline gets to step 5 (`Publish anchor`) and stalls or
fails.

The on-chain advance has not happened yet. Re-execute the trade
when network is restored. No state is corrupted because steps 5+6
are gated on storage-node responses.

### Stale-reserves OutputMismatch

Symptom: pipeline reaches step 6 and fails with
`OutputMismatch — typed reject` (chunk #7 gate).

This is correct safety behaviour: someone else's trade settled
between Alice's Quote and her Execute. Re-tap **Quote** on the
trader screen — the discovered-vaults panel re-renders with fresh
reserves. Re-execute against the new quote.

### Repeated `OutputMismatch`

Symptom: re-quote and re-execute keeps producing the same mismatch.

The vault owner may not have run republish-on-settled (chunk
republish-on-settled landed but requires the unlock to come
through `dlv.unlockRouted` to fire). If a non-routed unlock
mutated reserves, manual republish via the AMM vault screen's
**Publish routing ad** button forces a state_number bump.

### Wallet pk empty error on `Send posted DLV`

Symptom: `wallet signing pk is empty`.

The wallet hasn't completed bootstrap. Walk through wallet
creation / recovery first; the SPHINCS+ key is set during
bootstrap.

---

## What this proves

After completing scenarios A and B successfully on two real
phones, the following claims are defensible:

- A user can create an AMM vault on Phone 1 and have Phone 2
  trade against it through the full chunks #1–#7 pipeline
  (advertisement publish → discovery → path search → RouteCommit
  bind → SPHINCS+ sign → external commitment → anchor publish →
  eligibility gate → AMM re-simulation → reserve advance →
  republish-on-settled).
- A user can post a DLV from Phone 1 addressed to Phone 2's
  Kyber pk, and Phone 2 can discover, sync, and claim it through
  the on-device inbox UI.
- All cryptographic operations stay Rust-side per the architectural
  rule. Frontend is a thin bridge.
- The `CLAUDE.md` ban list (placeholder markers, `hex::` codecs,
  JSON envelopes, deprecated identifiers, wall-clock APIs in
  protocol semantics) remains satisfied across the touched files.

What this does NOT prove (Tier 2 work, out of scope):

- Multi-trader concurrency safety (per-vault state registry +
  SMT inclusion proofs).
- Encumbrance + claim availability deferral semantics.
- Route-set membership proofs.
- Intent-bounds (slippage, expiry, max-input).

Those land in subsequent plans.
