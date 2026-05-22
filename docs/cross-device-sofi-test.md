# Cross-Device SoFi Trade Test (Phase 8)

Automated end-to-end test that proves SoFi spec §4.1's _"once a valid
σ exists on storage, the unlock is computable by anyone"_ property on
real hardware. Wallet A on one device creates AMM vaults and
publishes routing advertisements; Wallet B on a physically distinct
second device discovers them via shared storage and trades against
them without Wallet A's device being involved beyond the initial
publish.

This is the instrumentation-test counterpart to the manual
[SoFi Two-Device Playbook](./sofi-two-device-playbook.md). Use the
playbook for interactive demos and exploratory testing; use this
automated test for regression gating + CI-style repeatability on
local hardware.

---

## Prerequisites

1. **Two Android devices** visible to `adb devices`. The reference
   pair is Galaxy A54 (owner) + Galaxy A16 (trader); any two devices
   with the same APK should work.
2. **Identical APK + androidTest APK** installed on both devices:
   ```bash
   cd dsm_client/android
   ./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
   adb -s $OWNER_SERIAL  install -r app/build/outputs/apk/debug/app-debug.apk
   adb -s $OWNER_SERIAL  install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
   adb -s $TRADER_SERIAL install -r app/build/outputs/apk/debug/app-debug.apk
   adb -s $TRADER_SERIAL install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
   ```
3. **Identical `dsm_env_config.toml`** at `/sdcard/Download/dsm_env_config.toml`
   on both devices. The orchestrator script verifies the md5sums
   match before doing anything else — different cluster configs mean
   the trader can't read the owner's storage writes.
   ```bash
   adb -s $OWNER_SERIAL  push <local.toml> /sdcard/Download/dsm_env_config.toml
   adb -s $TRADER_SERIAL push <local.toml> /sdcard/Download/dsm_env_config.toml
   ```
4. **Both wallets bootstrapped**. Open the wallet UI once on each
   device + walk through the genesis flow, then close. The
   instrumentation test's `setUp` polls
   `Unified.ensureAppRouterInstalled()` for up to 60s but is more
   reliable when bootstrap is pre-warmed.

## Run

```bash
cd dsm_client/android
./scripts/run_cross_device_sofi_test.sh $OWNER_SERIAL $TRADER_SERIAL
```

Or via env vars:

```bash
OWNER_SERIAL=<a> TRADER_SERIAL=<b> ./scripts/run_cross_device_sofi_test.sh
```

Expected success output (last few lines):

```
✓ cross-device SoFi trade settled
  vault     : 971CDARC...
  trader log: SOFI_XDEV: trader_settled vault=971CDARC... expected_out=996 floor=991 fallbacks=1
  owner  log: SOFI_XDEV: owner_observed_settle vault=971CDARC... actual_in=1000 actual_out=996 ...
```

Total runtime: ~3-5 minutes (most of which is gradle assembly + the
owner's ~60s post-trade settlement poll waiting for storage
replication).

## What it proves

| Property | How |
|---|---|
| Trader can discover owner's vaults across devices | `route.syncVaultsForPair` reads owner's writes; trader's `findAndBindBestPath` returns a vault_id matching one of the owner's. |
| `dlv.unlockRouted` works for a non-owner trader | Phase 6 fix gates only the post-settle anchor republish on owner-key match. The unlock itself proceeds for any caller. |
| Storage cluster is genuinely shared | md5sum check on `dsm_env_config.toml` + the trader successfully decoding the owner's published `RoutingVaultAdvertisementV1`. |
| Phase 7 SMT inclusion proofs travel cross-device | The trader's strict-mode composition (`compose_vault_state`) refuses to fold the owner's vault without a verifiable `VaultStateInclusionProofV1` published by the owner. If this check rejects, the failure is informative (`MissingInclusionProof` / `InvalidInclusionProof`) and lands in the trader's logcat. |
| Phase 6 pending-pointer composition reflects cross-device settles | The owner's `dlv.listOwnedAmmVaults` shows the post-trade reserve drift after the trader's settlement, even though the trader's `dlv.unlockRouted` ran in a completely separate process on a different device. |

## Failure modes

The orchestrator dumps both devices' logcat tails on failure. Most
common modes:

- **"orchestrator setup failure"** (exit 1) — devices unreachable or
  cluster config md5sum mismatch. Fix the config first.
- **"owner test failed"** (exit 2) — vaults didn't publish, OR the
  trader's settlement never propagated back to the owner within the
  poll budget. Check the owner's gradle log for the actual JUnit
  failure (vaults usually publish fine; "settle not observed" is the
  trader's storage round trip not reaching the owner — almost always
  cluster connectivity).
- **"trader test failed"** (exit 3) — discovery, sign, publish, or
  unlock failed on the trader. The trader's gradle log shows the
  exact JUnit failure. Two common variants:
  - `findAndBindBestPath picked vault=<X> which is NEITHER owner's v1 NOR v2` →
    storage round trip read stale ads. Run again with fresh devices.
  - `CompositionError::MissingInclusionProof` → owner didn't publish
    Phase 7 inclusion proofs. Verify the owner is on the post-Phase-7
    APK (commit `b9960b2` or later).
- **"cross-validation failed"** (exit 4) — both tests passed locally
  but the trader's settled vault_id doesn't match the owner's
  observed vault_id. Means there's a stale advertisement somewhere
  that masked the cross-device path. Reinstall both APKs + clear app
  data (`adb shell pm clear com.dsm.wallet`) and re-run.

## Out of scope

- **BLE transport.** SoFi unlock is online and storage-mediated.
  Bilateral BLE transport is a separate use case (direct A-to-B
  transfer with no routing); see the BLE-specific test suite.
- **Three-device or N-device chained settlement.** Two devices proves
  the cross-device property. N-device scaling is exercised in-process
  by the Phase 6 composition unit tests.
- **CI integration.** Manual run on local hardware for now. Hardware-
  test rigs in CI are a separate workstream.
- **§5.2 multi-hop atomic settlement.** Different gap — chained vault
  unlocks under one envelope. Future phase.

## Related

- [SoFi Two-Device Playbook](./sofi-two-device-playbook.md) — manual
  UI-driven runbook for the same protocol property
- [SoFi LP walkthrough](./sofi-lp-walkthrough.md) — LP-side flow
- Test sources:
  `dsm_client/android/app/src/androidTest/java/com/dsm/wallet/sofi/`
- Orchestrator: `dsm_client/android/scripts/run_cross_device_sofi_test.sh`
- Phase 8 plan: `~/.claude/plans/finish-implementing-the-actual-typed-river.md`
