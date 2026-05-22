#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Cross-device SoFi trade test orchestrator (Phase 8).
#
# Drives two physically distinct Android devices through the full
# SoFi (Sovereign Finance) trade pipeline:
#
#   Wallet A (owner)  : SoFiCrossDeviceOwnerTest  on $OWNER_SERIAL
#   Wallet B (trader) : SoFiCrossDeviceTraderTest on $TRADER_SERIAL
#
# Together they prove SoFi spec §4.1's "once a valid σ exists on
# storage, the unlock is computable by anyone" property on real
# hardware — Wallet B discovers Wallet A's vaults via shared storage
# nodes (configured in dsm_env_config.toml), trades against them, and
# settles WITHOUT Wallet A's device being involved beyond the initial
# publish.
#
# Prerequisites:
#  • Two Android devices visible to `adb devices` with USB or
#    network ADB.
#  • Both devices have the SAME debug + androidTest APKs installed
#    (run `./gradlew :app:assembleDebug :app:assembleDebugAndroidTest`
#    then `adb -s $SERIAL install -r ...` for each device + APK pair).
#  • Both devices have IDENTICAL `dsm_env_config.toml` deployed at
#    `/sdcard/Download/dsm_env_config.toml`.  This script verifies
#    the md5sums match before doing anything else — different cluster
#    configs mean Wallet B can't read Wallet A's storage writes, which
#    is the whole load-bearing assumption.
#  • Both wallets have completed genesis bootstrap (open the wallet
#    UI once on each device + walk through the setup, then close).
#
# Usage:
#
#   ./scripts/run_cross_device_sofi_test.sh OWNER_SERIAL TRADER_SERIAL
#
# Or via env vars:
#
#   OWNER_SERIAL=<a> TRADER_SERIAL=<b> ./scripts/run_cross_device_sofi_test.sh
#
# Exit codes:
#   0 — both tests passed; cross-device settle observed on both sides
#   1 — orchestrator setup failure (devices unreachable, config mismatch)
#   2 — owner test failed (vaults not published, settle not observed)
#   3 — trader test failed (discovery, sign, publish, or unlock failed)
#   4 — both tests passed locally but cross-validation failed (e.g.
#       trader's settled vault doesn't match owner's observed vault)

set -euo pipefail

OWNER_SERIAL="${1:-${OWNER_SERIAL:-}}"
TRADER_SERIAL="${2:-${TRADER_SERIAL:-}}"

if [[ -z "$OWNER_SERIAL" || -z "$TRADER_SERIAL" ]]; then
    echo "usage: $0 <OWNER_SERIAL> <TRADER_SERIAL>" >&2
    echo "  or:  OWNER_SERIAL=<a> TRADER_SERIAL=<b> $0" >&2
    exit 1
fi

if [[ "$OWNER_SERIAL" == "$TRADER_SERIAL" ]]; then
    echo "ERROR: owner and trader must be different devices (got $OWNER_SERIAL == $TRADER_SERIAL)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

OWNER_LOG="$TMP_DIR/owner.logcat"
TRADER_LOG="$TMP_DIR/trader.logcat"

echo "════════════════════════════════════════════════════════════"
echo "  Cross-device SoFi trade test orchestrator"
echo "  Owner  : $OWNER_SERIAL"
echo "  Trader : $TRADER_SERIAL"
echo "  Work   : $TMP_DIR"
echo "════════════════════════════════════════════════════════════"

# ── Sanity check: both devices reachable ──────────────────────────
for SERIAL in "$OWNER_SERIAL" "$TRADER_SERIAL"; do
    if ! adb -s "$SERIAL" shell echo OK >/dev/null 2>&1; then
        echo "ERROR: device $SERIAL is not reachable via adb" >&2
        exit 1
    fi
done
echo "✓ both devices reachable"

# ── Disable Samsung/AOSP BackupManagerService on both devices.
#    Without this, `restoreAtInstall` fires every time gradle's
#    connectedAndroidTest reinstalls the APK and wipes the wallet's
#    locally-persisted genesis state with a stale cloud snapshot
#    (observed on Galaxy A54 + A16 — the wallet's manifest sets
#    allowBackup=false but Samsung's variant ignores that for system
#    restore).  The bmgr disable persists across reboots; subsequent
#    test runs see no further wipes.
for SERIAL in "$OWNER_SERIAL" "$TRADER_SERIAL"; do
    adb -s "$SERIAL" shell "bmgr enable false" >/dev/null 2>&1 || true
done
echo "✓ BackupManagerService disabled on both devices (prevents wallet-data wipe on reinstall)"

# ── Sanity check: identical dsm_env_config.toml ───────────────────
# Storage node set config MUST match — different config = different
# storage keyspaces = trader can't read owner's writes.
OWNER_CFG_MD5="$(adb -s "$OWNER_SERIAL" shell md5sum /sdcard/Download/dsm_env_config.toml 2>/dev/null | awk '{print $1}')"
TRADER_CFG_MD5="$(adb -s "$TRADER_SERIAL" shell md5sum /sdcard/Download/dsm_env_config.toml 2>/dev/null | awk '{print $1}')"
if [[ -z "$OWNER_CFG_MD5" || -z "$TRADER_CFG_MD5" ]]; then
    echo "ERROR: /sdcard/Download/dsm_env_config.toml missing on one or both devices" >&2
    echo "       owner_md5='$OWNER_CFG_MD5' trader_md5='$TRADER_CFG_MD5'" >&2
    exit 1
fi
if [[ "$OWNER_CFG_MD5" != "$TRADER_CFG_MD5" ]]; then
    echo "ERROR: dsm_env_config.toml differs between devices" >&2
    echo "       owner_md5  = $OWNER_CFG_MD5" >&2
    echo "       trader_md5 = $TRADER_CFG_MD5" >&2
    echo "       Push identical config to both: adb -s <serial> push <local.toml> /sdcard/Download/dsm_env_config.toml" >&2
    exit 1
fi
echo "✓ identical dsm_env_config.toml on both devices (md5=$OWNER_CFG_MD5)"

# ── Wallet-data backup + restore around the gradle install.
#    Gradle's connectedAndroidTest install path triggers an
#    Android-system clean install whenever the APK changes between
#    runs (signature/binary delta).  bmgr disable + allowBackup=false
#    do NOT prevent this on Samsung devices — observed empirically
#    that A54 + A16 both lose `dsm_silicon_fp_v4.bin` + `dsm_client.db`
#    on every code-change install cycle, forcing a ~15min M=3
#    re-enrollment per device.  This loop runs `run-as tar` against
#    each wallet's private files dir BEFORE the gradle install
#    spawns, stashes the archive to /sdcard, then restores after
#    the install completes.  The wallet's app is debuggable in the
#    dev build (manifest android:debuggable=true) so run-as is
#    available.  We pre-install + pre-restore here, then pass
#    `-Pandroid.testInstrumentationRunnerArguments.dontDisableTests=
#    true` (placeholder) — actually gradle still reinstalls; the
#    restore re-fires AFTER each gradle install pulses.  Cheaper to
#    move the backup right before tests and accept the wipe risk
#    once: see the explicit pre-install backup below.
HOST_BACKUP_DIR="$HOME/.dsm/sofi_wallet_backups"
mkdir -p "$HOST_BACKUP_DIR"

backup_wallet() {
    local SERIAL="$1"
    local STAGE="$2"
    local BACKUP_PATH="/sdcard/sofi_wallet_backup_${SERIAL}_${STAGE}.tar.b64"
    local HOST_PATH="$HOST_BACKUP_DIR/sofi_wallet_backup_${SERIAL}_${STAGE}.tar.b64"

    # Skip-and-preserve guard: if com.dsm.wallet isn't installed, the
    # `run-as` below would emit nothing and the `> $BACKUP_PATH` would
    # truncate any existing good backup to zero bytes (this is exactly
    # how a previous orchestrator run obliterated 634245-byte backups
    # from a successful prior run).  Bail without touching the device
    # or host file.
    local PKG_PRESENT
    PKG_PRESENT=$(adb -s "$SERIAL" shell "pm list packages com.dsm.wallet" 2>&1 | tr -d '\r')
    if [[ -z "$PKG_PRESENT" || "$PKG_PRESENT" != *"com.dsm.wallet"* ]]; then
        echo "  ! backup on $SERIAL skipped: com.dsm.wallet not installed — preserving any existing backup at $BACKUP_PATH + $HOST_PATH"
        return
    fi

    # Stage to a .new file so we don't truncate an existing good
    # backup if this attempt produces trivial output (e.g. wallet
    # files dir empty post-wipe).
    local TMP_BACKUP="${BACKUP_PATH}.new"
    adb -s "$SERIAL" shell "run-as com.dsm.wallet sh -c 'cd /data/data/com.dsm.wallet && tar -cf - files/' 2>/dev/null | base64 > $TMP_BACKUP" 2>&1 >/dev/null || true
    local SIZE
    SIZE=$(adb -s "$SERIAL" shell "stat -c %s $TMP_BACKUP 2>/dev/null" 2>&1 | tr -d '\r')
    SIZE=${SIZE:-0}
    if ! [[ "$SIZE" =~ ^[0-9]+$ ]]; then SIZE=0; fi
    # An empty wallet's `tar files/` produces ~512 bytes of tar header
    # + base64 overhead = several hundred bytes minimum.  A real
    # populated wallet is hundreds of KB.  Use 1024 as the floor.
    if (( SIZE > 1024 )); then
        adb -s "$SERIAL" shell "mv $TMP_BACKUP $BACKUP_PATH" >/dev/null 2>&1
        # Also pull to host so the backup survives a full device
        # uninstall (Samsung/Smart-Switch sometimes nukes
        # com.dsm.wallet between runs).
        adb -s "$SERIAL" pull "$BACKUP_PATH" "$HOST_PATH" >/dev/null 2>&1 || true
        echo "  ✓ backed up wallet on $SERIAL (size=$SIZE bytes) -> $BACKUP_PATH + $HOST_PATH"
    else
        adb -s "$SERIAL" shell "rm $TMP_BACKUP" >/dev/null 2>&1 || true
        echo "  ! backup on $SERIAL trivial (size=$SIZE); preserving existing $BACKUP_PATH + $HOST_PATH"
    fi
}

restore_wallet() {
    local SERIAL="$1"
    local STAGE="$2"
    local BACKUP_PATH="/sdcard/sofi_wallet_backup_${SERIAL}_${STAGE}.tar.b64"
    local HOST_PATH="$HOST_BACKUP_DIR/sofi_wallet_backup_${SERIAL}_${STAGE}.tar.b64"

    # If /sdcard backup is missing or trivial but a host backup
    # exists, push it back to the device first.  This is the
    # uninstall-survives path.
    local DEV_SIZE
    DEV_SIZE=$(adb -s "$SERIAL" shell "stat -c %s $BACKUP_PATH 2>/dev/null" 2>&1 | tr -d '\r')
    DEV_SIZE=${DEV_SIZE:-0}
    if ! [[ "$DEV_SIZE" =~ ^[0-9]+$ ]]; then DEV_SIZE=0; fi
    if (( DEV_SIZE <= 1024 )) && [[ -f "$HOST_PATH" ]]; then
        local HOST_SIZE=$(stat -f %z "$HOST_PATH" 2>/dev/null || stat -c %s "$HOST_PATH" 2>/dev/null || echo "0")
        if (( HOST_SIZE > 1024 )); then
            echo "  · device backup missing/trivial ($DEV_SIZE B); pushing from host ($HOST_SIZE B)"
            adb -s "$SERIAL" push "$HOST_PATH" "$BACKUP_PATH" >/dev/null 2>&1 || true
            DEV_SIZE=$HOST_SIZE
        fi
    fi
    if (( DEV_SIZE <= 1024 )); then
        echo "  ! restore on $SERIAL skipped: no usable backup (device=$DEV_SIZE B, host=$(stat -f %z "$HOST_PATH" 2>/dev/null || echo "absent"))"
        return
    fi
    # Force-stop the app so file operations are safe (no in-flight
    # writes), then untar over the existing dir.
    adb -s "$SERIAL" shell "am force-stop com.dsm.wallet" >/dev/null 2>&1 || true
    if adb -s "$SERIAL" shell "cat $BACKUP_PATH | base64 -d | run-as com.dsm.wallet tar -xf - -C /data/data/com.dsm.wallet" 2>&1 >/dev/null; then
        echo "  ✓ restored wallet on $SERIAL (size=$DEV_SIZE bytes) <- $BACKUP_PATH"
    else
        echo "  ! restore on $SERIAL failed"
    fi
}

echo
echo "── Phase 0/3: backup + reinstall main APK + test APK + restore on both devices"
echo "             (preserves M=3 enrollment across install; test runs via `am instrument` directly — bypass gradle's installer)"
APP_APK="$(dirname "$0")/../app/build/outputs/apk/debug/app-debug.apk"
TEST_APK="$(dirname "$0")/../app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
if [[ ! -f "$APP_APK" ]]; then
    echo "ERROR: main APK not found at $APP_APK — run ./gradlew :app:assembleDebug first" >&2
    exit 1
fi
if [[ ! -f "$TEST_APK" ]]; then
    echo "ERROR: androidTest APK not found at $TEST_APK — run ./gradlew :app:assembleDebugAndroidTest first" >&2
    exit 1
fi
for SERIAL in "$OWNER_SERIAL" "$TRADER_SERIAL"; do
    echo "  ── $SERIAL ──"
    backup_wallet "$SERIAL" "preinstall"
    # Force-stop before install to avoid in-flight write races.
    adb -s "$SERIAL" shell "am force-stop com.dsm.wallet" >/dev/null 2>&1 || true
    adb -s "$SERIAL" shell "am force-stop com.dsm.wallet.test" >/dev/null 2>&1 || true
    # Install both APKs.  Samsung's `pm install -r` clears
    # /data/data/com.dsm.wallet/files/* on every reinstall under
    # clean-install behaviour, so we install BOTH up front (main +
    # test) then restore wallet data ONCE.  Tests run via
    # `am instrument` directly — no further install cycles.
    echo "  · installing main APK"
    if adb -s "$SERIAL" install -r "$APP_APK" 2>&1 | tail -1 | grep -q Success; then
        echo "  ✓ installed main APK on $SERIAL"
    else
        echo "  ! main APK install on $SERIAL failed" >&2
    fi
    echo "  · installing androidTest APK"
    if adb -s "$SERIAL" install -r "$TEST_APK" 2>&1 | tail -1 | grep -q Success; then
        echo "  ✓ installed androidTest APK on $SERIAL"
    else
        echo "  ! androidTest APK install on $SERIAL failed" >&2
    fi
    # Restore AFTER both installs.  This is the load-bearing step —
    # the install above wiped data, this puts the M=3 enrollment +
    # SQLite identity back.
    restore_wallet "$SERIAL" "preinstall"
done
echo "  ✓ both APKs installed + wallet data restored on both devices"

# ── Start owner's logcat capture in the background ────────────────
echo
echo "── Phase 1/3: starting owner's logcat capture"
adb -s "$OWNER_SERIAL" logcat -c
adb -s "$OWNER_SERIAL" logcat -s SOFI_TRADE SOFI_XDEV > "$OWNER_LOG" &
OWNER_LOGCAT_PID=$!
trap 'kill $OWNER_LOGCAT_PID 2>/dev/null || true; rm -rf "$TMP_DIR"' EXIT

# ── Launch owner test in the background via `am instrument`
#    directly — bypassing gradle's installer pipeline so the wallet
#    data restored by Phase 0 is not wiped by an extra install
#    cycle.  Both main + test APKs are already on-device from
#    Phase 0; this just runs the test class. ──
echo "── Phase 1/3: launching owner test on $OWNER_SERIAL via am instrument"
(
    adb -s "$OWNER_SERIAL" shell am instrument -w -r \
        -e class com.dsm.wallet.sofi.SoFiCrossDeviceOwnerTest \
        com.dsm.wallet.test/androidx.test.runner.AndroidJUnitRunner \
        > "$TMP_DIR/owner.gradle.log" 2>&1
    # `am instrument` exits 0 even when tests fail; parse the output
    # for INSTRUMENTATION_CODE: -1 → all passed, anything else → failure.
    if grep -qE 'INSTRUMENTATION_CODE:\s*-1' "$TMP_DIR/owner.gradle.log"; then
        echo "0" > "$TMP_DIR/owner.exit"
    else
        echo "1" > "$TMP_DIR/owner.exit"
    fi
) &
OWNER_GRADLE_PID=$!

# ── Wait for the owner's "owner_published" sentinel ───────────────
echo "── Phase 2/3: waiting for owner sentinel (timeout 180s)"
SENTINEL_DEADLINE=$(( $(date +%s) + 180 ))
SALT=""
V1=""
V2=""
OUT=""
while [[ -z "$SALT" ]]; do
    if [[ $(date +%s) -gt $SENTINEL_DEADLINE ]]; then
        echo "ERROR: owner test did not emit 'owner_published' sentinel within 180s" >&2
        echo "── Owner logcat (last 80 lines) ─" >&2
        tail -n 80 "$OWNER_LOG" >&2 || true
        echo "── Owner gradle stdout (last 30 lines) ─" >&2
        tail -n 30 "$TMP_DIR/owner.gradle.log" >&2 || true
        kill $OWNER_GRADLE_PID 2>/dev/null || true
        exit 2
    fi
    # Look for the sentinel line in the captured logcat.
    SENTINEL_LINE="$(grep -E 'SOFI_XDEV.*owner_published' "$OWNER_LOG" 2>/dev/null | head -n 1 || true)"
    if [[ -n "$SENTINEL_LINE" ]]; then
        SALT="$(echo "$SENTINEL_LINE" | grep -oE 'salt=[a-f0-9]+' | head -n 1 | cut -d= -f2)"
        V1="$(echo   "$SENTINEL_LINE" | grep -oE 'v1=[A-Z0-9]+'   | head -n 1 | cut -d= -f2)"
        V2="$(echo   "$SENTINEL_LINE" | grep -oE 'v2=[A-Z0-9]+'   | head -n 1 | cut -d= -f2)"
        OUT="$(echo  "$SENTINEL_LINE" | grep -oE 'output_token_b32=[A-Z0-9]+' | head -n 1 | cut -d= -f2)"
        if [[ -n "$SALT" && -n "$V1" && -n "$V2" && -n "$OUT" ]]; then
            break
        fi
        # Reset partial matches — try again next iteration.
        SALT=""
    fi
    sleep 2
done
echo "✓ owner sentinel parsed: salt=$SALT v1=$V1 v2=$V2 output_token=$OUT"

# ── Start trader's logcat capture + launch trader test ────────────
echo
echo "── Phase 3/3: launching trader test on $TRADER_SERIAL"
adb -s "$TRADER_SERIAL" logcat -c
adb -s "$TRADER_SERIAL" logcat -s SOFI_TRADE SOFI_XDEV > "$TRADER_LOG" &
TRADER_LOGCAT_PID=$!
trap 'kill $OWNER_LOGCAT_PID $TRADER_LOGCAT_PID 2>/dev/null || true; rm -rf "$TMP_DIR"' EXIT

# Run trader test via `am instrument` directly (same bypass-gradle
# logic as the owner side).  Pass orchestrator args as `-e key val`
# pairs — AndroidJUnitRunner exposes these via
# InstrumentationRegistry.getArguments() inside the test.
adb -s "$TRADER_SERIAL" shell am instrument -w -r \
    -e class com.dsm.wallet.sofi.SoFiCrossDeviceTraderTest \
    -e owner_salt "$SALT" \
    -e owner_v1_b32 "$V1" \
    -e owner_v2_b32 "$V2" \
    -e output_token_b32 "$OUT" \
    com.dsm.wallet.test/androidx.test.runner.AndroidJUnitRunner \
    > "$TMP_DIR/trader.gradle.log" 2>&1 &
TRADER_GRADLE_PID=$!

# ── Wait for trader test to finish ────────────────────────────────
wait $TRADER_GRADLE_PID
# am instrument exits 0 even on test failure; check INSTRUMENTATION_CODE.
if grep -qE 'INSTRUMENTATION_CODE:\s*-1' "$TMP_DIR/trader.gradle.log"; then
    TRADER_EXIT=0
else
    TRADER_EXIT=1
fi
echo
echo "── trader test finished with exit code $TRADER_EXIT"
if [[ $TRADER_EXIT -ne 0 ]]; then
    echo "ERROR: trader test failed" >&2
    echo "── Trader logcat (last 80 lines) ─" >&2
    tail -n 80 "$TRADER_LOG" >&2 || true
    echo "── Trader gradle stdout (last 30 lines) ─" >&2
    tail -n 30 "$TMP_DIR/trader.gradle.log" >&2 || true
    kill $OWNER_GRADLE_PID 2>/dev/null || true
    exit 3
fi

# ── Wait for owner test to finish (its settlement poll should fire
#    once the trader's settle propagates back).  Bounded — the
#    owner's test has its own poll budget that will fail() if the
#    trader's settle never lands. ──
echo "── waiting for owner test to detect trader settlement"
wait $OWNER_GRADLE_PID
OWNER_EXIT="$(cat "$TMP_DIR/owner.exit" 2>/dev/null || echo "999")"
echo "── owner test finished with exit code $OWNER_EXIT"
if [[ "$OWNER_EXIT" != "0" ]]; then
    echo "ERROR: owner test failed" >&2
    echo "── Owner logcat (last 80 lines) ─" >&2
    tail -n 80 "$OWNER_LOG" >&2 || true
    echo "── Owner gradle stdout (last 30 lines) ─" >&2
    tail -n 30 "$TMP_DIR/owner.gradle.log" >&2 || true
    exit 2
fi

# ── Cross-validation: trader's `trader_settled` and owner's
#    `owner_observed_settle` must reference the same vault. ─
TRADER_SETTLED_LINE="$(grep -E 'SOFI_XDEV.*trader_settled' "$TRADER_LOG" 2>/dev/null | head -n 1 || true)"
OWNER_OBSERVED_LINE="$(grep -E 'SOFI_XDEV.*owner_observed_settle' "$OWNER_LOG" 2>/dev/null | head -n 1 || true)"

if [[ -z "$TRADER_SETTLED_LINE" ]]; then
    echo "ERROR: trader test passed but no 'trader_settled' sentinel in logcat" >&2
    exit 4
fi
if [[ -z "$OWNER_OBSERVED_LINE" ]]; then
    echo "ERROR: owner test passed but no 'owner_observed_settle' sentinel in logcat" >&2
    exit 4
fi
TRADER_VAULT="$(echo "$TRADER_SETTLED_LINE" | grep -oE 'vault=[A-Z0-9]+' | head -n 1 | cut -d= -f2)"
OWNER_VAULT="$(echo  "$OWNER_OBSERVED_LINE"  | grep -oE 'vault=[A-Z0-9]+' | head -n 1 | cut -d= -f2)"
if [[ "$TRADER_VAULT" != "$OWNER_VAULT" ]]; then
    echo "ERROR: cross-validation failed — trader settled vault=$TRADER_VAULT" >&2
    echo "       but owner observed settle on vault=$OWNER_VAULT" >&2
    exit 4
fi

echo
echo "════════════════════════════════════════════════════════════"
echo "  ✓ cross-device SoFi trade settled"
echo "    vault     : $TRADER_VAULT"
echo "    trader log: $TRADER_SETTLED_LINE"
echo "    owner  log: $OWNER_OBSERVED_LINE"
echo "════════════════════════════════════════════════════════════"
