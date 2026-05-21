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

# ── Sanity check: identical dsm_env_config.toml ───────────────────
# Storage cluster config MUST match — different clusters = different
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

# ── Start owner's logcat capture in the background ────────────────
echo
echo "── Phase 1/3: starting owner's logcat capture"
adb -s "$OWNER_SERIAL" logcat -c
adb -s "$OWNER_SERIAL" logcat -s SOFI_TRADE SOFI_XDEV > "$OWNER_LOG" &
OWNER_LOGCAT_PID=$!
trap 'kill $OWNER_LOGCAT_PID 2>/dev/null || true; rm -rf "$TMP_DIR"' EXIT

# ── Launch owner test in the background.  We need it running BEFORE
#    the trader so its setUp + publish steps land first; the owner
#    will block in its settlement-poll loop waiting for the trader. ──
echo "── Phase 1/3: launching owner test on $OWNER_SERIAL"
cd "$ANDROID_DIR"
(
    ./gradlew :app:connectedAndroidTest \
        -Pandroid.testInstrumentationRunnerArguments.class=com.dsm.wallet.sofi.SoFiCrossDeviceOwnerTest \
        -PdeviceSerial="$OWNER_SERIAL" \
        > "$TMP_DIR/owner.gradle.log" 2>&1
    echo "$?" > "$TMP_DIR/owner.exit"
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

./gradlew :app:connectedAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=com.dsm.wallet.sofi.SoFiCrossDeviceTraderTest \
    -Pandroid.testInstrumentationRunnerArguments.owner_salt="$SALT" \
    -Pandroid.testInstrumentationRunnerArguments.owner_v1_b32="$V1" \
    -Pandroid.testInstrumentationRunnerArguments.owner_v2_b32="$V2" \
    -Pandroid.testInstrumentationRunnerArguments.output_token_b32="$OUT" \
    -PdeviceSerial="$TRADER_SERIAL" \
    > "$TMP_DIR/trader.gradle.log" 2>&1 &
TRADER_GRADLE_PID=$!

# ── Wait for trader test to finish ────────────────────────────────
wait $TRADER_GRADLE_PID
TRADER_EXIT=$?
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
