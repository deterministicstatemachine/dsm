#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Point the DSM wallets on this machine's phones at the developer's own
# storage set (make nodes-up), or open a connect code on them.
#
#   scripts/phones_local.sh point          every adb device and every booted iOS Simulator
#   scripts/phones_local.sh open <code>    open a dsm:connect/v1: code in each wallet
#
# Android (debug builds read a developer override; release builds never do):
#   - `adb reverse` for the five nodes (8080-8084) and the app's relay (8443),
#     so the phone reaches them at 127.0.0.1, the address their certificates name;
#   - the client config as files/dsm_env_config.override.toml and the set's CA
#     as files/dev-ca.pem (never files/ca.crt: the app rewrites that one with
#     the bundled fleet CA on every launch);
#   - the wallet restarted.
#
# iOS Simulator (Debug builds read <app Documents>/dsm_env_config.toml):
#   - the client config and dev-ca.pem copied into the wallet's Documents;
#   - the wallet restarted. The Simulator shares this Mac's network, so
#     127.0.0.1 reaches the nodes and the relay directly.
#
# DSM_ADB_TRANSPORT (an adb transport id) or DSM_SIM_UDID (a Simulator's
# UDID) limits it to that one device; with either set, only that kind of
# device is touched.
#
# A wallet that already made its identity on another storage set keeps it
# there: clear the app's data first (Android: adb shell pm clear com.dsm.wallet,
# then grant its Bluetooth permissions again; iOS: delete and reinstall).

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NET="$REPO/.dsm-dev/net"
APP_ID="com.dsm.wallet"
PORTS=(8080 8081 8082 8083 8084 8443)

android_transports() {
    if [ -n "${DSM_ADB_TRANSPORT:-}" ]; then echo "$DSM_ADB_TRANSPORT"; return 0; fi
    [ -z "${DSM_SIM_UDID:-}" ] || return 0
    command -v adb >/dev/null 2>&1 || return 0
    # Transport ids, not serials: wireless serials contain spaces.
    adb devices -l | awk '/ device /{for(i=1;i<=NF;i++) if($i ~ /^transport_id:/){sub("transport_id:","",$i); print $i}}'
}

booted_simulators() {
    if [ -n "${DSM_SIM_UDID:-}" ]; then echo "$DSM_SIM_UDID"; return 0; fi
    [ -z "${DSM_ADB_TRANSPORT:-}" ] || return 0
    command -v xcrun >/dev/null 2>&1 || return 0
    xcrun simctl list devices booted | sed -n 's/.*(\([0-9A-F-]\{36\}\)) (Booted).*/\1/p'
}

point_android() {
    local t="$1" p
    for p in "${PORTS[@]}"; do
        adb -t "$t" reverse "tcp:$p" "tcp:$p" >/dev/null
    done
    if ! adb -t "$t" shell run-as "$APP_ID" mkdir -p files 2>/dev/null; then
        echo "[phones] android transport $t: no debug build of $APP_ID installed (make install)" >&2
        return 1
    fi
    adb -t "$t" push "$NET/dsm_env_config.toml" /data/local/tmp/dsm_env_config.override.toml >/dev/null
    adb -t "$t" push "$NET/dev-ca.pem" /data/local/tmp/dev-ca.pem >/dev/null
    adb -t "$t" shell run-as "$APP_ID" cp /data/local/tmp/dsm_env_config.override.toml files/dsm_env_config.override.toml
    adb -t "$t" shell run-as "$APP_ID" cp /data/local/tmp/dev-ca.pem files/dev-ca.pem
    adb -t "$t" shell rm -f /data/local/tmp/dsm_env_config.override.toml /data/local/tmp/dev-ca.pem
    adb -t "$t" shell am force-stop "$APP_ID"
    adb -t "$t" shell am start -n "$APP_ID/.ui.MainActivity" >/dev/null
    echo "[phones] android transport $t: on the local set (adb reverse ${PORTS[*]})"
}

point_simulator() {
    local udid="$1" container
    if ! container="$(xcrun simctl get_app_container "$udid" "$APP_ID" data 2>/dev/null)"; then
        echo "[phones] simulator $udid: $APP_ID is not installed (make ios-simulator-run)" >&2
        return 1
    fi
    mkdir -p "$container/Documents"
    cp "$NET/dsm_env_config.toml" "$container/Documents/dsm_env_config.toml"
    cp "$NET/dev-ca.pem" "$container/Documents/dev-ca.pem"
    xcrun simctl terminate "$udid" "$APP_ID" >/dev/null 2>&1 || :
    xcrun simctl launch "$udid" "$APP_ID" >/dev/null
    echo "[phones] simulator $udid: on the local set"
}

point() {
    if [ ! -f "$NET/dsm_env_config.toml" ]; then
        echo "[phones] no local set yet: make nodes-up" >&2
        exit 1
    fi
    local found=0 failed=0 t udid
    for t in $(android_transports); do
        found=1
        point_android "$t" || failed=1
    done
    for udid in $(booted_simulators); do
        found=1
        point_simulator "$udid" || failed=1
    done
    if [ "$found" = 0 ]; then
        echo "[phones] no adb device and no booted iOS Simulator" >&2
        exit 1
    fi
    exit "$failed"
}

open_code() {
    local code="$1" found=0 t udid
    case "$code" in
        dsm:connect/v1:*) ;;
        *) echo "[phones] not a connect code: $code" >&2; exit 2 ;;
    esac
    for t in $(android_transports); do
        found=1
        adb -t "$t" shell am start -a android.intent.action.VIEW -d "'$code'" "$APP_ID" >/dev/null
        echo "[phones] android transport $t: opened the code"
    done
    for udid in $(booted_simulators); do
        found=1
        xcrun simctl openurl "$udid" "$code"
        echo "[phones] simulator $udid: opened the code"
    done
    if [ "$found" = 0 ]; then
        echo "[phones] no adb device and no booted iOS Simulator" >&2
        exit 1
    fi
}

case "${1:-}" in
    point) point ;;
    open) open_code "${2:?usage: $0 open <dsm:connect/v1:code>}" ;;
    *) echo "usage: $0 point | open <code>" >&2; exit 2 ;;
esac
