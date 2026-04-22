#!/usr/bin/env bash
set -euo pipefail

# Fast deploy for DSM Android app — RELEASE (signed) variant.
# Same as fast_deploy_android.sh but builds assembleRelease.
# Prompts for the keystore path, key alias, and signing passwords when running interactively.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_DIR="$ROOT_DIR/dsm_client/android"
APK="$ANDROID_DIR/app/build/outputs/apk/release/app-release.apk"

SKIP_BUILD=0
BUILD_ONLY=0
SKIP_UNINSTALL=1
START_APP=1
LOCAL_DEV=0

usage() {
  cat <<'USAGE'
Usage: scripts/fast_deploy_android_release.sh [options]

Options:
  --no-build         Skip gradle build step (assumes APK exists)
  --build-only       Build the signed release APK, then exit without adb install
  --uninstall        Uninstall app before install (clears data)
  --no-start         Don't launch MainActivity
  --local            Local dev mode: push localhost env config override + adb reverse ports

Environment:
  DSM_KEYSTORE_PASSWORD   Optional; if unset, the script prompts on an interactive TTY.
  DSM_KEYSTORE_PATH       Optional keystore path override; if unset, the script prompts and defaults to $HOME/dsm-release.p12.
  DSM_KEY_ALIAS           Optional key alias override; if unset, the script prompts and defaults to dsm-release.
  DSM_KEY_PASSWORD        Optional key-entry password override; defaults to the keystore password.
  SERIALS="id1 id2"       Space-separated adb device serials. If not set, auto-detect.
USAGE
}

prompt_keystore_path() {
  if [[ -n "${DSM_KEYSTORE_PATH:-}" ]]; then
    return 0
  fi

  local default_path="$HOME/dsm-release.p12"

  if [[ ! -t 0 ]]; then
    export DSM_KEYSTORE_PATH="$default_path"
    return 0
  fi

  read -r -p "DSM Android keystore path [$default_path]: " DSM_KEYSTORE_PATH
  DSM_KEYSTORE_PATH="${DSM_KEYSTORE_PATH:-$default_path}"
  export DSM_KEYSTORE_PATH
}

prompt_key_alias() {
  if [[ -n "${DSM_KEY_ALIAS:-}" ]]; then
    return 0
  fi

  if [[ ! -t 0 ]]; then
    export DSM_KEY_ALIAS="dsm-release"
    return 0
  fi

  read -r -p "DSM key alias [dsm-release]: " DSM_KEY_ALIAS
  DSM_KEY_ALIAS="${DSM_KEY_ALIAS:-dsm-release}"
  export DSM_KEY_ALIAS
}

prompt_keystore_password() {
  if [[ -n "${DSM_KEYSTORE_PASSWORD:-}" ]]; then
    return 0
  fi

  if [[ ! -t 0 ]]; then
    echo "[fast_deploy_release] ERROR: no interactive TTY for keystore password prompt." >&2
    echo "[fast_deploy_release] Run this script from a terminal or set DSM_KEYSTORE_PASSWORD for non-interactive use." >&2
    exit 1
  fi

  local keystore_path="${DSM_KEYSTORE_PATH:-$HOME/dsm-release.p12}"
  local key_alias="${DSM_KEY_ALIAS:-dsm-release}"

  if [[ ! -f "$keystore_path" ]]; then
    echo "[fast_deploy_release] ERROR: keystore not found at $keystore_path" >&2
    exit 1
  fi

  read -r -s -p "DSM keystore password for $key_alias ($keystore_path): " DSM_KEYSTORE_PASSWORD
  echo
  if [[ -z "$DSM_KEYSTORE_PASSWORD" ]]; then
    echo "[fast_deploy_release] ERROR: empty keystore password." >&2
    exit 1
  fi
  export DSM_KEYSTORE_PASSWORD
}

prompt_key_password() {
  if [[ -n "${DSM_KEY_PASSWORD:-}" ]]; then
    return 0
  fi

  if [[ ! -t 0 ]]; then
    return 0
  fi

  read -r -s -p "DSM key password for $DSM_KEY_ALIAS (press Enter to reuse keystore password): " DSM_KEY_PASSWORD
  echo
  if [[ -z "$DSM_KEY_PASSWORD" ]]; then
    DSM_KEY_PASSWORD="$DSM_KEYSTORE_PASSWORD"
  fi
  export DSM_KEY_PASSWORD
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) SKIP_BUILD=1; shift ;;
    --build-only) BUILD_ONLY=1; shift ;;
    --uninstall) SKIP_UNINSTALL=0; shift ;;
    --no-start) START_APP=0; shift ;;
    --local) LOCAL_DEV=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

if [[ $SKIP_BUILD -eq 0 ]]; then
  prompt_keystore_path
  prompt_key_alias
  prompt_keystore_password
  prompt_key_password
  echo "[fast_deploy_release] Gradle assembleRelease (incremental)…"
  (cd "$ANDROID_DIR" && ./gradlew --stop && ./gradlew :app:assembleRelease --no-daemon --console=plain)
fi

if [[ ! -f "$APK" ]]; then
  echo "[fast_deploy_release] APK not found: $APK" >&2
  exit 1
fi

if [[ $BUILD_ONLY -eq 1 ]]; then
  echo "[fast_deploy_release] Build-only mode complete: $APK"
  exit 0
fi

if [[ -n "${SERIALS:-}" ]]; then
  # shellcheck disable=SC2206
  DEVICES=($SERIALS)
else
  mapfile -t DEVICES < <(adb devices | awk '/\tdevice$/{print $1}')
fi

if [[ ${#DEVICES[@]} -eq 0 ]]; then
  echo "[fast_deploy_release] No adb devices in 'device' state." >&2
  adb devices -l || true
  exit 2
fi

echo "[fast_deploy_release] APK: $APK"
echo "[fast_deploy_release] Devices: ${DEVICES[*]}"

if [[ $LOCAL_DEV -eq 1 ]]; then
  _nodes_ok=0
  for _p in 8080 8081 8082 8083 8084; do
    if curl -sf --max-time 2 "http://127.0.0.1:$_p/health" >/dev/null 2>&1; then
      _nodes_ok=1; break
    fi
  done
  if [[ $_nodes_ok -eq 0 ]]; then
    echo ""
    echo "WARNING: local storage nodes do not appear to be running (no response on 8080-8084)."
    echo "         Genesis will fail. Start them with: make nodes-up"
    echo ""
  fi
else
  echo "[fast_deploy_release] GCP mode: using bundled dsm_env_config.toml (6 GCP nodes)"
fi

for d in "${DEVICES[@]}"; do
  echo "=== $d ==="
  if [[ $SKIP_UNINSTALL -eq 0 ]]; then
    adb -s "$d" uninstall com.dsm.wallet || true
  fi

  adb -s "$d" install -r "$APK"

  if [[ $LOCAL_DEV -eq 1 ]]; then
    is_emu=$(adb -s "$d" shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r\n')
    if [[ "$is_emu" == "1" ]]; then
      ENV_HOST="10.0.2.2"
    else
      ENV_HOST="127.0.0.1"
    fi
    for p in 8080 8081 8082 8083 8084 18443; do
      adb -s "$d" reverse tcp:$p tcp:$p || echo "reverse failed for $d:$p"
    done
    ENV_TOML=$(mktemp /tmp/dsm_env_XXXXXX)
    cat >"$ENV_TOML" <<EOF
protocol = "http"
lan_ip = "$ENV_HOST"
ports = [8080, 8081, 8082, 8083, 8084]
allow_localhost = true
bitcoin_network = "signet"
dbtc_min_confirmations = 1
dbtc_min_vault_balance_sats = 546

[[nodes]]
name = "storage-node-1"
endpoint = "http://$ENV_HOST:8080"

[[nodes]]
name = "storage-node-2"
endpoint = "http://$ENV_HOST:8081"

[[nodes]]
name = "storage-node-3"
endpoint = "http://$ENV_HOST:8082"

[[nodes]]
name = "storage-node-4"
endpoint = "http://$ENV_HOST:8083"

[[nodes]]
name = "storage-node-5"
endpoint = "http://$ENV_HOST:8084"
EOF
    adb -s "$d" push "$ENV_TOML" /data/local/tmp/dsm_env_config.toml
    adb -s "$d" shell run-as com.dsm.wallet mkdir -p files 2>/dev/null || true
    adb -s "$d" shell run-as com.dsm.wallet cp /data/local/tmp/dsm_env_config.toml files/dsm_env_config.toml
    rm -f "$ENV_TOML"
    echo "[fast_deploy_release] Env config pushed to $d (host=$ENV_HOST)"
  else
    # GCP mode: remove any stale local override so the app uses the bundled GCP config.
    adb -s "$d" shell run-as com.dsm.wallet rm -f files/dsm_env_config.override.toml 2>/dev/null || true
    adb -s "$d" shell run-as com.dsm.wallet rm -f files/dsm_env_config.local.toml 2>/dev/null || true
    echo "[fast_deploy_release] Cleared stale overrides on $d (app will use bundled GCP config)"
  fi

  if [[ $START_APP -eq 1 ]]; then
    adb -s "$d" shell am force-stop com.dsm.wallet 2>/dev/null || true
    adb -s "$d" shell am start -n com.dsm.wallet/.ui.MainActivity || echo "Failed to start on $d"
  fi

done

echo "[fast_deploy_release] Done."
