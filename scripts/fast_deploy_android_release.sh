#!/usr/bin/env bash
set -euo pipefail

# Fast deploy for DSM Android app — RELEASE (signed) variant.
# Same as fast_deploy_android.sh but builds assembleRelease.
# One prompt: the keystore password, checked against the keystore before Gradle
# runs. The keystore defaults to $HOME/dsm-release.p12, the key to dsm-release
# (or the keystore's only private key), the key password to the keystore password.

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
  DSM_KEYSTORE_PATH       Optional; defaults to $HOME/dsm-release.p12.
  DSM_KEY_ALIAS           Optional; defaults to dsm-release, or the keystore's only private key.
  DSM_KEY_PASSWORD        Optional key-entry password override; defaults to the keystore password.
  SERIALS="id1 id2"       Space-separated adb device serials. If not set, every device in
                          'device' state is used, addressed by its adb transport id.
USAGE
}

resolve_keystore_path() {
  export DSM_KEYSTORE_PATH="${DSM_KEYSTORE_PATH:-$HOME/dsm-release.p12}"
  if [[ ! -f "$DSM_KEYSTORE_PATH" ]]; then
    echo "[fast_deploy_release] ERROR: keystore not found at $DSM_KEYSTORE_PATH (set DSM_KEYSTORE_PATH)." >&2
    exit 1
  fi
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

  read -r -s -p "Keystore password ($DSM_KEYSTORE_PATH): " DSM_KEYSTORE_PASSWORD
  echo
  export DSM_KEYSTORE_PASSWORD
}

# The password opens the keystore and the key Gradle signs with is in it.
# Checked here, so a wrong password costs a prompt rather than a Gradle run.
check_keystore() {
  if ! command -v keytool >/dev/null 2>&1; then
    echo "[fast_deploy_release] keytool not on PATH; Gradle will check the password." >&2
    export DSM_KEY_ALIAS="${DSM_KEY_ALIAS:-dsm-release}"
    return 0
  fi
  local listing
  if ! listing="$(keytool -list -keystore "$DSM_KEYSTORE_PATH" -storepass:env DSM_KEYSTORE_PASSWORD 2>&1)"; then
    echo "[fast_deploy_release] $DSM_KEYSTORE_PATH refused that password." >&2
    return 1
  fi
  local keys wanted
  keys="$(awk -F', ' '/PrivateKeyEntry/{print $1}' <<<"$listing")"
  wanted="${DSM_KEY_ALIAS:-dsm-release}"
  if grep -qxF "$wanted" <<<"$keys"; then
    export DSM_KEY_ALIAS="$wanted"
  elif [[ -z "${DSM_KEY_ALIAS:-}" && "$(grep -c . <<<"$keys")" -eq 1 ]]; then
    export DSM_KEY_ALIAS="$keys"
  else
    echo "[fast_deploy_release] ERROR: no key named '$wanted' in $DSM_KEYSTORE_PATH. Its keys:" >&2
    sed 's/^/  /' <<<"$keys" >&2
    echo "[fast_deploy_release] Set DSM_KEY_ALIAS to one of them." >&2
    exit 1
  fi
  echo "[fast_deploy_release] Keystore opened; signing with key '$DSM_KEY_ALIAS'."
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
  resolve_keystore_path
  for attempt in 1 2 3; do
    prompt_keystore_password
    if check_keystore; then
      break
    fi
    if [[ ! -t 0 || $attempt -eq 3 ]]; then
      exit 1
    fi
    unset DSM_KEYSTORE_PASSWORD
  done
  export DSM_KEY_PASSWORD="${DSM_KEY_PASSWORD:-$DSM_KEYSTORE_PASSWORD}"
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

# The Android SDK's adb, ahead of any other on PATH: two adb versions share one
# server port and reset each other's connections.
SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
if [[ -x "$SDK_DIR/platform-tools/adb" ]]; then
  export PATH="$SDK_DIR/platform-tools:$PATH"
fi

# Each device is an adb selector, "-s SERIAL" or "-t TRANSPORT_ID". A device
# found by itself is addressed by its transport id: a wireless-debugging serial
# can hold a space ("adb-XXXX (2)._adb-tls-connect._tcp").
DEVICES=()
if [[ -n "${SERIALS:-}" ]]; then
  for s in $SERIALS; do
    DEVICES+=("-s $s")
  done
else
  while read -r t; do
    DEVICES+=("-t $t")
  done < <(adb devices -l | grep -E '[[:space:]]device[[:space:]]' | grep -oE 'transport_id:[0-9]+' | cut -d: -f2)
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
  echo "[fast_deploy_release] GCP mode: using bundled dsm_env_config.toml (the beta fleet: 5 GCP nodes)"
fi

FAILED=()
for d in "${DEVICES[@]}"; do
  read -r -a sel <<<"$d"
  label="$(adb "${sel[@]}" shell getprop ro.serialno 2>/dev/null | tr -d '\r\n' || true)"
  echo "=== ${label:-$d} ($d) ==="
  if [[ $SKIP_UNINSTALL -eq 0 ]]; then
    adb "${sel[@]}" uninstall com.dsm.wallet || true
  fi

  if ! adb "${sel[@]}" install -r "$APK"; then
    echo "[fast_deploy_release] Install FAILED on ${label:-$d}" >&2
    FAILED+=("${label:-$d}")
    continue
  fi

  if [[ $LOCAL_DEV -eq 1 ]]; then
    is_emu=$(adb "${sel[@]}" shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r\n')
    if [[ "$is_emu" == "1" ]]; then
      ENV_HOST="10.0.2.2"
    else
      ENV_HOST="127.0.0.1"
    fi
    for p in 8080 8081 8082 8083 8084 18443; do
      adb "${sel[@]}" reverse tcp:$p tcp:$p || echo "reverse failed for ${label:-$d}:$p"
    done
    ENV_TOML=$(mktemp /tmp/dsm_env_XXXXXX)
    cat >"$ENV_TOML" <<EOF
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
    adb "${sel[@]}" push "$ENV_TOML" /data/local/tmp/dsm_env_config.toml
    adb "${sel[@]}" shell run-as com.dsm.wallet mkdir -p files 2>/dev/null || true
    adb "${sel[@]}" shell run-as com.dsm.wallet cp /data/local/tmp/dsm_env_config.toml files/dsm_env_config.toml
    rm -f "$ENV_TOML"
    echo "[fast_deploy_release] Env config pushed to ${label:-$d} (host=$ENV_HOST)"
  else
    # GCP mode: remove any stale local override so the app uses the bundled GCP config.
    adb "${sel[@]}" shell run-as com.dsm.wallet rm -f files/dsm_env_config.override.toml 2>/dev/null || true
    adb "${sel[@]}" shell run-as com.dsm.wallet rm -f files/dsm_env_config.local.toml 2>/dev/null || true
    echo "[fast_deploy_release] Cleared stale overrides on ${label:-$d} (app will use bundled GCP config)"
  fi

  if [[ $START_APP -eq 1 ]]; then
    adb "${sel[@]}" shell am force-stop com.dsm.wallet 2>/dev/null || true
    adb "${sel[@]}" shell am start -n com.dsm.wallet/.ui.MainActivity || echo "Failed to start on ${label:-$d}"
  fi

done

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "[fast_deploy_release] Install failed on: ${FAILED[*]}" >&2
  exit 1
fi
echo "[fast_deploy_release] Done."
