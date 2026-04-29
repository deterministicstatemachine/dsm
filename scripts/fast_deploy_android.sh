#!/usr/bin/env bash
set -euo pipefail

# Fast deploy for DSM Android app.
# Goals:
# - Avoid full workspace rebuilds unless needed
# - Prefer incremental Gradle build
# - Install with -r (replace) and reuse adb reverse
# - Optional skip uninstall to preserve app data when desired

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_DIR="$ROOT_DIR/dsm_client/android"
APK="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"

SKIP_BUILD=0
SKIP_UNINSTALL=1
SKIP_REVERSE=1        # default: GCP nodes are reachable directly; no adb reverse needed
START_APP=1
LOCAL_DEV=0           # --local: push localhost override config + set up adb reverse

usage() {
  cat <<'USAGE'
Usage: scripts/fast_deploy_android.sh [options]

Options:
  --no-build         Skip gradle build step (assumes APK exists)
  --uninstall        Uninstall app before install (clears data)
  --no-start         Don't launch MainActivity
  --local            Local dev mode: push localhost env config override + adb reverse ports

Environment:
  SERIALS="id1 id2"  Space-separated adb device serials. If not set, auto-detect.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) SKIP_BUILD=1; shift ;;
    --uninstall) SKIP_UNINSTALL=0; shift ;;
    --no-reverse) SKIP_REVERSE=1; shift ;;   # kept for compat, already default
    --no-start) START_APP=0; shift ;;
    --local) LOCAL_DEV=1; SKIP_REVERSE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

if [[ $SKIP_BUILD -eq 0 ]]; then
  echo "[fast_deploy] Gradle assembleDebug (incremental)…"
  (cd "$ANDROID_DIR" && ./gradlew :app:assembleDebug --no-daemon --console=plain)
fi

if [[ ! -f "$APK" ]]; then
  echo "[fast_deploy] APK not found: $APK" >&2
  exit 1
fi

if [[ -n "${SERIALS:-}" ]]; then
  # shellcheck disable=SC2206
  DEVICES=($SERIALS)
else
  mapfile -t DEVICES < <(adb devices | awk '/\tdevice$/{print $1}')
fi

if [[ ${#DEVICES[@]} -eq 0 ]]; then
  echo "[fast_deploy] No adb devices in 'device' state." >&2
  adb devices -l || true
  exit 2
fi

echo "[fast_deploy] APK: $APK"
echo "[fast_deploy] Devices: ${DEVICES[*]}"

if [[ $LOCAL_DEV -eq 1 ]]; then
  # Warn if local storage nodes are not running — genesis will fail without them.
  _nodes_ok=0
  for _p in 8080 8081 8082 8083 8084; do
    if curl -sf --max-time 2 "http://127.0.0.1:$_p/health" >/dev/null 2>&1; then
      _nodes_ok=1; break
    fi
  done
  if [[ $_nodes_ok -eq 0 ]]; then
    echo ""
    echo "WARNING: local storage nodes do not appear to be running (no response on 8080-8084)."
    echo "         Genesis will fail. Start them with: cd dsm_storage_node && ./scripts/dev/start_dev_nodes.sh"
    echo ""
  fi
else
  echo "[fast_deploy] GCP mode: using bundled dsm_env_config.toml (6 GCP nodes, no adb reverse)"
fi

for d in "${DEVICES[@]}"; do
  echo "=== $d ==="
  if [[ $SKIP_UNINSTALL -eq 0 ]]; then
    adb -s "$d" uninstall com.dsm.wallet || true
  fi

  adb -s "$d" install -r "$APK"

  if [[ $SKIP_REVERSE -eq 0 ]]; then
    for p in 8080 8081 8082 8083 8084 18443; do
      adb -s "$d" reverse tcp:$p tcp:$p || echo "reverse failed for $d:$p"
    done
  fi

  if [[ $LOCAL_DEV -eq 1 ]]; then
    # Local dev: push a localhost override so the app reaches nodes via adb reverse.
    is_emu=$(adb -s "$d" shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r\n')
    if [[ "$is_emu" == "1" ]]; then
      ENV_HOST="10.0.2.2"
    else
      ENV_HOST="127.0.0.1"
    fi
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
    echo "[fast_deploy] Env config pushed to $d (host=$ENV_HOST)"
  else
    # GCP mode: remove any stale local overrides so the app uses the bundled GCP config.
    adb -s "$d" shell run-as com.dsm.wallet rm -f files/dsm_env_config.override.toml 2>/dev/null || true
    adb -s "$d" shell run-as com.dsm.wallet rm -f files/dsm_env_config.local.toml 2>/dev/null || true
    echo "[fast_deploy] Cleared stale overrides on $d (app will use bundled GCP config)"
  fi

  if [[ $START_APP -eq 1 ]]; then
    adb -s "$d" shell am start -n com.dsm.wallet/.ui.MainActivity || echo "Failed to start on $d"
  fi

done

echo "[fast_deploy] Done."
