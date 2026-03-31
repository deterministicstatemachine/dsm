#!/usr/bin/env zsh
# Push DSM env config to devices/emulators.
#
# Modes:
#   --local   (default)  Generate localhost config + adb reverse ports (dev nodes)
#   --aws               Push pre-built AWS config + self-signed CA cert (production nodes)
#   --gcp               Push pre-built GCP config + self-signed CA cert (production nodes)
#
# Usage:
#   ./push_env_override.sh             # local dev nodes (default)
#   ./push_env_override.sh --local     # same as above, explicit
#   ./push_env_override.sh --aws       # AWS storage nodes
#   ./push_env_override.sh --gcp       # GCP storage nodes

set -e

APP_PKG="com.dsm.wallet"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APK_PATH="$REPO_ROOT/dsm_client/android/app/build/outputs/apk/debug/app-debug.apk"
PORTS=(8080 8081 8082 8083 8084)

# --- Mode selection ---
MODE="local"
for arg in "$@"; do
  case "$arg" in
    --aws)   MODE="aws" ;;
    --gcp)   MODE="gcp" ;;
    --local) MODE="local" ;;
    --help|-h)
      echo "Usage: $0 [--local|--aws|--gcp]"
      echo "  --local  (default) Local dev nodes via adb reverse"
      echo "  --aws    AWS storage nodes (6 nodes, 3 regions)"
      echo "  --gcp    GCP storage nodes (6 nodes, 3 regions)"
      exit 0
      ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

echo "Mode: $MODE"

# --- Remote config paths ---
AWS_CONFIG="$REPO_ROOT/scripts/dsm_env_config.aws.toml"
GCP_CONFIG="$REPO_ROOT/scripts/dsm_env_config.gcp.toml"
CA_CERT="$REPO_ROOT/dsm_storage_node/deploy/nodes/ca/ca.crt"
CA_CERT_SCRIPTS="$REPO_ROOT/scripts/ca.crt"

# Resolve REMOTE_CONFIG and CA cert based on mode
REMOTE_CONFIG=""
if [[ "$MODE" == "aws" ]]; then
  REMOTE_CONFIG="$AWS_CONFIG"
elif [[ "$MODE" == "gcp" ]]; then
  REMOTE_CONFIG="$GCP_CONFIG"
fi

if [[ -n "$REMOTE_CONFIG" ]]; then
  if [[ ! -f "$REMOTE_CONFIG" ]]; then
    echo "Config not found at $REMOTE_CONFIG"
    echo "Run the deployment first (deploy/provision_${MODE}.sh)"
    exit 1
  fi
  # Try deploy/nodes CA first, fall back to scripts/ca.crt
  if [[ ! -f "$CA_CERT" ]]; then
    if [[ -f "$CA_CERT_SCRIPTS" ]]; then
      CA_CERT="$CA_CERT_SCRIPTS"
    else
      echo "CA cert not found at $CA_CERT or $CA_CERT_SCRIPTS"
      echo "Run deploy/generate_node_configs.sh first to generate TLS certs"
      exit 1
    fi
  fi
fi

# --- Local mode: generate config ---
make_env_toml() {
  local host="$1"
  cat <<EOF
protocol = "http"
lan_ip = "$host"
ports = [${PORTS[1]}, ${PORTS[2]}, ${PORTS[3]}, ${PORTS[4]}, ${PORTS[5]}]
allow_localhost = true
bitcoin_network = "signet"
dbtc_min_confirmations = 1
dbtc_min_vault_balance_sats = 546

[[nodes]]
name = "storage-node-1"
endpoint = "http://$host:${PORTS[1]}"

[[nodes]]
name = "storage-node-2"
endpoint = "http://$host:${PORTS[2]}"

[[nodes]]
name = "storage-node-3"
endpoint = "http://$host:${PORTS[3]}"

[[nodes]]
name = "storage-node-4"
endpoint = "http://$host:${PORTS[4]}"

[[nodes]]
name = "storage-node-5"
endpoint = "http://$host:${PORTS[5]}"
EOF
}

# --- Gather devices ---
serials=( $(adb devices | awk '/\tdevice$/{print $1}') )
if [[ ${#serials[@]} -eq 0 ]]; then
  echo "No connected adb devices in device state."
  adb devices -l
  exit 2
fi

echo "Detected devices: $serials"

for d in $serials; do
  echo "=== Processing $d ==="

  # Ensure app-private files dir exists
  adb -s "$d" shell run-as "$APP_PKG" mkdir -p files || true

  if [[ "$MODE" == "aws" || "$MODE" == "gcp" ]]; then
    # --- Remote mode (AWS or GCP) ---
    echo "Pushing $MODE storage node config to $d..."
    adb -s "$d" push "$REMOTE_CONFIG" /data/local/tmp/dsm_env_config.toml
    adb -s "$d" shell run-as "$APP_PKG" cp /data/local/tmp/dsm_env_config.toml files/dsm_env_config.toml

    echo "Pushing CA cert to $d..."
    adb -s "$d" push "$CA_CERT" /data/local/tmp/ca.crt
    adb -s "$d" shell run-as "$APP_PKG" cp /data/local/tmp/ca.crt files/ca.crt

    # Remove any stale adb reverse ports (not needed for remote)
    for p in $PORTS 18443; do
      adb -s "$d" reverse --remove tcp:$p 2>/dev/null || true
    done

    echo "Config: 6 $MODE storage nodes (HTTPS + custom CA)"
    adb -s "$d" shell run-as "$APP_PKG" ls -l files/dsm_env_config.toml files/ca.crt

  else
    # --- Local mode ---
    is_emulator=$(adb -s "$d" shell getprop ro.kernel.qemu | tr -d '\r' | tr -d '\n')
    if [[ "$is_emulator" == "1" ]]; then
      host="10.0.2.2"
      echo "Device $d identified as emulator (ro.kernel.qemu=1). Using host=$host"
    else
      host="127.0.0.1"
      echo "Device $d identified as physical. Using host=$host and setting reverse ports"
      for p in $PORTS 18443; do
        adb -s "$d" reverse tcp:$p tcp:$p || echo "reverse failed for $d:$p"
      done
    fi

    # Build env TOML in temp
    _tmpbase=$(mktemp /tmp/dsm_env_XXXXXX)
    tmpfile="${_tmpbase}.toml"
    mv "$_tmpbase" "$tmpfile"
    make_env_toml "$host" > "$tmpfile"
    echo "Generated local dev config:"; head -10 "$tmpfile"

    adb -s "$d" push "$tmpfile" /data/local/tmp/dsm_env_config.toml
    adb -s "$d" shell run-as "$APP_PKG" cp /data/local/tmp/dsm_env_config.toml files/dsm_env_config.toml
    adb -s "$d" shell run-as "$APP_PKG" ls -l files/dsm_env_config.toml
    rm -f "$tmpfile"

    echo "Config: 5 local dev nodes (HTTP via adb reverse)"
  fi

  # Uninstall/install APK if not present
  pm_out=$(adb -s "$d" shell pm list packages | grep -c "$APP_PKG" || true)
  if [[ "$pm_out" == "0" ]]; then
    echo "App not installed on $d; installing APK..."
    adb -s "$d" install -r "$APK_PATH" || echo "Install failed; continuing"
  fi

  echo "Restarting app on $d..."
  adb -s "$d" shell am force-stop "$APP_PKG" || true
  adb -s "$d" shell am start -n "$APP_PKG"/.ui.MainActivity || echo "Failed to start on $d"

  echo "Verifying startup logs for $d..."
  sleep 2
  if [[ "$MODE" == "aws" || "$MODE" == "gcp" ]]; then
    adb -s "$d" logcat -d | grep -iE "(storage node|ca cert|6 storage|appState changed to: wallet_ready)" | tail -15 || true
  else
    adb -s "$d" logcat -d | grep -E "(Using 5 storage nodes|appState changed to: wallet_ready|Genesis.*published)" | tail -15 || true
  fi
  echo "=== Done $d ==="
  echo
done

echo "All devices configured for $MODE mode."
