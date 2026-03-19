#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APK="${REPO_ROOT}/dsm_client/android/app/build/outputs/apk/debug/app-debug.apk"

if [[ ! -f "$APK" ]]; then
  echo "APK not found; building debug APK..."
  (cd "${REPO_ROOT}/dsm_client/android" && ./gradlew :app:assembleDebug --no-daemon --console=plain) || {
    echo "Gradle build failed" >&2
    exit 1
  }
fi

SERIALS=$(adb devices | awk '/[[:space:]]device$/{print $1}')
if [[ -z "${SERIALS}" ]]; then
  echo "No connected adb devices in 'device' state. Current list:" >&2
  adb devices -l
  exit 2
fi

echo "Detected devices: ${SERIALS}"

for d in ${SERIALS}; do
  echo "=== Installing on ${d} ==="

  # By default, do NOT uninstall. Uninstalling can fail spuriously on some devices
  # (e.g., DELETE_FAILED_INTERNAL_ERROR) and it's not needed for iterative dev.
  # To force uninstall first: DSM_UNINSTALL_FIRST=1 ./scripts/install_apk_connected_devices.sh
  if [[ "${DSM_UNINSTALL_FIRST:-0}" == "1" ]]; then
    adb -s "${d}" uninstall com.dsm.wallet || true
  fi

  if ! adb -s "${d}" install -r "${APK}"; then
    echo "Install failed on ${d}" >&2
    continue
  fi

  # Storage node APIs used by the app in local dev.
  for p in 8080 8081 8082 8083 8084; do
    adb -s "${d}" reverse "tcp:${p}" "tcp:${p}" || echo "reverse failed for ${d}:${p}" >&2
  done

  # Launch the actual launchable activity (verified via dumpsys/resolve-activity)
  adb -s "${d}" shell am start -n com.dsm.wallet/.ui.MainActivity || echo "Failed to start on ${d}" >&2
  echo "=== Done ${d} ==="
done
