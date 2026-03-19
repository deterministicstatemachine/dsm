#!/usr/bin/env bash
# Enable ADB reverse port forwarding for DSM local storage nodes
# Usage:
#   scripts/adb_reverse_storage.sh            # uses first connected device
#   SERIAL=<device-serial> scripts/adb_reverse_storage.sh

set -euo pipefail

SERIAL=${SERIAL:-""}

if [ -z "${SERIAL}" ]; then
  SERIAL=$(adb devices -l | awk 'NR==2 {print $1}')
fi

if [ -z "${SERIAL}" ] || [ "${SERIAL}" = "device" ]; then
  echo "No device detected. Connect a device and run 'adb devices' first." >&2
  exit 1
fi

echo "Using device serial: ${SERIAL}"

# Local storage node ports
PORTS=(8080 8081 8082 8083 8084)

for p in "${PORTS[@]}"; do
  echo "adb -s ${SERIAL} reverse tcp:${p} tcp:${p}"
  adb -s "${SERIAL}" reverse tcp:${p} tcp:${p}
done

echo "Active reverse mappings:"
adb -s "${SERIAL}" reverse --list || true
