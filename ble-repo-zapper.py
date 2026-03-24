#!/usr/bin/env python3
"""
ble-zapper-strict.py — Exact-allowlist BLE issue indexer
────────────────────────────────────────────────────────
Only dumps a very small, explicit set of files related to the current BLE issue.

Default target set:
- Rust BLE transport / bridge / bilateral transport-adjacent files
- Kotlin BLE runtime files
- BLE persistence files
- Optional wallet/balance symptom files

Usage:
    python3 ble-zapper-strict.py /path/to/repo -o ble_dump.txt

Optional:
    python3 ble-zapper-strict.py /path/to/repo -o ble_dump.txt --with-balance
"""

import os
import sys
import argparse
from pathlib import Path

# EXACT relative path suffixes to include.
# Keep this small and brutal.
DEFAULT_ALLOWLIST = [
    # Rust BLE / transport / bridge
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/android_ble_bridge.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/ble_frame_coordinator.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/pairing_orchestrator.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bluetooth_transport.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/secure_ble_transport.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/jni/ble_bridge.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/jni/ble_events.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/jni/transport.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs",

    # Rust persistence directly relevant to BLE transport symptoms
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/ble_chunk_buffer.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/online_outbox.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/bilateral_sessions.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/contacts.rs",

    # Kotlin / Android BLE runtime
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BleEventRelay.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BleOutboxRepository.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeBleHandler.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeEncoding.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeEnvelopeCodec.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedBleBridge.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedBleEvents.kt",

    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleAdvertiser.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleConstants.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleCoordinator.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleDiagEvent.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleDiagnostics.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleOperationDispatcher.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleOutbox.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleScanner.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleSessionEvent.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleSessionMode.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleSessionState.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/GattClientSession.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/GattServerHost.kt",

    "dsm_client/android/app/src/main/java/com/dsm/wallet/service/BleBackgroundService.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/permissions/BluetoothPermissionHelper.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/EventPoller.kt",
]

BALANCE_ALLOWLIST = [
    "dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/wallet_routes.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/transactions.rs",
]

# If you want even less, use --core-only.
CORE_ONLY_ALLOWLIST = [
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/android_ble_bridge.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/ble_frame_coordinator.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/pairing_orchestrator.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/ble_chunk_buffer.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/online_outbox.rs",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedBleBridge.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/BleCoordinator.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/GattClientSession.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/ble/GattServerHost.kt",
]

def norm(p: str) -> str:
    return os.path.normpath(p).replace("\\", "/")

def resolve_files(repo_root: str, allowlist: list[str]) -> list[str]:
    repo_root = norm(repo_root)
    found = []
    missing = []

    for rel in allowlist:
        full = norm(os.path.join(repo_root, rel))
        if os.path.isfile(full):
            found.append(full)
        else:
            missing.append(rel)

    if missing:
        print("Missing files:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)

    return found

def generate_index(files: list[str], out_file):
    out_file.write("=== File Index ===\n\n")
    for i, path in enumerate(files, start=1):
        out_file.write(f"{i}. {path}\n")
    out_file.write(f"\nTotal files: {len(files)}\n")
    out_file.write("\n" + "=" * 80 + "\n\n")

def write_contents(files: list[str], out_file):
    for i, path in enumerate(files, start=1):
        out_file.write(f"Index: {i}\n")
        out_file.write(f"File: {path}\n\n")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                out_file.write(f.read())
        except Exception as e:
            out_file.write(f"Error reading file: {e}\n")
        out_file.write("\n" + "-" * 80 + "\n\n")

def main():
    parser = argparse.ArgumentParser(description="Strict BLE issue repo indexer.")
    parser.add_argument("repo_root", help="Repository root")
    parser.add_argument("-o", "--output", required=True, help="Output file")
    parser.add_argument("--with-balance", action="store_true",
                        help="Include wallet_routes.rs and transactions.rs")
    parser.add_argument("--core-only", action="store_true",
                        help="Only include the smallest core BLE file set")
    args = parser.parse_args()

    repo_root = norm(args.repo_root)
    output = norm(args.output)

    if not os.path.isdir(repo_root):
        print(f"Repo root does not exist: {repo_root}", file=sys.stderr)
        sys.exit(1)

    if args.core_only:
        allowlist = CORE_ONLY_ALLOWLIST[:]
    else:
        allowlist = DEFAULT_ALLOWLIST[:]

    if args.with_balance and not args.core_only:
        allowlist.extend(BALANCE_ALLOWLIST)

    files = resolve_files(repo_root, allowlist)

    if not files:
        print("No files found from allowlist.", file=sys.stderr)
        sys.exit(1)

    with open(output, "w", encoding="utf-8") as out_file:
        out_file.write("Strict BLE Issue Repository Index\n")
        out_file.write(f"Repo root: {repo_root}\n")
        out_file.write(f"Mode: {'core-only' if args.core_only else 'full strict allowlist'}\n")
        out_file.write(f"Balance files: {'enabled' if args.with_balance and not args.core_only else 'disabled'}\n")
        out_file.write("=" * 80 + "\n\n")
        generate_index(files, out_file)
        write_contents(files, out_file)

    print(f"Wrote {len(files)} files to {output}", file=sys.stderr)

if __name__ == "__main__":
    main()