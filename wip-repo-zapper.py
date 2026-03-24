#!/usr/bin/env python3
"""
balance-zapper-strict.py — Exact-allowlist sender-debit / canonical-balance issue indexer
──────────────────────────────────────────────────────────────────────────────────────────
Only dumps the small, explicit set of files relevant to:

- bilateral Bluetooth settlement
- canonical sender debit persistence
- wallet balance reload after restart
- ERA token balance sourcing
"""

import os
import sys
import argparse

DEFAULT_ALLOWLIST = [
    # Core bilateral settlement / canonical state mutation
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bilateral_settlement.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/core_sdk.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/token_state.rs",

    # Wallet / balance loading / route layer
    "dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/wallet_routes.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/transaction_routes.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bilateral_routes.rs",

    # Local persistence that may still affect displayed balances
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/transactions.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/bilateral_sessions.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/contacts.rs",

    # State/archive/checkpoint persistence if present in this layout
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/wallet_state.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/state_archive.rs",

    # JNI / bridge path that triggers wallet refresh
    "dsm_client/deterministic_state_machine/dsm_sdk/src/jni/transport.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/jni/ble_events.rs",

    # Android / frontend reload path
    "dsm_client/android/app/src/main/java/com/dsm/wallet/EventPoller.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt",

    # If your app still routes balance refresh through bridge events
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedBleBridge.kt",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedBleEvents.kt",
]

BALANCE_ALLOWLIST = [
    "dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/wallet_routes.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/transactions.rs",
]

CORE_ONLY_ALLOWLIST = [
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bilateral_settlement.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/core_sdk.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/token_state.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/wallet_routes.rs",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/transactions.rs",
    "dsm_client/android/app/src/main/java/com/dsm/wallet/EventPoller.kt",
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
        out_file.write("Strict balance Issue Repository Index\n")
        out_file.write(f"Repo root: {repo_root}\n")
        out_file.write(f"Mode: {'core-only' if args.core_only else 'full strict allowlist'}\n")
        out_file.write(f"Balance files: {'enabled' if args.with_balance and not args.core_only else 'disabled'}\n")
        out_file.write("=" * 80 + "\n\n")
        generate_index(files, out_file)
        write_contents(files, out_file)

    print(f"Wrote {len(files)} files to {output}", file=sys.stderr)

if __name__ == "__main__":
    main()