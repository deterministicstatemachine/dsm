#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

echo "[proto-guard] Verifying only canonical proto exists (proto/dsm_app.proto) and no stray copies..."

canonical="$ROOT_DIR/proto/dsm_app.proto"
if [[ ! -f "$canonical" ]]; then
  echo "[proto-guard] ERROR: Missing canonical proto at $canonical" >&2
  exit 1
fi

# Disallow ANY .proto files outside the canonical location, including third_party/vendor
# Exclude node_modules since they may contain third-party proto files
violations=$(git ls-files "**/*.proto" | grep -v "^proto/dsm_app.proto$" | grep -v "^node_modules/" || true)
if [[ -n "$violations" ]]; then
  echo "[proto-guard] ERROR: Found additional .proto files in repo (ALL proto files must be removed except canonical):" >&2
  echo "$violations" >&2
  exit 1
fi

# Ensure Android proto directory does NOT exist at all
android_proto_dir="$ROOT_DIR/dsm_client/android/app/src/main/proto"
if [[ -e "$android_proto_dir" ]]; then
  echo "[proto-guard] ERROR: $android_proto_dir must be completely removed - no symlinks or directories allowed" >&2
  exit 1
fi

# Ensure Rust proto directory does NOT exist at all
rust_proto_dir="$ROOT_DIR/dsm_client/deterministic_state_machine/proto"
if [[ -e "$rust_proto_dir" ]]; then
  echo "[proto-guard] ERROR: $rust_proto_dir must be completely removed - no directories allowed" >&2
  exit 1
fi

echo "[proto-guard] OK - Single source of truth enforced"
