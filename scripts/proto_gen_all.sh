#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Unified protobuf generation from the single source of truth: proto/dsm_app.proto
# Generates:
#  - TypeScript (frontend/src/proto)
#  - Rust (build-time outputs via cargo build --features proto)
#  - Android (Gradle generateProto)
#
# NOTE: Rust uses build.rs + OUT_DIR generation, so there is no committed Rust file to diff;
# this script ensures the build is exercised and stays in sync with proto changes.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROTO_SCHEMA="$ROOT_DIR/proto/dsm_app.proto"

if [[ ! -f "$PROTO_SCHEMA" ]]; then
  echo "❌ proto schema not found: $PROTO_SCHEMA" >&2
  exit 1
fi

echo "🔧 DSM unified proto generation"
echo "   schema: $PROTO_SCHEMA"

# -------------------------
# TypeScript (frontend)
# -------------------------
echo "🧩 Generating TypeScript protobufs (protoc-gen-es)..."
(
  cd "$ROOT_DIR/dsm_client/frontend"
  # uses package.json script: proto:gen -> npx protoc ... -I ../../proto ../../proto/dsm_app.proto
  npm run -s proto:gen
)

# -------------------------
# Rust + Android (existing script)
# -------------------------
echo "🦀📱 Generating Rust (build-time) + Android protos..."
(
  cd "$ROOT_DIR"
  ./dsm_client/scripts/build-proto.sh
)

echo "✅ Proto generation complete"
