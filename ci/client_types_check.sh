#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The clients' protobuf types are committed, so both clients install with no
# protobuf compiler (a developer needs neither protoc nor a clone of DSM):
#
#   clients/typescript/src/generated/dsm_app_pb.ts     protoc-gen-es 1.10.1 (pinned in package-lock.json)
#   clients/python/dsm_app_client/generated/dsm_app_pb2.py
#                                                      protoc 29.0, from grpcio-tools 1.71.0
#
# This regenerates both from proto/dsm_app.proto with those pinned generators
# and fails on any difference, so a committed type cannot drift from the
# schema. --write puts the regenerated files in place instead (make
# client-types, after a change to the proto).
#
# Needs protoc (any version: protoc-gen-es's output does not depend on it),
# Node.js 20+, and a Python that grpcio-tools 1.71.0 has wheels for (3.9 to
# 3.13); DSM_TYPES_PYTHON names one, else python3.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WRITE=""
[ "${1:-}" = "--write" ] && WRITE=1
TS_DIR="$REPO/clients/typescript"
TS_FILE="src/generated/dsm_app_pb.ts"
PY_FILE="$REPO/clients/python/dsm_app_client/generated/dsm_app_pb2.py"
GRPCIO_TOOLS="grpcio-tools==1.71.0"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
failed=0

# ---- TypeScript ---------------------------------------------------------------
(cd "$TS_DIR" && npm ci --no-audit --no-fund --silent)
mkdir -p "$WORK/ts"
protoc --plugin=protoc-gen-es="$TS_DIR/node_modules/.bin/protoc-gen-es" \
    --es_out=import_extension=.js:"$WORK/ts" --es_opt=target=ts \
    -I "$REPO/proto" "$REPO/proto/dsm_app.proto"
if [ -n "$WRITE" ]; then
    cp "$WORK/ts/dsm_app_pb.ts" "$TS_DIR/$TS_FILE"
    echo "[client-types] wrote clients/typescript/$TS_FILE"
elif ! cmp -s "$WORK/ts/dsm_app_pb.ts" "$TS_DIR/$TS_FILE"; then
    echo "[client-types] clients/typescript/$TS_FILE differs from what proto/dsm_app.proto generates:" >&2
    diff -u "$TS_DIR/$TS_FILE" "$WORK/ts/dsm_app_pb.ts" | head -40 >&2 || :
    failed=1
fi

# ---- Python -------------------------------------------------------------------
"${DSM_TYPES_PYTHON:-python3}" -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install --quiet --disable-pip-version-check "$GRPCIO_TOOLS"
mkdir -p "$WORK/py"
"$WORK/venv/bin/python" -m grpc_tools.protoc -I "$REPO/proto" --python_out="$WORK/py" "$REPO/proto/dsm_app.proto"
if [ -n "$WRITE" ]; then
    cp "$WORK/py/dsm_app_pb2.py" "$PY_FILE"
    echo "[client-types] wrote ${PY_FILE#"$REPO/"}"
elif ! cmp -s "$WORK/py/dsm_app_pb2.py" "$PY_FILE"; then
    echo "[client-types] ${PY_FILE#"$REPO/"} differs from what proto/dsm_app.proto generates:" >&2
    diff -u "$PY_FILE" "$WORK/py/dsm_app_pb2.py" | head -40 >&2 || :
    failed=1
fi

if [ "$failed" != 0 ]; then
    echo "[client-types] run make client-types and commit the result" >&2
    exit 1
fi
[ -n "$WRITE" ] || echo "[client-types] both clients' committed types are what proto/dsm_app.proto generates"
