#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
export LEAN_PATH="$PWD/target/sphincs-blake3:$PWD/lean4"
mkdir -p target/sphincs-blake3/Sphincs
# Compile the executable test model; this is not native_decide and does not
# participate in kernel proof checking. Keep module roots consistent for linking.
for module in Model Transcript Blake3 Blake3Vectors Blake3Checks; do
  lean -DwarningAsError=true -R lean4 \
    -o "target/sphincs-blake3/Sphincs/$module.olean" \
    -c "target/sphincs-blake3/$module.c" "lean4/Sphincs/$module.lean"
done
lean -DwarningAsError=true lean4/Sphincs/Blake3Proofs.lean
leanc -O3 -o target/sphincs-blake3/check \
  target/sphincs-blake3/Model.c target/sphincs-blake3/Transcript.c \
  target/sphincs-blake3/Blake3.c target/sphincs-blake3/Blake3Vectors.c \
  target/sphincs-blake3/Blake3Checks.c
target/sphincs-blake3/check "$@"
python3 scripts/sphincs_blake3_controls.py target/sphincs-blake3/check
