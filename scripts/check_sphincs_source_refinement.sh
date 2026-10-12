#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
: "${DSM_AENEAS_REPO:?Set DSM_AENEAS_REPO to the pinned Aeneas checkout}"
: "${DSM_CHARON_REPO:?Set DSM_CHARON_REPO to the pinned Charon checkout}"
[[ "$(git -C "$DSM_AENEAS_REPO" rev-parse HEAD)" == aa66752b15d02335f936f607b5ad5b9fecb65b13 ]]
[[ "$(git -C "$DSM_CHARON_REPO" rev-parse HEAD)" == c8f15d7d658c86a95658f71ad99cddd4be002e04 ]]
cd "$root"
out="$root/target/sphincs-source-refinement"
mkdir -p "$out/generated" "$out/check/DsmSphincs" "$out/check/Sphincs"
"$DSM_CHARON_REPO/bin/charon" cargo --preset=aeneas --sysroot default \
  --start-from dsm_sphincs::next_layer --start-from 'dsm_sphincs::Adrs::set_tree' \
  --start-from 'dsm_sphincs::Adrs::set_type_and_clear' --start-from dsm_sphincs::base_2b --dest "$out" -- --locked -p dsm-sphincs --lib
"$DSM_AENEAS_REPO/src/_build/default/main.exe" -backend lean -use-lean-modules false \
  -split-files -dest "$out/generated" -namespace DSMSphincsRust -no-progress-bar "$out/dsm_sphincs.llbc"
for name in Types Funs; do
  cmp "$out/generated/$name.lean" "$root/lean4/Sphincs/RustExtraction/DsmSphincs/$name.lean"
  cp "$out/generated/$name.lean" "$out/check/DsmSphincs/$name.lean"
done
cp "$root/lean4/Sphincs/Model.lean" "$out/check/Sphincs/Model.lean"
cp "$root/lean4/Sphincs/RustExtraction/Refinement.lean" "$out/check/Refinement.lean"
cd "$DSM_AENEAS_REPO/backends/lean"
export LEAN_PATH="$out/check:${LEAN_PATH:-}"
for name in DsmSphincs/Types DsmSphincs/Funs Sphincs/Model; do
  lake env lean -R "$out/check" -o "$out/check/$name.olean" "$out/check/$name.lean"
done
lake env lean -DwarningAsError=true -R "$out/check" "$out/check/Refinement.lean"
