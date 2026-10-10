#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Translation frontier only: this does not discharge external models or proofs.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
: "${DSM_AENEAS_REPO:?Set DSM_AENEAS_REPO to the pinned Aeneas checkout}"
: "${DSM_CHARON_REPO:?Set DSM_CHARON_REPO to the pinned Charon checkout}"
[[ "$(git -C "$DSM_AENEAS_REPO" rev-parse HEAD)" == aa66752b15d02335f936f607b5ad5b9fecb65b13 ]]
[[ "$(git -C "$DSM_CHARON_REPO" rev-parse HEAD)" == c8f15d7d658c86a95658f71ad99cddd4be002e04 ]]
cd "$root"
out="$root/target/sphincs-rust-frontier"
mkdir -p "$out/lean"
"$DSM_CHARON_REPO/bin/charon" cargo --preset=aeneas --sysroot default \
  --start-from dsm_sphincs::sign --start-from dsm_sphincs::verify \
  --start-from dsm_sphincs::generate_keypair_from_seed \
  --opaque dsm_sphincs::keyed --opaque blake3 --opaque rand_chacha \
  --opaque zeroize --opaque subtle --dest "$out" -- --locked -p dsm-sphincs --lib
"$DSM_AENEAS_REPO/src/_build/default/main.exe" -backend lean -use-lean-modules false \
  -split-files -filter-trait-methods -dest "$out/lean" -namespace DSMSphincsRust \
  -no-progress-bar "$out/dsm_sphincs.llbc"
python3 - "$out" <<'PYTHON'
import pathlib, re, subprocess, sys
out = pathlib.Path(sys.argv[1])
rows = ['kind\tdeclaration\tgenerated_file\tline']
for path in sorted((out/'lean').glob('*External_Template.lean')):
    data = path.read_text()
    for hit in re.finditer(r'(?m)^axiom\s+([^\s:({]+)', data):
        kind = 'type' if path.name.startswith('Types') else 'function'
        rows.append(f'{kind}\t{hit.group(1)}\t{path.name}\t{data[:hit.start()].count(chr(10))+1}')
(out/'unproved-externals.tsv').write_text('\n'.join(rows)+'\n')
source = subprocess.check_output(['git','hash-object','crates/dsm-sphincs/src/lib.rs'],text=True).strip()
(out/'SOURCE.md').write_text('Source blob: '+source+'\n\nTranslation only. External templates are not accepted as checked proofs.\n')
print(f'Extraction completed; {len(rows)-1} external declarations still require models and refinement proofs.')
PYTHON
