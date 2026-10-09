#!/usr/bin/env bash
set -euo pipefail

# Audit EVERY Cargo.lock the repository tracks, not only the root one.
#
# Each lockfile resolves a dependency set some build uses: the root workspace;
# dsm_client/deterministic_state_machine, which is its own workspace root (the
# test board and `make android-libs` resolve through it); crates/dsm-android-anchor,
# the shipped Android native library; and the anchor crates built outside the
# root workspace. Auditing only the root lock let RUSTSEC-2026-0285 (rustls)
# and RUSTSEC-2026-0185 (quinn-proto) sit unreported in the others.
#
# The list comes from git, so a lockfile is audited from the commit that adds
# it and there is no hand-kept list to fall behind. Every run starts at the
# repository root, so .cargo/audit.toml (each ignore with a written rationale)
# applies to every lockfile alike. All lockfiles are audited before the script
# fails, so one run reports every failure.

cd "$(git rev-parse --show-toplevel)"

locks=()
while IFS= read -r lock; do
  locks+=("${lock}")
done < <(git ls-files -- '*Cargo.lock')

if [ "${#locks[@]}" -eq 0 ]; then
  echo "ERROR: git lists no Cargo.lock, so the audit would pass vacuously" >&2
  exit 1
fi

failed=()
for lock in "${locks[@]}"; do
  echo "==> cargo audit -f ${lock}"
  if ! cargo audit -f "${lock}"; then
    failed+=("${lock}")
  fi
done

if [ "${#failed[@]}" -ne 0 ]; then
  echo "cargo audit failed for ${#failed[@]} of ${#locks[@]} lockfiles:" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "cargo audit: ${#locks[@]} lockfiles, no vulnerabilities"
