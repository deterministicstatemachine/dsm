# DSM SBOM Report

- Generated: `2026-04-22T16:41:57Z`
- Run ID: `beta3-20260422`
- Commit: `e1c08f4bbd5add0f52aec34a39edd274d567a87f`
- Branch: `main`
- Tree State: `clean`

## What This Bundle Contains

- A consolidated CycloneDX SBOM at `sbom/beta3-20260422/dsm-consolidated.cdx.json`
- Per-ecosystem inventories under `sbom/beta3-20260422`
- Validation evidence from the integrated TLA check at `sbom/beta3-20260422/validation-evidence.json`

## Inventory Summary

| Inventory | Resolution | Components |
|---|---|---:|
| Rust workspace | resolved via `cargo cyclonedx` | 541 |
| Node lockfiles | resolved via `package-lock.json` | 1017 |
| Root JS workspace | manifest snapshot | 8 |
| Android build files | manifest snapshot | 33 |
| Consolidated total | merged unique components | 1516 |

## Validation Evidence

- Status: `skipped`
- Command: `cargo run -p dsm_vertical_validation -- tla-check`
- Log: `sbom/beta3-20260422/logs/tla-check.log`

## Limits

- Rust dependencies are resolved through cargo-cyclonedx for the current host target and current feature set.
- Frontend and optional MCP server Node inventories are lockfile-resolved where package-lock.json is present.
- The root JS workspace inventory is lockfile-resolved via package-lock.json.
- Android dependencies are build-file derived in this run; they are not Gradle-resolved.
- No vulnerability scan or license/compliance verdict is included by this generator.

## Reproduce

```bash
./scripts/generate-sbom.sh
./scripts/generate-sbom-report.sh --run-dir sbom/beta3-20260422
cargo run -p dsm_vertical_validation -- tla-check
```
