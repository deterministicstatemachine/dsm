# DSM SBOM Report

- Generated: `2026-03-29T09:53:40Z`
- Run ID: `beta-release-2026-03-29`
- Commit: `5e1986951b9887a0704375a23d94b5c1287ba211`
- Branch: `crypt`
- Tree State: `dirty`

## What This Bundle Contains

- A consolidated CycloneDX SBOM at `sbom/beta-release-2026-03-29/dsm-consolidated.cdx.json`
- Per-ecosystem inventories under `sbom/beta-release-2026-03-29`
- Validation evidence from the integrated TLA check at `sbom/beta-release-2026-03-29/validation-evidence.json`

## Inventory Summary

| Inventory | Resolution | Components |
|---|---|---:|
| Rust workspace | resolved via `cargo cyclonedx` | 494 |
| Node lockfiles | resolved via `package-lock.json` | 997 |
| Root JS workspace | manifest snapshot | 8 |
| Android build files | manifest snapshot | 33 |
| Consolidated total | merged unique components | 1464 |

## Validation Evidence

- Status: `skipped`
- Command: `cargo run -p dsm_vertical_validation -- tla-check`
- Log: `sbom/beta-release-2026-03-29/logs/tla-check.log`

## Limits

- Rust dependencies are resolved through cargo-cyclonedx for the current host target and current feature set.
- Frontend and MCP server Node inventories are lockfile-resolved because package-lock.json is present.
- The root JS workspace inventory is lockfile-resolved via package-lock.json.
- Android dependencies are build-file derived in this run; they are not Gradle-resolved.
- No vulnerability scan or license/compliance verdict is included by this generator.

## Reproduce

```bash
./scripts/generate-sbom.sh
./scripts/generate-sbom-report.sh --run-dir sbom/beta-release-2026-03-29
cargo run -p dsm_vertical_validation -- tla-check
```
