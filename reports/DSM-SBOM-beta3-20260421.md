# DSM SBOM Report

- Generated: `2026-04-22T00:30:14Z`
- Run ID: `beta3-20260421`
- Commit: `0132ec9ecd4a01f26897fe4ff590d727c653005c`
- Branch: `main`
- Tree State: `dirty`

## What This Bundle Contains

- A consolidated CycloneDX SBOM at `sbom/beta3-20260421/dsm-consolidated.cdx.json`
- Per-ecosystem inventories under `sbom/beta3-20260421`
- Validation evidence from the integrated TLA check at `sbom/beta3-20260421/validation-evidence.json`

## Inventory Summary

| Inventory | Resolution | Components |
|---|---|---:|
| Rust workspace | resolved via `cargo cyclonedx` | 540 |
| Node lockfiles | resolved via `package-lock.json` | 1017 |
| Root JS workspace | manifest snapshot | 8 |
| Android build files | manifest snapshot | 33 |
| Consolidated total | merged unique components | 1515 |

## Validation Evidence

- Status: `pass`
- Command: `cargo run -p dsm_vertical_validation -- tla-check`
- Log: `sbom/beta3-20260421/logs/tla-check.log`

Validation summary lines:

- `  Running TLC: DSM_tiny (DSM_tiny.cfg) ...`
- `  Running TLC: DSM_small (DSM_small.cfg) ...`
- `  Running TLC: DSM_system (DSM_system_bounded.cfg) ...`
- `  Running TLC: Tripwire (DSM_Tripwire.cfg) ...`
- `    DSM_tiny -> literal=PASS direct=PASS (5 steps, 4.6ms / 1250.2ms)`
- `    DSM_small -> literal=PASS direct=PASS (5 steps, 1.6ms / 2323.2ms)`
- `    DSM_system -> literal=PASS direct=PASS (5 steps, 1.1ms / 1294.0ms)`
- `    Tripwire -> literal=PASS direct=PASS (4 steps, 0.5ms / 0.9ms)`
- `  DSM_tiny                 |     10,938 |      3,444 |    10 | PASS |   PASS |   PASS |   PASS |   PASS`
- `  DSM_small                |     35,960 |      5,727 |     8 | PASS |   PASS |   PASS |   PASS |   PASS`
- `  DSM_system               |    164,525 |     13,232 |     7 | PASS |   PASS |   PASS |   PASS |   PASS`
- `  Tripwire                 |     14,569 |      1,581 |     6 | PASS |   PASS |   PASS |   PASS |   PASS`
- `  Invariants verified: TypeInvariant, DJTESafety, ConcreteRefinesAbstract, RefinementStrengthening, SourceVaultBounded, TripwireInvariant, TypeOK, BilateralIrreversibility, FullSettlement, NoHalfCommit, TripwireGuaranteesUniqueness, TokenConservation, BalancesNonNegative, NonInterference, PairIsolation, PerPairConservation, ZeroRefreshForInactive`

## Limits

- Rust dependencies are resolved through cargo-cyclonedx for the current host target and current feature set.
- Frontend and optional MCP server Node inventories are lockfile-resolved where package-lock.json is present.
- The root JS workspace inventory is lockfile-resolved via package-lock.json.
- Android dependencies are build-file derived in this run; they are not Gradle-resolved.
- No vulnerability scan or license/compliance verdict is included by this generator.

## Reproduce

```bash
./scripts/generate-sbom.sh
./scripts/generate-sbom-report.sh --run-dir sbom/beta3-20260421
cargo run -p dsm_vertical_validation -- tla-check
```
