# DSM anchor RP2350 — validation matrix (§11)

The measurement boundary is **not** complete because the firmware builds. It is complete only when
every row below passes — the host-automatable ones in CI, the hardware-boundary ones on a
provisioned silicon board. Until then the property is **"implemented, activation and silicon
validation pending,"** never "proven" or "deployed."

Legend — **Where:** `host` = automatable off-device (unit/integration test); `silicon` = requires a
provisioned RP2350 board.

| # | Test | Expected | Where | Status |
|---|---|---|---|---|
| 1 | Correct monitor + exact app | boot succeeds; committed `HostSign` succeeds | silicon | pending |
| 2 | One app byte changed | `measurement_ok=false`; `HostSign` unavailable | silicon (host: measure fn) | pending |
| 3 | Different app signed by the same signing infra | measurement still fails | silicon | pending |
| 4 | Non-secure OTP read | denied (hardware permission) | silicon | pending |
| 5 | Non-secure TROPIC SPI access | denied (SAU/ACCESSCTRL) | silicon | pending |
| 6 | Non-secure DMA → protected SRAM/SPI | denied | silicon | pending |
| 7 | Arbitrary Secure Gateway signing request | rejected (no oracle) | host (API) + silicon | pending |
| 8 | `sg_prepare` | no chip or host signature; no counter move | host + silicon | pending |
| 9 | prepare / abort / re-prepare | no signatures produced | host + silicon | pending |
| 10 | one `sg_commit` | exactly one counter decrement + one committed message | silicon | pending |
| 11 | second distinct commit from same origin | rejected | host + silicon | pending |
| 12 | power loss BEFORE decrement | safe cancel OR exact completion | silicon | pending |
| 13 | power loss AFTER decrement, BEFORE signatures | only the committed message is signed | silicon | pending |
| 14 | power loss AFTER signatures, BEFORE export | same package re-emitted | silicon | pending |
| 15 | external flash modified after app loaded | running SRAM image + measurement unaffected | silicon | pending |
| 16 | debug access after provisioning | denied | silicon | pending |
| 17 | unsigned monitor | rejected by bootrom | silicon | pending |
| 18 | device with different OTP secret | cannot reproduce the same host key | silicon (host: HKDF determinism) | pending |
| 19 | bench build | cannot create a production-compatible enrollment bundle | host (domain-tag separation) | pending |
| 20 | any fallback exposing HostSign when measurement fails | none exists | host (code audit) + silicon | pending |

## Host-automatable now (no board)

These become unit/integration tests in the monitor crate as the split lands:
- #2 (measurement fn: flip a byte → `constant_time_equal` false),
- #7/#8/#9/#11 (gateway state machine: no signature except through commit; second-commit refusal),
- #18 (HKDF: distinct `k_host_root` → distinct `k_host`),
- #19 (bench vs production bundle domain-tag separation),
- #20 (code audit: no HostSign path bypasses `measurement_ok`).

## Definition of done (spec)

- Secure/Non-secure split implemented; exact app SRAM-loaded and measured; `mu_enrolled` +
  `k_host_root` OTP-protected; host signer + TROPIC path Secure-only; no generic signing oracle;
  production OTP sequence run on a sacrificial board; modified-app AND signed-alternate-app attacks
  both fail on silicon; all power-loss cases preserve single-message emission; the final production
  board passes this entire matrix.
