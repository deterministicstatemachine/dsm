# tools/

| Directory | What it is | Run it with |
|---|---|---|
| [`dsm_guarded_reference/`](dsm_guarded_reference/) | A standalone reference implementation of guarded-candidate enforcement: resource keys derived from the parent, never taken from a branch (Appendix D of the owner's paper, "Deterministic State Machines as Guarded Linear Constraint Systems", revised July 2026). Not wired into the production state machine. | `cargo test` in the directory |
| [`requirement_map/`](requirement_map/) | The backend's function-level call graph, read from rust-analyzer SCIP indexes of each shipped build and content-hashed with BLAKE3, and the seals that lock each requirement finding to it. | `make requirement-map` |
| [`vertical_validation/`](vertical_validation/) | TLA+ model checking, proof checks, property tests, implementation traces against the real state machine, adversarial runs, crypto KATs and benchmarks, and the formal report. | see the README's [Formal verification](../README.md#formal-verification) |
| [`walkthrough/`](walkthrough/) | The developer walkthrough as scripted terminal sessions; CI runs every command. | see [its README](walkthrough/README.md) |
| [`verify-proofs.sh`](verify-proofs.sh) | Runs the machine-checked provers (TLAPS and Lean 4) and writes `verification-reports/verification-report.{json,txt}`. | `./tools/verify-proofs.sh` |
