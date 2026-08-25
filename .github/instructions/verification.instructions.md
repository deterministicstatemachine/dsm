---
applyTo: '**'
---

# Verification doctrine — what counts as a board

**Authoritative.** A local `CLAUDE.md` may carry a copy for convenience, but it
is gitignored and machine-local; this file is the one that reaches fresh clones
and CI.

This exists because a security change was verified with `cargo test --lib`,
reported as a green board, and merged on that report. Fifteen of fifty-one
integration suites were broken and `main` went red. Every rule below is a
specific thing that went wrong, not a general aspiration.

## The board is the exact CI command

From `dsm_client/deterministic_state_machine/`:

```bash
cargo test --locked --workspace --exclude dsm_storage_node -- --nocapture --test-threads=1
```

This is what `.github/workflows/ci.yml` runs. Anything narrower is a smoke
test, and calling it a board is how `main` goes red.

- **`cargo test --lib` is NOT a board.** It neither compiles nor runs
  `tests/*.rs`. `dsm_sdk` alone has ~51 integration binaries it never touches,
  so a crate can report 1772 passed / 0 failed on `--lib` while a third of its
  integration suites are broken.
- `--workspace` covers every crate. `--test-threads=1` matches CI, and
  parallel-vs-serial is a real source of "passes locally, fails in CI",
  `#[serial]` tests especially.

## A board has two halves

Tests green with `make lint` red is not green. Run both.

```bash
make lint
```

`make lint` runs `cargo fmt --check` and `cargo clippy --all-targets` as a
pair, and it exists **only at the repository root** — there is no `lint` target
under `deterministic_state_machine/`. Running it from the wrong directory
reports `No rule to make target 'lint'`, which is a missing target, not a
passing lint. Read the output, not just the exit code.

The temptation to push is highest exactly when the big slow half just came back
clean.

## Never `tail` a board

Truncation discards the failure *names* and forces a full re-run to recover
information the first run already produced. Redirect to a file and grep it.

```bash
cargo test --locked --workspace --exclude dsm_storage_node -- --nocapture --test-threads=1 > board.txt 2>&1
grep -E "^test .* FAILED$" board.txt
```

Grep for real failure lines rather than the bare string `FAILED`: test output
routinely contains that word in a passing test's own log messages.

## Name crates and counts before claiming green

"dsm 1658/0, dsm_sdk 1772/0, lint exit 0" is a claim. "The board is green" is
not.

A board that finished **before** your last edit does not describe the tree you
are pushing. Re-run it or discard it; do not reason that the change was
harmless. "Provably behaviour-free" is the argument that produces stale-green
reports.

## A change that REMOVES a capability owes a dependent sweep

Any sentence describing the consequence — in a PR body, a plan, a commit
message — is a **test obligation**, not a disclaimer.

```bash
grep -rn "<the route or function being disabled>" --include='*.rs' .
```

If you can write "X will no longer work", you can grep for X. Fixtures are the
usual dependents, and they are precisely what `--lib` hides.

## Enabling a previously-unenabled cargo feature is a build-graph change

It can wake code gated behind that feature which has never compiled, and
therefore never been linted. Grep for everything gated on it first.

```bash
grep -rn 'feature = "<name>"' --include='*.rs' .
```

## Mutation-test every security gate

Remove the gate, watch a **named** test go red by actually performing the
forbidden action, then restore it. A green suite around a gate proves nothing
about whether the gate is load-bearing.

Two rules about how to read the result:

- **Positive-control the mutation itself.** A silent no-op edit (a string
  replace that matched nothing) produces a green run that looks like a passing
  gate. Assert the edit landed before trusting the outcome.
- **A mutation that stays green is a finding, not a pass.** It means either the
  gate is dead or the test is. In the `R_econ` primitives work, a mutation
  reporting green turned out to be a control test that an earlier edit had
  silently deleted — the mutation run is the only thing that surfaced it.
