#!/usr/bin/env python3
# ci/conformance_evidence.py: a requirement's conformance status is derived
# from evidence the repository can execute, never from prose.
#
# The derived artifacts (specs/requirements/) used to be maintained by hand,
# and they drifted: specifications were amended without new canonical rows or
# new pins, rows stayed "Met" on code and tests that had been deleted, and the
# totals were typed rather than counted. This gate makes each of those a
# failure.
#
# Checks, each against the files as committed:
#
#   1. PINS. Every specification's `git hash-object` equals the pin in
#      MASTER_REQUIREMENTS.md §1. A specification change therefore fails until
#      the derived artifacts are revisited and re-pinned in the same change.
#   2. COVERAGE. MASTER §8.1-§8.4 IDs are unique; CONFORMANCE_GAPS §8 has
#      exactly one row per canonical ID (a range row counts each ID it names),
#      and names no ID MASTER does not define.
#   3. COUNTS. MASTER's canonical-row sentence and CONFORMANCE §7 Totals equal
#      the counts of the rows themselves (`--write` regenerates the totals).
#   4. EVIDENCE. A code reference is a backticked module path to an item that
#      exists: `dsm::route_chain::CommittedAt::chain_link_holds` (a module, or
#      an item — fn, struct, enum, trait, const, static, type, macro — defined
#      in the module's file). A test reference is a backticked canonical name:
#          `dsm::route_chain::tests::only_links_of_one_chain_count_toward_final`
#          `dsm_sdk::supply_cap_partial_history::cap_is_exact_...`   (tests/*.rs)
#          `dsm_storage_node::main::tests::...`                      (src/main.rs)
#      or a formal property: `tla/<File>.tla::<Name>`, `lean4/<File>.lean::<name>`.
#      Every test reference in CONFORMANCE §8, the verification matrix's
#      Negative test column and the §5A Evidence column must resolve to a test
#      function (or property) that exists. A "Met" row must name at least one code item and at least one
#      test, and every name in its Code and Test cells must be canonical. A
#      ticked §5A row must name a test.
#   5. EXECUTION (`--board-log`, repeatable). Every referenced test must have
#      run and passed in the given `cargo test` logs; an ignored test is not
#      evidence. With `--write`, the commit the logs were produced at
#      (`--tested-at`, default HEAD) is recorded in CONFORMANCE §1, and only
#      when the code the boards compile is exactly that commit's: nothing in
#      the crates, the proto or the Cargo manifests and lockfiles differs from
#      it, tracked or untracked.
#
# Mutation evidence (a named test observed red with its gate removed) is not
# derivable from a log and stays in the verification matrix's own column.
import argparse
import os
import re
import subprocess
import sys

REQ = "specs/requirements/MASTER_REQUIREMENTS.md"
GAPS = "specs/requirements/CONFORMANCE_GAPS.md"
MATRIX = "specs/requirements/VERIFICATION_MATRIX.md"
SPECS = [
    "specs/DSM_High_Level_Explainer.md",
    "specs/SoFi_Settlement_Specification.md",
    "specs/dBTC_Native_Specification.md",
    "specs/DSM_Storage_Node_Specification.md",
]
CRATES = {
    "dsm": "dsm_client/deterministic_state_machine/dsm",
    "dsm_sdk": "dsm_client/deterministic_state_machine/dsm_sdk",
    "dsm_storage_node": "dsm_storage_node",
    "dsm_vertical_validation": "tools/vertical_validation",
}
# What the boards compile and run: a recorded commit must match these exactly.
TESTED_CODE = [
    "dsm_client/deterministic_state_machine",
    "dsm_storage_node",
    "crates",
    "tools",
    "proto",
    "Cargo.toml",
    "Cargo.lock",
]
SPEC_PREFIX = {
    "MR-DSM": "DSM high-level (MR-DSM)",
    "MR-SOFI": "SoFi (MR-SOFI)",
    "MR-DBTC": "dBTC (MR-DBTC)",
    "MR-STOR": "Storage node (MR-STOR)",
    "STOR-014": "Storage §14 lines added after the pin (STOR-014)",
}
STATUSES = ["Met", "Partial", "Missing", "Violated", "Not code", "Deferred"]
TEST_ATTR = re.compile(
    r"#\[(?:test|tokio::test|rstest|test_case|async_std::test|sqlx::test|serial_test::serial)\b"
)
CANON = re.compile(r"^[a-z_][a-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+$")
FORMAL = re.compile(r"^(tla/[A-Za-z0-9_]+\.tla|lean4/[A-Za-z0-9_/]+\.lean)::([A-Za-z_][A-Za-z0-9_'.]*)$")

errors = []


def fail(msg):
    errors.append(msg)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# ── Rust test index ─────────────────────────────────────────────────────────


def strip_rust(text):
    """Blank comments, strings and char literals, keeping every newline and
    every brace outside them, so a structural scan cannot be misled by
    `"{"` in a format string or `}` in a doc comment."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
            continue
        m = re.match(r'b?r(#*)"', text[i : i + 40])
        if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = '"' + m.group(1)
            j = text.find(close, i + m.end())
            j = n if j < 0 else j + len(close)
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j += 1
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
            continue
        if c == "'":
            m = re.match(r"'(?:\\u\{[0-9a-fA-F]+\}|\\.|[^\\'\n])'", text[i : i + 12])
            if m:
                out.append(" " * m.end())
                i += m.end()
                continue
        out.append(c)
        i += 1
    return "".join(out)


TOKEN = re.compile(r"\bmod\s+([A-Za-z_]\w*)\s*\{|\bfn\s+([A-Za-z_]\w*)|[{};]")


def tests_in(path):
    """(module path within the file, fn name, line, ignored) of every test fn."""
    raw = read(path)
    text = strip_rust(raw)
    found = []
    depth = 0
    mods = []  # (name, depth outside its brace)
    item_start = 0
    for m in TOKEN.finditer(text):
        tok = m.group(0)
        if m.group(1):
            mods.append((m.group(1), depth))
            depth += 1
            item_start = m.end()
        elif m.group(2):
            attrs = text[item_start : m.start()]
            if TEST_ATTR.search(attrs):
                line = text.count("\n", 0, m.start()) + 1
                found.append(([n for n, _ in mods], m.group(2), line, "#[ignore" in attrs))
        elif tok == "{":
            depth += 1
            item_start = m.end()
        elif tok == "}":
            depth -= 1
            while mods and mods[-1][1] >= depth:
                mods.pop()
            item_start = m.end()
        else:
            item_start = m.end()
    return found


def build_index():
    """canonical name -> (binary, cargo test path, file:line, ignored)."""
    index = {}
    stems = {}
    for crate, root in CRATES.items():
        if not os.path.isdir(root):
            continue
        for dirpath, _, files in os.walk(root):
            if "/target" in dirpath or "/node_modules" in dirpath:
                continue
            for f in files:
                if not f.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, f)
                rel = os.path.relpath(path, root).split(os.sep)
                if rel[0] == "src":
                    parts = rel[1:]
                    if parts == ["lib.rs"]:
                        binary, base, head = (crate, "lib"), [], []
                    elif parts == ["main.rs"]:
                        binary, base, head = (crate, "bin:main"), [], ["main"]
                    elif parts[0] == "bin":
                        stem = parts[-1][:-3]
                        binary, base, head = (crate, "bin:" + stem), [], ["bin", stem]
                    else:
                        segs = parts[:-1] + ([] if parts[-1] == "mod.rs" else [parts[-1][:-3]])
                        binary, base, head = (crate, "lib"), segs, []
                elif rel[0] == "tests" and len(rel) == 2:
                    stem = rel[1][:-3]
                    stems.setdefault(stem, set()).add(crate)
                    binary, base, head = (crate, "test:" + stem), [], [stem]
                else:
                    continue
                for mods, name, line, ignored in tests_in(path):
                    cargo_path = "::".join(base + mods + [name])
                    canon = "::".join([crate] + head + base + mods + [name])
                    loc = f"{path}:{line}"
                    if canon in index and index[canon][2] != loc:
                        fail(f"ambiguous test name {canon}: {index[canon][2]} and {loc}")
                    index[canon] = (binary, cargo_path, loc, ignored)
    return index, stems


ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|async|unsafe|extern\s+\"C\")\s+)*"
    r"(?:fn|struct|enum|trait|const|static|type|mod|union)\s+([A-Za-z_]\w*)"
    r"|^\s*macro_rules!\s*([A-Za-z_]\w*)",
    re.M,
)


def module_file(crate, segs):
    """The file of module `segs` in `crate`'s library, or None."""
    src = os.path.join(CRATES[crate], "src")
    if not segs:
        return os.path.join(src, "lib.rs")
    for cand in (os.path.join(src, *segs) + ".rs", os.path.join(src, *segs, "mod.rs")):
        if os.path.isfile(cand):
            return cand
    return None


def item_exists(ref):
    """A code reference names a module, or items defined in a module's file:
    `crate::m::n::Item` or `crate::m::n::Type::method`."""
    segs = ref.split("::")
    crate, path = segs[0], segs[1:]
    if crate not in CRATES:
        return False
    for k in range(len(path), -1, -1):
        f = module_file(crate, path[:k])
        if f is None:
            continue
        rest = path[k:]
        if not rest:
            return True
        defined = {a or b for a, b in ITEM.findall(read(f))}
        return all(r in defined for r in rest[-2:]) if len(rest) <= 2 else False
    return False


def formal_exists(ref):
    m = FORMAL.match(ref)
    if not m or not os.path.isfile(m.group(1)):
        return False
    text = read(m.group(1))
    name = re.escape(m.group(2))
    if m.group(1).endswith(".tla"):
        return re.search(rf"^{name}\s*(\([^)]*\))?\s*==", text, re.M) is not None
    return re.search(rf"^\s*(?:private\s+)?(?:theorem|lemma|def|structure|inductive|abbrev)\s+{name}\b", text, re.M) is not None


# ── cargo test logs ─────────────────────────────────────────────────────────


def parse_logs(paths, stems):
    """(binary, cargo test path) -> 'ok' | 'failed' | 'ignored'."""
    results = {}
    for p in paths:
        binary, started, failures = None, [], set()

        def close():
            for t in started:
                if results.get((binary, t)) != "ignored":
                    results[(binary, t)] = "failed" if t in failures else "ok"

        in_failures = False
        for line in read(p).splitlines():
            m = re.match(r"\s*Running (unittests )?(\S+) \(.*?/deps/([A-Za-z0-9_]+)-[0-9a-f]+\)", line)
            if m:
                if binary:
                    close()
                started, failures, in_failures = [], set(), False
                src, dep = m.group(2), m.group(3)
                if src.endswith("src/lib.rs"):
                    binary = (dep, "lib")
                elif src.endswith("src/main.rs"):
                    binary = (dep, "bin:main")
                elif "/bin/" in src or src.startswith("src/bin/"):
                    binary = (next((c for c in CRATES if src.startswith(CRATES[c])), dep), "bin:" + os.path.basename(src)[:-3])
                else:
                    stem = os.path.basename(src)[:-3]
                    owners = stems.get(stem, set())
                    binary = (sorted(owners)[0] if len(owners) == 1 else "?", "test:" + stem)
                continue
            if binary is None:
                continue
            m = re.match(r"test (\S+) \.\.\. (ignored)", line)
            if m:
                results[(binary, m.group(1))] = "ignored"
                continue
            m = re.match(r"test (\S+) \.\.\. ", line)
            if m:
                started.append(m.group(1))
                continue
            if line.strip() == "failures:":
                in_failures = True
                continue
            if in_failures:
                m = re.match(r"    (\S+)$", line)
                if m:
                    failures.add(m.group(1))
            if line.startswith("test result:"):
                close()
                started, failures, in_failures = [], set(), False
        if binary:
            close()
    return results


# ── derived documents ───────────────────────────────────────────────────────


def table_rows(text):
    return [[c.strip() for c in l.strip()[1:-1].split("|")] for l in text.splitlines() if l.startswith("| ")]


def section(text, start, end=None):
    i = text.index(start)
    j = text.index(end, i + len(start)) if end else len(text)
    return text[i:j]


def id_range(cell):
    """`MR-X-0001` or `MR-X-0001–MR-X-0135` -> list of IDs."""
    m = re.fullmatch(r"(MR-[A-Z]+)-(\d{4})\s*[–-]\s*(?:MR-[A-Z]+-)?(\d{4})", cell)
    if m:
        return [f"{m.group(1)}-{k:04d}" for k in range(int(m.group(2)), int(m.group(3)) + 1)]
    return [cell]


def refs(cell):
    return [t for t in re.findall(r"`([^`]+)`", cell)]


def check_ref(ref, index, results, where, use_logs):
    if FORMAL.match(ref):
        if not formal_exists(ref):
            fail(f"{where}: formal property {ref} does not exist")
        return
    if ref not in index:
        fail(f"{where}: test {ref} does not exist")
        return
    binary, cargo_path, loc, ignored = index[ref]
    if ignored:
        fail(f"{where}: test {ref} is #[ignore]d ({loc}) and is not evidence")
    if use_logs:
        outcome = results.get((binary, cargo_path))
        if outcome is None:
            fail(f"{where}: test {ref} did not run in the given board logs")
        elif outcome != "ok":
            fail(f"{where}: test {ref} {outcome} in the given board logs")


def is_test_ref(ref):
    head = ref.split("::")[0]
    return (CANON.match(ref) and head in CRATES) or FORMAL.match(ref)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--board-log", action="append", default=[])
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--tested-at", default="HEAD")
    args = ap.parse_args()
    use_logs = bool(args.board_log)

    req, gaps, matrix = read(REQ), read(GAPS), read(MATRIX)

    # 1. pins
    pins = dict(re.findall(r"^\| `(specs/[^`]+)` \| `([0-9a-f]{40})` \|", req, re.M))
    for spec in SPECS:
        actual = subprocess.run(["git", "hash-object", spec], capture_output=True, text=True, check=True).stdout.strip()
        if pins.get(spec) != actual:
            fail(f"{REQ} §1 pins {spec} at {pins.get(spec)}, the file is {actual}: re-derive the requirements it changed and re-pin")

    # 2. coverage
    canon = section(req, "## 8 Canonical requirements", "### 8.5")
    ids = [r[0] for r in table_rows(canon) if re.fullmatch(r"MR-[A-Z]+-\d{4}", r[0])]
    if len(ids) != len(set(ids)):
        fail(f"{REQ} §8 repeats an ID")
    sources = {r[0]: r[4] for r in table_rows(canon) if re.fullmatch(r"MR-[A-Z]+-\d{4}", r[0])}
    per_req = section(gaps, "## 8 Per-requirement results")
    rows = [r for r in table_rows(per_req) if re.match(r"(MR-[A-Z]+-\d{4}|STOR-014/L)", r[0])]
    seen = {}
    for r in rows:
        for i in id_range(r[0]):
            seen[i] = seen.get(i, 0) + 1
            if i.startswith("MR-") and i not in sources:
                fail(f"{GAPS} §8 names {i}, which {REQ} does not define")
    for i in ids:
        if seen.get(i, 0) != 1:
            fail(f"{GAPS} §8 has {seen.get(i, 0)} rows for {i}")

    # 3. counts
    amended = {p: sum(1 for i, s in sources.items() if i.startswith(p + "-") and s.startswith("amendment")) for p in SPEC_PREFIX}
    m = re.search(r"Added afterwards by amendment \(§7\.1\): DSM (\d+), SoFi (\d+), storage (\d+), for (\d+) canonical requirements in all\.", req)
    want = (amended["MR-DSM"], amended["MR-SOFI"], amended["MR-STOR"], len(ids))
    sentence = f"Added afterwards by amendment (§7.1): DSM {want[0]}, SoFi {want[1]}, storage {want[2]}, for {want[3]} canonical requirements in all."
    if not m or tuple(int(x) for x in m.groups()) != want:
        if args.write:
            req = re.sub(r"Added afterwards by amendment \(§7\.1\):[^\n]*", sentence, req)
        else:
            fail(f"{REQ} §8: the amendment sentence must read: {sentence}")

    counts = {label: {s: 0 for s in STATUSES} for label in SPEC_PREFIX.values()}
    for r in rows:
        if r[1] not in STATUSES:
            fail(f"{GAPS} §8 {r[0]}: status {r[1]!r} is not one of {STATUSES}")
            continue
        prefix = "STOR-014" if r[0].startswith("STOR-014/") else "-".join(r[0].split("-")[:2])
        counts[SPEC_PREFIX[prefix]][r[1]] += len(id_range(r[0]))
    lines = ["| Spec | Rows | " + " | ".join(STATUSES) + " |", "|---" * (len(STATUSES) + 2) + "|"]
    total = {s: 0 for s in STATUSES}
    for label, c in counts.items():
        lines.append(f"| {label} | {sum(c.values())} | " + " | ".join(str(c[s]) for s in STATUSES) + " |")
        for s in STATUSES:
            total[s] += c[s]
    lines.append(f"| **All** | **{sum(total.values())}** | " + " | ".join(f"**{total[s]}**" for s in STATUSES) + " |")
    generated = "\n".join(lines)
    totals_block = re.search(r"(## 7 Totals\n\n)(\|.*?\n)(?=\n)", gaps, re.S)
    if not totals_block or totals_block.group(2).strip() != generated:
        if args.write and totals_block:
            gaps = gaps[: totals_block.start(2)] + generated + "\n" + gaps[totals_block.end(2) :]
        else:
            fail(f"{GAPS} §7 Totals differ from the §8 rows; run ci/conformance_evidence.py --write")

    # 4 + 5. evidence
    index, stems = build_index()
    results = parse_logs(args.board_log, stems) if use_logs else {}
    for r in rows:
        where = f"{GAPS} §8 {r[0]}"
        code_cell = r[2] if len(r) > 2 else ""
        test_cell = r[3] if len(r) > 3 else ""
        for ref in refs(code_cell):
            if is_test_ref(ref) and not item_exists(ref):
                fail(f"{where}: code item {ref} does not exist")
        for ref in refs(test_cell):
            if is_test_ref(ref):
                check_ref(ref, index, results, where, use_logs)
        if r[1] == "Met":
            for label, cell in (("code item", code_cell), ("test", test_cell)):
                named = refs(cell)
                if not any(is_test_ref(t) for t in named):
                    fail(f"{where}: Met names no canonical {label}")
                for t in named:
                    if not is_test_ref(t):
                        fail(f"{where}: Met names {t!r} as a {label}, which is not a canonical name")

    # The matrix's Negative test column (the third) names tests only by their
    # canonical names; prose may describe what has no cargo test.
    for r in table_rows(section(matrix, "## Rows")):
        if r[0] in ("Requirement",) or set(r[0]) <= set("-"):
            continue
        where = f"{MATRIX} {r[0][:40]}"
        for ref in refs(r[2]):
            if is_test_ref(ref):
                check_ref(ref, index, results, where, use_logs)
            else:
                fail(f"{where}: negative test {ref!r} is not a canonical test name")

    # §5A: the Evidence column (the last) names the end-to-end tests. A
    # ticked row needs one, and every name there must be a test that exists
    # (and passed, with logs). Code named in the other cells is prose.
    checklist = section(gaps, "## 5A", "## 6")
    for r in table_rows(checklist):
        if r[0] == "Done" or set(r[0]) <= set("-"):
            continue
        if r[0] not in ("[ ]", "[x]"):
            fail(f"{GAPS} §5A: Done cell {r[0]!r} is neither [ ] nor [x]")
            continue
        where = f"{GAPS} §5A {r[1][:40]}"
        named = [t for t in refs(r[-1]) if is_test_ref(t)]
        if r[0] == "[x]" and not named:
            fail(f"{where}: ticked without a named end-to-end test")
        for t in named:
            check_ref(t, index, results, where, use_logs)

    if errors:
        for e in errors:
            print("FAIL", e)
        print(f"conformance evidence: {len(errors)} failure(s)")
        return 1

    if args.write:
        if use_logs:
            sha = subprocess.run(
                ["git", "rev-parse", "--verify", args.tested_at + "^{commit}"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            outside = ["--", *TESTED_CODE]
            differs = subprocess.run(["git", "diff", "--quiet", sha] + outside).returncode != 0
            untracked = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"] + outside,
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            if differs or untracked:
                print(f"refusing to record {sha[:12]}: this tree's code is not that commit's")
                return 1
            line = f"| Evidence | every test named in §5A, §8 and `VERIFICATION_MATRIX.md` passed on the board at `{sha[:12]}` (`ci/conformance_evidence.py --board-log`) |"
            if re.search(r"^\| Evidence \|.*$", gaps, re.M):
                gaps = re.sub(r"^\| Evidence \|.*$", line, gaps, flags=re.M)
            else:
                gaps = gaps.replace("| Crates |", line + "\n| Crates |", 1)
        with open(GAPS, "w", encoding="utf-8") as f:
            f.write(gaps)
        with open(REQ, "w", encoding="utf-8") as f:
            f.write(req)
    print(f"conformance evidence: {len(rows)} rows, {len(index)} tests indexed, " + ("board logs checked" if use_logs else "static"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
