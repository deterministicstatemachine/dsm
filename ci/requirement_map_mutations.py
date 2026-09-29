#!/usr/bin/env python3
# ci/requirement_map_mutations.py: the requirement map's mutation cases.
#
# Each case in tools/requirement_map/fixture/mutations.toml changes one thing
# in a temporary copy and runs the map's real pipeline over it; the working
# tree is never touched, and every copy is removed afterwards (unless --keep).
#
#   fixture       the fixture crate, in a copy of the whole tracked tree (so
#                 its build script runs the real-code guard exactly as in the
#                 repository), is changed, indexed by rust-analyzer and read
#                 by `requirement_map fixture` against expected.tsv with the
#                 case's changes: every reading the case does not name is a
#                 sentinel that must hold as before
#   declarations  the app's Kotlin/Java sources are copied and changed, and
#                 `requirement_map index` reads the real tree's indexes (from
#                 a finished `make requirement-map`) against them
#   reindex       the whole tree is copied and changed, the Android and test
#                 builds are indexed again in the copy (with a target
#                 directory of their own), and `requirement_map index` reads it
#   planted       a copy of the fixture's map (make requirement-map-fixture)
#                 gets one contradiction written into it, and the map's own
#                 `check` must name the case's rule: the checker is attacked
#                 as the map is
#   manifest      a copy of the fixture's intent manifest is changed and the
#                 intent comparator reads it against the fixture's map: it
#                 must refuse the row, or move exactly the outcomes named
#
# A case passes only when every reading it expects changes as written, every
# reading it names as unchanged holds before and after, and every explain
# query prints what the case says. Anything else is a failure, printed with
# the command's own output.
#
#   python3 ci/requirement_map_mutations.py --cases tools/requirement_map/fixture/mutations.toml \
#       --map target/requirement-map [--kinds fixture,declarations,reindex] [--keep]
import argparse
import csv
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib

FIXTURE = "tools/requirement_map/fixture"
BINARY = os.path.abspath("target/release/requirement_map")
SENTINELS = "ci/requirement_map.sentinels.tsv"
ROOTS = "ci/requirement_map.roots.tsv"
COUNTS = "ci/requirement_map.counts.tsv"
FIXTURE_SENTINELS = f"{FIXTURE}/sentinels.tsv"
DECLARATIONS = "dsm_client/android/app/src/main"
SOURCE_SUFFIXES = (".rs", ".kt", ".kts", ".java", ".ts", ".tsx", ".js", ".mjs", ".proto")


class Failure(Exception):
    pass


def rust_pin():
    with open("rust-toolchain.toml", "rb") as fh:
        return tomllib.load(fh)["toolchain"]["channel"]


def run(cmd, what, cwd=None, env=None, out_path=None):
    """Runs a command; its stdout goes to `out_path` when given. A non-zero
    exit is a failure carrying the command's own output."""
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            r = subprocess.run(cmd, cwd=cwd, env=env, stdout=fh, stderr=subprocess.PIPE, text=1)
    else:
        r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=1, text=1)
    if r.returncode:
        tail = (r.stdout or "")[-3000:] + (r.stderr or "")[-3000:]
        raise Failure(f"{what} exited {r.returncode}:\n{tail}")
    return r.stdout


def apply(root, case):
    path = os.path.join(root, case["file"])
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    found = text.count(case["find"])
    if found != 1:
        raise Failure(f"{case['file']}: the case's text occurs {found} times, not once")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text.replace(case["find"], case["replace"]))


def read_expected(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            if line.startswith("#") or not line.strip():
                rows.append(("comment", line))
                continue
            key, state, code = line.split("\t")
            rows.append(("row", (key, state, code)))
    return rows


def write_expected(path, rows, changes):
    keys = {r[0] for kind, r in rows if kind == "row"}
    unknown = sorted(set(changes) - keys)
    if unknown:
        raise Failure(f"expected.tsv holds no reading for {', '.join(unknown)}")
    lines = []
    for kind, r in rows:
        if kind == "comment":
            lines.append(r)
            continue
        key, state, code = r
        if key in changes:
            state, code = changes[key].split(" ")
        lines.append(f"{key}\t{state}\t{code}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def readings(map_dir, artifact):
    """Each Rust path's reading in one artifact, as "state CODE"."""
    path_of = {}
    with open(os.path.join(map_dir, "defs.tsv"), encoding="utf-8") as fh:
        for d in csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE):
            if d["path"]:
                path_of.setdefault(d["path"], []).append(d["symbol"])
    by_symbol = {}
    with open(os.path.join(map_dir, "reach.tsv"), encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE):
            if r["artifact"] == artifact:
                by_symbol[r["symbol"]] = f"{r['state']} {r['code']}"
    out = {}
    for path, symbols in path_of.items():
        # One value per definition the artifact reads: two that read alike
        # are still two, and never fold into one.
        values = sorted(by_symbol[s] for s in symbols if s in by_symbol)
        out[path] = values
    return out


def check_readings(label, found, wanted):
    faults = []
    for key, value in wanted.items():
        got = found.get(key)
        if got != [value]:
            faults.append(f"{label} {key}: expected {value}, read {got}")
    return faults


def explain_checks(map_dir, case):
    faults = []
    for key, text in case.get("explain", {}).items():
        out = run(
            [sys.executable, "ci/requirement_map.py", "--map", map_dir, "explain", key],
            f"explain {key}",
        )
        if text not in out:
            faults.append(f"explain {key} does not print {text!r}:\n{out}")
    return faults


def tracked_files():
    listed = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], "git ls-files")
    return [f for f in listed.split("\0") if f and os.path.isfile(f)]


def copy_tree(files, into):
    """A copy of the tracked tree: everything a build, the guard and its
    wiring read, nothing ignored."""
    for f in files:
        dst = os.path.join(into, f)
        os.makedirs(os.path.dirname(dst), exist_ok=1)
        shutil.copy2(f, dst)


def fixture_case(case, tree, pin):
    """One fixture case inside the shared copy of the tree: the fixture is
    restored from the repository, changed, and read."""
    fixture = os.path.join(tree, FIXTURE)
    scratch = tempfile.mkdtemp(prefix=f"{case['name']}-", dir=os.path.dirname(tree))
    try:
        shutil.rmtree(fixture)
        shutil.copytree(FIXTURE, fixture, ignore=shutil.ignore_patterns("target"))
        apply(fixture, case)
        manifest = os.path.join(fixture, "Cargo.toml")
        built = os.path.join(scratch, "features.txt")
        indexed = os.path.join(scratch, "features-indexed.txt")
        tree_args = ["--locked", "--color", "never", "--manifest-path", manifest, "--prefix", "none", "-f", "{p} {f}"]
        run(["rustup", "run", pin, "cargo", "tree", *tree_args, "-p", "probe", "-e", "normal,build"], "cargo tree (build)", out_path=built)
        run(["rustup", "run", pin, "cargo", "tree", *tree_args, "--workspace", "-e", "normal,build,dev"], "cargo tree (index)", out_path=indexed)
        scip = os.path.join(scratch, "index.scip")
        log = os.path.join(scratch, "index.log")
        run(
            ["rustup", "run", pin, "rust-analyzer", "scip", fixture,
             "--config-path", os.path.abspath("ci/requirement_map.fixture.rust-analyzer.json"), "--output", scip],
            "rust-analyzer scip", out_path=log,
        )
        expected = os.path.join(scratch, "expected.tsv")
        write_expected(expected, read_expected(os.path.join(FIXTURE, "expected.tsv")), case.get("expect", {}))
        map_dir = os.path.join(scratch, "map")
        run(
            [BINARY, "fixture", "--root", fixture, "--scip", scip, "--log", log,
             "--jni-declarations", "kotlin", "--crate", "probe/src/", "--package", "probe",
             "--features", built, "--features-indexed", indexed, "--expect", expected, "--out", map_dir],
            "requirement_map fixture",
        )
        return explain_checks(map_dir, case)
    finally:
        if not ARGS.keep:
            shutil.rmtree(scratch)


def index_args(root, map_dir, out_dir, declarations, have_node, target_dir=None):
    args = [
        BINARY, "index", "--root", root,
        "--files", os.path.join(map_dir, "sources.txt"),
        "--inputs", os.path.join(map_dir, "inputs.txt"),
        "--fingerprint", os.path.join(map_dir, "tree"),
        "--android", os.path.join(map_dir, "android.scip"), "--android-log", os.path.join(map_dir, "android.log"),
        "--android-features", os.path.join(map_dir, "android-features.txt"),
        "--android-features-indexed", os.path.join(map_dir, "android-features-indexed.txt"),
        "--android-packages", os.path.join(map_dir, "android-packages.txt"),
        "--node-packages", os.path.join(map_dir, "node-packages.txt"),
        "--tests", os.path.join(map_dir, "tests.scip"), "--tests-log", os.path.join(map_dir, "tests.log"),
        "--jni-declarations", declarations,
        "--unindexed-consumer", "crates/dsm-android-anchor/src",
        "--out", out_dir,
    ]
    if target_dir:
        args += ["--target-dir", target_dir]
    if have_node:
        args += [
            "--node", os.path.join(map_dir, "node.scip"), "--node-log", os.path.join(map_dir, "node.log"),
            "--node-features", os.path.join(map_dir, "node-features.txt"),
            "--node-features-indexed", os.path.join(map_dir, "node-features-indexed.txt"),
        ]
    return args


def compare_real(case, before_dir, after_dir):
    before = readings(before_dir, "android")
    after = readings(after_dir, "android")
    faults = check_readings("after:", after, case.get("expect", {}))
    faults += check_readings("before:", before, case.get("unchanged", {}))
    faults += check_readings("after:", after, case.get("unchanged", {}))
    for key in case.get("expect", {}):
        if before.get(key) == after.get(key):
            faults.append(f"{key}: the change moved nothing ({before.get(key)})")
    return faults + explain_checks(after_dir, case)


def declarations_case(case, work, map_dir):
    tree = tempfile.mkdtemp(prefix=f"{case['name']}-", dir=work)
    try:
        for base, _, names in os.walk(DECLARATIONS):
            for n in names:
                if n.endswith((".kt", ".java")):
                    src = os.path.join(base, n)
                    dst = os.path.join(tree, src)
                    os.makedirs(os.path.dirname(dst), exist_ok=1)
                    shutil.copy2(src, dst)
        apply(tree, case)
        out_dir = os.path.join(tree, "map")
        declarations = os.path.relpath(os.path.join(tree, DECLARATIONS))
        have_node = os.path.exists(os.path.join(map_dir, "node.scip"))
        run(index_args(".", map_dir, out_dir, declarations, have_node), "requirement_map index")
        return compare_real(case, map_dir, out_dir)
    finally:
        if not ARGS.keep:
            shutil.rmtree(tree)


def reindex_case(case, work, map_dir, pin):
    ndk = os.environ.get("ANDROID_NDK_HOME")
    if not ndk:
        raise Failure("a reindex case builds the Android index: set ANDROID_NDK_HOME to the NDK Gradle pins")
    host = f"{os.uname().sysname.lower()}-x86_64"
    ndk_bin = os.path.join(ndk, "toolchains", "llvm", "prebuilt", host, "bin")
    tree = tempfile.mkdtemp(prefix=f"{case['name']}-", dir=work)
    try:
        files = tracked_files()
        copy_tree(files, tree)
        apply(tree, case)
        out_dir = os.path.join(tree, "target", "requirement-map")
        os.makedirs(out_dir, exist_ok=1)
        sources = [f for f in files if f.endswith(SOURCE_SUFFIXES)]
        with open(os.path.join(out_dir, "sources.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(sources) + "\n")
        run(["rustup", "run", pin, "rust-analyzer", "--version"], "rust-analyzer --version",
            out_path=os.path.join(out_dir, "analyzer.txt"))
        shutil.copy2(os.path.join(map_dir, "inputs.txt"), os.path.join(out_dir, "inputs.txt"))
        run([BINARY, "fingerprint", "--root", tree, "--files", os.path.join(out_dir, "sources.txt"),
             "--inputs", os.path.join(out_dir, "inputs.txt"), "--out", os.path.join(out_dir, "tree")], "fingerprint")
        # A target directory of the harness's own: never the tree's, and never
        # used by two builds at once.
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = os.path.abspath(os.path.join(work, "target"))
        env["CC_aarch64_linux_android"] = os.path.join(ndk_bin, "aarch64-linux-android23-clang")
        env["AR_aarch64_linux_android"] = os.path.join(ndk_bin, "llvm-ar")
        tree_args = ["--locked", "--color", "never", "--prefix", "none", "-f", "{p} {f}"]
        run(["rustup", "run", pin, "cargo", "tree", *tree_args, "-p", "dsm_sdk", "--features", "jni,bluetooth",
             "--target", "aarch64-linux-android", "-e", "normal,build"], "cargo tree (android build)",
            cwd=tree, env=env, out_path=os.path.join(out_dir, "android-features.txt"))
        run(["rustup", "run", pin, "cargo", "tree", *tree_args, "--workspace", "--features", "dsm_sdk/jni,dsm_sdk/bluetooth",
             "--target", "aarch64-linux-android", "-e", "normal,build,dev"], "cargo tree (android index)",
            cwd=tree, env=env, out_path=os.path.join(out_dir, "android-features-indexed.txt"))
        packages_args = ["--locked", "--color", "never", "--prefix", "none", "-f", "{p}", "-e", "normal"]
        run(["rustup", "run", pin, "cargo", "tree", *packages_args, "-p", "dsm_sdk", "--features", "jni,bluetooth",
             "--target", "aarch64-linux-android"], "cargo tree (android packages)",
            cwd=tree, env=env, out_path=os.path.join(out_dir, "android-packages.txt"))
        run(["rustup", "run", pin, "cargo", "tree", *packages_args, "-p", "dsm_storage_node",
             "--target", "x86_64-unknown-linux-gnu"], "cargo tree (node packages)",
            cwd=tree, env=env, out_path=os.path.join(out_dir, "node-packages.txt"))
        for profile in ("android", "tests"):
            run(["rustup", "run", pin, "rust-analyzer", "scip", ".", "--config-path",
                 f"ci/requirement_map.{profile}.rust-analyzer.json", "--output", os.path.join(out_dir, f"{profile}.scip")],
                f"rust-analyzer scip ({profile})", cwd=tree, env=env,
                out_path=os.path.join(out_dir, f"{profile}.log"))
        run(index_args(tree, out_dir, out_dir, DECLARATIONS, 0, env["CARGO_TARGET_DIR"]), "requirement_map index")
        return compare_real(case, map_dir, out_dir)
    finally:
        if not ARGS.keep:
            shutil.rmtree(tree)


def check_args(real):
    """The check's committed facts: a real map's sentinels, entry points and
    counts; the fixture's own sentinels."""
    if not real:
        return ["--sentinels", FIXTURE_SENTINELS]
    return ["--sentinels", SENTINELS, "--roots", ROOTS, "--counts", COUNTS]


def planted_case(case, work, fixture_map):
    """Writes one fault into a copy of a map's tables (the fixture's, or with
    map = "real" the real tree's, checked against the committed sentinels,
    entry points and counts) and requires the check to name the case's rule.
    Only the edited table is written; the others are linked."""
    real = case.get("map") == "real"
    source = os.path.abspath(ARGS.map if real else fixture_map)
    tree = tempfile.mkdtemp(prefix=f"{case['name']}-", dir=work)
    try:
        name = {"reach": "reach.tsv", "defs": "defs.tsv", "edges": "edges.tsv"}[case["table"]]
        for table_name in os.listdir(source):
            if table_name.endswith(".tsv") and table_name != name:
                os.symlink(os.path.join(source, table_name), os.path.join(tree, table_name))
        symbols_of = {}
        with open(os.path.join(source, "defs.tsv"), encoding="utf-8") as fh:
            for d in csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE):
                symbols_of.setdefault(d["path"], []).append(d["symbol"])
        def symbols(path):
            found = symbols_of.get(path)
            if not found:
                raise Failure(f"the map names no {path}")
            return found
        table = os.path.join(tree, name)
        with open(os.path.join(source, name), encoding="utf-8") as fh:
            reader = csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE)
            columns = reader.fieldnames
            rows = list(reader)
        def selected(row):
            for key, value in case["where"].items():
                if key.endswith("_path"):
                    if row[key[: -len("_path")]] not in symbols(value):
                        return 0
                elif row[key] != value:
                    return 0
            return 1
        hits = [r for r in rows if selected(r)]
        if not hits:
            raise Failure(f"the case's `where` selects no row of {name}")
        if case.get("action") == "delete":
            rows = [r for r in rows if not selected(r)]
        else:
            for r in hits:
                for key, value in case["set"].items():
                    if key.endswith("_path"):
                        r[key[: -len("_path")]] = symbols(value)[0]
                    else:
                        r[key] = value
        # The map's cells hold no tab and no newline (the writer refuses them).
        with open(table, "w", encoding="utf-8") as fh:
            fh.write("\t".join(columns) + "\n")
            for row in rows:
                fh.write("\t".join(row[c] for c in columns) + "\n")
        r = subprocess.run([sys.executable, "ci/requirement_map.py", "--map", tree, "check", *check_args(real)],
                           capture_output=1, text=1)
        if f"[{case['rule']}]" not in r.stdout:
            return [f"the check does not name [{case['rule']}]:\n{r.stdout[-2000:]}{r.stderr[-1000:]}"]
        if r.returncode == 0:
            return ["the check named the rule but exited 0"]
        return []
    finally:
        if not ARGS.keep:
            shutil.rmtree(tree)


def manifest_case(case, work, fixture_map):
    """Changes one thing in a copy of the fixture's intent manifest and runs
    the comparator over the fixture's map: `refused` names text the refusal
    must hold; otherwise `expect` names each row (`requirement:symbol`) whose
    outcome must become `OUTCOME fails|known-hole|-`, and every other row
    keeps its expected outcome."""
    tree = tempfile.mkdtemp(prefix=f"{case['name']}-", dir=work)
    try:
        with open(os.path.join(FIXTURE, "intent.tsv"), encoding="utf-8") as fh:
            text = fh.read()
        if text.count(case["find"]) != 1:
            raise Failure(f"`find` occurs {text.count(case['find'])} times in the fixture's manifest")
        # The changed manifest, and a directory of its own for the report
        # (whose intent.tsv would otherwise overwrite it).
        manifest = os.path.join(tree, "manifest.tsv")
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write(text.replace(case["find"], case["replace"]))
        report = os.path.join(tree, "report")
        os.makedirs(report)
        r = subprocess.run([sys.executable, "ci/intent_comparator.py", "--map", fixture_map, "--manifest", manifest,
                            "--requirements", os.path.join(FIXTURE, "requirements.tsv"), "--report", report],
                           capture_output=1, text=1)
        # The comparator exits nonzero when rows fail, which the fixture's do;
        # a crash is told apart by what it writes to stderr.
        if r.stderr.strip():
            return [f"the comparator failed:\n{r.stderr[-2000:]}"]
        if "refused" in case:
            if r.returncode == 0 or case["refused"] not in r.stdout:
                return [f"the comparator did not refuse with {case['refused']!r}:\n{r.stdout[-1500:]}{r.stderr[-500:]}"]
            return []
        if "intent comparator:" in r.stdout:
            return [f"the comparator refused the manifest:\n{r.stdout[-1500:]}"]
        def rows_of(path, columns):
            with open(path, encoding="utf-8") as fh:
                lines = [l for l in fh.read().split("\n") if l and not l.startswith("#")]
            if tuple(lines[0].split("\t")) != columns:
                raise Failure(f"{path}: columns {lines[0]!r}, not {columns}")
            rows = []
            for l in lines[1:]:
                cells = l.split("\t")
                if len(cells) != len(columns):
                    raise Failure(f"{path}: {len(cells)} cells, not {len(columns)}, in {l!r}")
                rows.append(dict(zip(columns, cells)))
            return rows
        written = os.path.join(report, "intent.tsv")
        if not os.path.exists(written):
            return [f"the comparator wrote no report:\n{r.stdout[-1500:]}"]
        got = rows_of(written, REPORT)
        baseline = rows_of(os.path.join(FIXTURE, "intent-expected.tsv"), EXPECTED)
        if len(got) != len(baseline):
            return [f"{len(got)} rows reported, {len(baseline)} expected"]
        faults = []
        wanted = case.get("expect", {})
        for g, b in zip(got, baseline):
            key = f"{g['requirement']}:{g['symbol']}"
            now = f"{g['outcome']} {g['fails']}"
            if key in wanted:
                if now != wanted[key]:
                    faults.append(f"{key}: expected {wanted[key]}, the comparator says {now}")
            elif now != f"{b['outcome']} {b['fails']}":
                faults.append(f"{key}: moved from {b['outcome']} {b['fails']} to {now}, and the case names no such change")
        missing = set(wanted) - {f"{g['requirement']}:{g['symbol']}" for g in got}
        faults += [f"{k}: no such row after the change" for k in sorted(missing)]
        return faults
    finally:
        if not ARGS.keep:
            shutil.rmtree(tree)


REPORT = ("requirement", "symbol", "artifact", "reachability", "lifecycle", "root", "evidence", "exception", "cites",
          "state", "code", "outcome", "action", "status", "fails")
EXPECTED = ("requirement", "symbol", "artifact", "reachability", "lifecycle", "root", "outcome", "fails")


def main():
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cases", required=1)
    ap.add_argument("--map", required=1, help="a finished `make requirement-map` directory (declarations and reindex cases)")
    ap.add_argument("--kinds", default="fixture,declarations,reindex,planted,manifest")
    ap.add_argument("--fixture-map", help="the fixture's map (make requirement-map-fixture) for planted cases; default MAP/fixture/map")
    ap.add_argument("--keep", action="store_true", help="keep each case's temporary copy")
    ARGS = ap.parse_args()
    kinds = set(ARGS.kinds.split(","))
    with open(ARGS.cases, "rb") as fh:
        cases = tomllib.load(fh)["case"]
    work = os.path.abspath(os.path.join(ARGS.map, "mutations"))
    os.makedirs(work, exist_ok=1)
    pin = rust_pin()
    fixture_map = ARGS.fixture_map or os.path.join(ARGS.map, "fixture", "map")
    # A planted fault means something only against a map that holds none: a
    # map that is not clean fails its planted cases, and every other case
    # still runs.
    unclean = {}
    if "planted" in kinds:
        planted_maps = {case.get("map", "fixture") for case in cases if case["kind"] == "planted"}
        for which in sorted(planted_maps):
            real = which == "real"
            r = subprocess.run([sys.executable, "ci/requirement_map.py", "--map", ARGS.map if real else fixture_map,
                                "check", *check_args(real)], capture_output=1, text=1)
            if r.returncode:
                print(f"the {which} map is not clean before planting:\n{r.stdout}{r.stderr}")
                unclean[which] = f"the {which} map is not clean before planting (its check is printed above)"
    failed = []
    ran = 0
    fixture_tree = None
    for case in cases:
        if case["kind"] not in kinds:
            continue
        ran += 1
        try:
            if case["kind"] == "fixture":
                if fixture_tree is None:
                    fixture_tree = tempfile.mkdtemp(prefix="fixture-tree-", dir=work)
                    copy_tree(tracked_files(), fixture_tree)
                faults = fixture_case(case, fixture_tree, pin)
            elif case["kind"] == "declarations":
                faults = declarations_case(case, work, ARGS.map)
            elif case["kind"] == "reindex":
                faults = reindex_case(case, work, ARGS.map, pin)
            elif case["kind"] == "manifest":
                faults = manifest_case(case, work, fixture_map)
            elif case["kind"] == "planted":
                which = case.get("map", "fixture")
                faults = [unclean[which]] if which in unclean else planted_case(case, work, fixture_map)
            else:
                faults = [f"no such kind {case['kind']!r}"]
        except Failure as e:
            faults = [str(e)]
        status = "FAIL" if faults else "ok"
        print(f"[{status}] {case['kind']:<12} {case['name']}")
        for f in faults:
            print("    " + f.replace("\n", "\n    "))
        if faults:
            failed.append(case["name"])
    if fixture_tree is not None and not ARGS.keep:
        shutil.rmtree(fixture_tree)
    print(f"{ran} mutation cases run, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
