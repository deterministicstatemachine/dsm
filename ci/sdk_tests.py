#!/usr/bin/env python3
"""Which dsm_sdk library tests a run executes, and on how many runners.

The dsm_sdk library suite is 1,459 tests run one at a time (--test-threads=1:
they share process-global state). Measured 2026-11-09 on main: 141 minutes,
nearly all of a three-hour CI run. Two things shorten it, and this script does
both:

  1. TEST IMPACT. On a pull request, run only the test modules that execute a
     file the pull request changed. Which files each module executes comes
     from the test map (.github/workflows/test-map.yml): every module of the
     suite run once, instrumented, on main, recording the files it executed.
  2. SHARDS. Whatever is selected is split across parallel runners, balanced
     by each test's measured time (ci/sdk_test_times.tsv), so even a run that
     needs every test finishes in roughly the time of one shard.

Every doubt resolves to running MORE (the rules are in `select_tests`):
no map, an incomplete map, an event or file that makes the run FULL, a changed
file the suite links but no module executes, a file the map never saw, or a
changed const/static/macro/include line -> every test. A test whose module the
map does not know (added after the map was built) always runs. Pushes to main
run every test, and the unsplit Rust board on main stays the safety net.

Subcommands:
  select    decide what runs (select job) -> GitHub outputs + selection JSON
  plan      one shard's exact test names, from the live --list of the binary
  check     the shard ran exactly the tests it was given, no more, no fewer
  learn     per-test seconds from a GitHub job log of a serial run
  groups    split a --list into one name file per module (test-map build)
  assemble  per-module coverage exports -> the test map (test-map build)
"""
from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import subprocess
import sys
from pathlib import Path

# A shard's target length. A shard cannot be shorter than its longest test
# (node_e2e_tests::small_trades_take_one_of_five_equal_vaults_and_large_ones_split,
# 1,125 s measured), so a target below that only buys more runners.
TARGET_SHARD_SECONDS = 15 * 60
MAX_SHARDS = 8
# Seconds assumed for a test the timing table has never seen.
DEFAULT_SECONDS_FLOOR = 1.0

MAP_VERSION = 1

# A changed line of this shape moves behaviour that coverage cannot attribute
# to the file it lives in: consts and statics are inlined where they are used,
# macro bodies expand at their call sites, included bytes are data. Any of
# them in a pull request runs every test.
RISKY_LINE = re.compile(
    r"^\s*(pub(\s*\([^)]*\))?\s+)?(const|static)\s"
    r"|macro_rules!"
    r"|include_(bytes|str)!"
)

# Directories of a crate whose files are never linked into another crate's
# library: changing them cannot change what the dsm_sdk library tests run.
NOT_LINKED_DIRS = ("tests/", "benches/", "examples/")

IGNORED_SUFFIXES = (".md",)


# ── names and modules ────────────────────────────────────────────────────────


def module_key(test_name: str) -> str:
    """The module a test belongs to for selection: its first two path
    segments (`handlers::node_e2e_tests`), or one for a two-segment name
    (`tests::x` -> `tests`). A test at the crate root keys as `<root>`."""
    parts = test_name.split("::")
    depth = min(2, len(parts) - 1)
    return "::".join(parts[:depth]) if depth > 0 else "<root>"


def parse_list(text: str) -> list[str]:
    """Test names from `<binary> --list --format terse` (benchmarks dropped)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.endswith(": test"):
            out.append(line[: -len(": test")])
    if len(out) != len(set(out)):
        raise SystemExit("sdk_tests: the test list names a test twice")
    return out


# ── timings ──────────────────────────────────────────────────────────────────


GH_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z ")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def learn_times(log_text: str) -> dict[str, float]:
    """Per-test seconds from a GitHub job log of a --test-threads=1 run.

    Serial libtest prints `test NAME ... ` when a test starts; each test runs
    until the next one starts, the last until the `test result:` line. The
    timestamps are the ones GitHub stamps on every log line."""
    import datetime as dt

    def ts(line: str):
        m = GH_TS.match(line)
        return dt.datetime.fromisoformat(m.group(1)[:26]) if m else None

    starts: list[tuple[object, str]] = []
    end = None
    for raw in log_text.splitlines():
        line = ANSI.sub("", raw)
        t = ts(line)
        if t is None:
            continue
        body = line[GH_TS.match(line).end():]
        m = re.match(r"test (\S+) \.\.\. ", body)
        if m:
            starts.append((t, m.group(1)))
            continue
        # The first binary's result line ends the library run.
        if body.startswith("test result:") and starts:
            end = t
            break
    times: dict[str, float] = {}
    for i, (t, name) in enumerate(starts):
        nxt = starts[i + 1][0] if i + 1 < len(starts) else end
        if nxt is None:
            break
        times[name] = round(max((nxt - t).total_seconds(), 0.0), 1)
    return times


def read_times(path: Path) -> dict[str, float]:
    times = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            name, secs = line.split("\t")
            times[name] = float(secs)
    return times


def write_times(path: Path, times: dict[str, float], source: str) -> None:
    lines = [
        "# Seconds per dsm_sdk library test, measured on a GitHub runner (release,",
        "# --test-threads=1). Balances the CI shards only: a stale or missing entry",
        "# makes shards uneven, never skips a test. Refresh with",
        "#   python3 ci/sdk_tests.py learn --log <GitHub job log> --out ci/sdk_test_times.tsv",
        f"# Source: {source}",
    ]
    lines += [f"{n}\t{s:.1f}" for n, s in sorted(times.items())]
    path.write_text("\n".join(lines) + "\n")


def default_seconds(times: dict[str, float]) -> float:
    return max(statistics.median(times.values()), DEFAULT_SECONDS_FLOOR) if times else DEFAULT_SECONDS_FLOOR


# ── sharding ─────────────────────────────────────────────────────────────────


def shard_count(seconds: float) -> int:
    return max(1, min(MAX_SHARDS, math.ceil(seconds / TARGET_SHARD_SECONDS)))


def partition(names: list[str], times: dict[str, float], shards: int) -> list[list[str]]:
    """Longest-processing-time-first: deterministic for a given list, table
    and count, so every shard computes the same partition independently.
    Each name lands in exactly one shard."""
    d = default_seconds(times)
    load = [0.0] * shards
    out: list[list[str]] = [[] for _ in range(shards)]
    for name in sorted(names, key=lambda n: (-times.get(n, d), n)):
        k = min(range(shards), key=lambda i: (load[i], i))
        out[k].append(name)
        load[k] += times.get(name, d)
    return [sorted(s) for s in out]


def chosen_tests(names: list[str], selection: dict) -> list[str]:
    if selection["mode"] == "all":
        return list(names)
    selected = set(selection["modules"])
    known = set(selection["known_modules"])
    return [n for n in names if module_key(n) in selected or module_key(n) not in known]


# ── selection ────────────────────────────────────────────────────────────────


def changed_files(base: str, head: str) -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def changed_lines(base: str, head: str, path: str) -> list[str]:
    out = subprocess.run(
        ["git", "diff", "-U0", f"{base}...{head}", "--", path],
        capture_output=True, text=True, check=True,
    ).stdout
    return [
        line[1:] for line in out.splitlines()
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    ]


def owning_root(path: str, roots: list[str]) -> str | None:
    best = None
    for r in roots:
        # "." is a package at the repository root: it owns every path.
        prefix = "" if r in ("", ".") else r.rstrip("/") + "/"
        if path.startswith(prefix) and (best is None or len(prefix) > len(best[1])):
            best = (r, prefix)
    return best[1] if best else None


def select_tests(test_map: dict | None, files: list[str], full: bool, lines_of) -> tuple[dict, str]:
    """(selection, reason). selection = {"mode": "all"} or
    {"mode": "impact", "modules": [...], "known_modules": [...]}."""
    everything = {"mode": "all"}
    if full:
        return everything, "the run is FULL"
    if test_map is None:
        return everything, "no test map from main"
    if test_map.get("version") != MAP_VERSION or not test_map.get("complete"):
        return everything, "the test map is incomplete or of another version"

    map_files = test_map["files"]
    index = {f: i for i, f in enumerate(map_files)}
    covering: dict[int, set[str]] = {}
    for key, idxs in test_map["modules"].items():
        for i in idxs:
            covering.setdefault(i, set()).add(key)

    selected: set[str] = set()
    considered = []
    for f in files:
        if f.endswith(IGNORED_SUFFIXES):
            continue
        root = owning_root(f, test_map["dep_roots"])
        if root is None:
            continue  # not part of any crate the dsm_sdk test binary links
        rel = f[len(root):]
        if rel.startswith(NOT_LINKED_DIRS):
            continue
        considered.append(f)
        if f not in index:
            return everything, f"{f} is in a crate the suite links, but the map never saw it"
        mods = covering.get(index[f], set())
        if not mods:
            return everything, f"{f} is linked in, but no test module executes it"
        for line in lines_of(f):
            if RISKY_LINE.search(line):
                return everything, f"{f} changes a line coverage cannot attribute: {line.strip()[:80]}"
        selected |= mods

    selection = {
        "mode": "impact",
        "modules": sorted(selected),
        "known_modules": sorted(test_map["modules"]),
    }
    reason = (
        f"{len(considered)} changed file(s) the suite links -> "
        f"{len(selected)} of {len(test_map['modules'])} test modules"
    )
    return selection, reason


def estimated_seconds(selection: dict, times: dict[str, float]) -> float:
    if selection["mode"] == "all":
        return sum(times.values())
    chosen = chosen_tests(list(times), selection)
    return sum(times[n] for n in chosen)


def selection_outputs(selection: dict, reason: str, times: dict[str, float]) -> list[str]:
    secs = estimated_seconds(selection, times)
    n = shard_count(secs)
    # Impact mode can still be handed tests the timing table does not know
    # (new modules), so it never asks for zero shards.
    matrix = [{"shard": k, "of": n} for k in range(1, n + 1)]
    return [
        f"sdk_mode={selection['mode']}",
        f"sdk_shards={json.dumps(matrix)}",
        f"sdk_summary={reason}; ~{secs / 60:.0f} min of tests on {n} shard(s)",
    ]


# ── the test map ─────────────────────────────────────────────────────────────


def dep_roots(metadata: dict, root: Path, package: str = "dsm_sdk") -> list[str]:
    """Directories of every path (workspace) package the `package` test binary
    can link: its normal, dev and build dependencies, then everything those
    reach. Over-including is safe: a root only makes more files count."""
    pkgs = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    start = next(p["id"] for p in metadata["packages"] if p["name"] == package and p["source"] is None)
    seen, stack = {start}, [start]
    while stack:
        for dep in nodes[stack.pop()]["deps"]:
            if dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                stack.append(dep["pkg"])
    out = set()
    for pid in seen:
        p = pkgs[pid]
        if p["source"] is None:
            d = Path(p["manifest_path"]).parent.resolve()
            try:
                out.add(str(d.relative_to(root.resolve())))
            except ValueError:
                continue  # a path dependency outside the repository
    return sorted(out)


def assemble_map(exports: dict[str, dict], failed: set[str], roots: list[str],
                 root: Path, commit: str) -> dict:
    """exports: module key -> `llvm-cov export -summary-only` JSON."""
    rootp = str(root.resolve()).rstrip("/") + "/"

    def rel(path: str) -> str | None:
        return path[len(rootp):] if path.startswith(rootp) else None

    files: set[str] = set()
    covered: dict[str, set[str]] = {}
    for key, doc in exports.items():
        hit = covered.setdefault(key, set())
        for f in doc["data"][0]["files"]:
            r = rel(f["filename"])
            if r is None:
                continue
            files.add(r)
            s = f["summary"]
            if s["lines"]["covered"] > 0 or s["regions"]["covered"] > 0:
                hit.add(r)
    ordered = sorted(files)
    index = {f: i for i, f in enumerate(ordered)}
    return {
        "version": MAP_VERSION,
        "commit": commit,
        "complete": not failed and bool(exports),
        "failed_modules": sorted(failed),
        "dep_roots": roots,
        "files": ordered,
        "modules": {k: sorted(index[f] for f in v) for k, v in sorted(covered.items())},
    }


# ── checking a shard ─────────────────────────────────────────────────────────


RESULT = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def ran_count(log_text: str) -> int:
    total = 0
    for m in RESULT.finditer(ANSI.sub("", log_text)):
        total += int(m.group(1)) + int(m.group(2)) + int(m.group(3))
    return total


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    here = Path(__file__).parent
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("select")
    s.add_argument("--map", default="none")
    s.add_argument("--base", default="")
    s.add_argument("--head", default="HEAD")
    s.add_argument("--full", default="false")
    s.add_argument("--times", default=str(here / "sdk_test_times.tsv"))
    s.add_argument("--out", required=True)

    p = sub.add_parser("plan")
    p.add_argument("--list", required=True)
    p.add_argument("--selection", required=True)
    p.add_argument("--times", default=str(here / "sdk_test_times.tsv"))
    p.add_argument("--shard", type=int, required=True)
    p.add_argument("--of", type=int, required=True)

    c = sub.add_parser("check")
    c.add_argument("--log", required=True)
    c.add_argument("--expect", type=int, required=True)

    lr = sub.add_parser("learn")
    lr.add_argument("--log", required=True)
    lr.add_argument("--source", default="")
    lr.add_argument("--out", required=True)

    g = sub.add_parser("groups")
    g.add_argument("--list", required=True)
    g.add_argument("--out-dir", required=True)

    a = sub.add_parser("assemble")
    a.add_argument("--groups-dir", required=True)
    a.add_argument("--exports-dir", required=True)
    a.add_argument("--metadata", required=True)
    a.add_argument("--root", required=True)
    a.add_argument("--commit", required=True)
    a.add_argument("--package", default="dsm_sdk")
    a.add_argument("--out", required=True)

    args = ap.parse_args()

    if args.cmd == "select":
        full = args.full.strip().lower() == "true"
        test_map = None
        if args.map != "none" and Path(args.map).exists():
            test_map = json.loads(Path(args.map).read_text())
        if full or test_map is None or not args.base:
            files = []
            full = full or not args.base
        else:
            files = changed_files(args.base, args.head)
        selection, reason = select_tests(
            test_map, files, full, lambda f: changed_lines(args.base, args.head, f)
        )
        if test_map is not None:
            selection["map_commit"] = test_map.get("commit")
        Path(args.out).write_text(json.dumps(selection, indent=1) + "\n")
        for line in selection_outputs(selection, reason, read_times(Path(args.times))):
            print(line)
        print(f"sdk_tests: {reason}", file=sys.stderr)
        return 0

    if args.cmd == "plan":
        names = parse_list(Path(args.list).read_text())
        selection = json.loads(Path(args.selection).read_text())
        chosen = chosen_tests(names, selection)
        if not 1 <= args.shard <= args.of:
            raise SystemExit(f"sdk_tests: shard {args.shard} of {args.of}")
        mine = partition(chosen, read_times(Path(args.times)), args.of)[args.shard - 1]
        for n in mine:
            print(n)
        print(
            f"sdk_tests: {len(names)} listed, {len(chosen)} chosen ({selection['mode']}), "
            f"shard {args.shard}/{args.of} runs {len(mine)}",
            file=sys.stderr,
        )
        return 0

    if args.cmd == "check":
        ran = ran_count(Path(args.log).read_text(errors="replace"))
        if ran != args.expect:
            print(f"::error::this shard was given {args.expect} tests and the log shows {ran} run")
            return 1
        print(f"sdk_tests: shard ran exactly its {ran} tests")
        return 0

    if args.cmd == "learn":
        times = learn_times(Path(args.log).read_text(errors="replace"))
        if not times:
            raise SystemExit("sdk_tests: no serial test starts with timestamps in that log")
        write_times(Path(args.out), times, args.source or args.log)
        print(f"sdk_tests: {len(times)} tests, {sum(times.values()) / 60:.1f} min", file=sys.stderr)
        return 0

    if args.cmd == "groups":
        names = parse_list(Path(args.list).read_text())
        by: dict[str, list[str]] = {}
        for n in names:
            by.setdefault(module_key(n), []).append(n)
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "index.tsv", "w") as idx:
            for i, key in enumerate(sorted(by)):
                (out / f"{i}.txt").write_text("\n".join(by[key]) + "\n")
                idx.write(f"{i}\t{key}\n")
        print(f"sdk_tests: {len(names)} tests in {len(by)} modules", file=sys.stderr)
        return 0

    if args.cmd == "assemble":
        gdir, edir = Path(args.groups_dir), Path(args.exports_dir)
        exports, failed = {}, set()
        for line in (gdir / "index.tsv").read_text().splitlines():
            i, key = line.split("\t")
            if (gdir / f"{i}.failed").exists():
                failed.add(key)
            exp = edir / f"{i}.json"
            if exp.exists():
                exports[key] = json.loads(exp.read_text())
            else:
                failed.add(key)
        metadata = json.loads(Path(args.metadata).read_text())
        root = Path(args.root)
        test_map = assemble_map(exports, failed, dep_roots(metadata, root, args.package), root, args.commit)
        Path(args.out).write_text(json.dumps(test_map, separators=(",", ":")) + "\n")
        print(
            f"sdk_tests: map of {len(test_map['modules'])} modules over {len(test_map['files'])} files; "
            f"complete={test_map['complete']} failed={test_map['failed_modules']}",
            file=sys.stderr,
        )
        return 0 if test_map["complete"] else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
