#!/usr/bin/env python3
"""The dsm_sdk library tests, split across parallel runners.

The suite is ~1,460 tests run one at a time (--test-threads=1: they share
process-global state): about 160 minutes of tests, which was nearly all of a
three-hour CI run as one job. When CI's layer selection runs the SDK layer,
this splits its library tests across shards balanced by each test's measured
time (ci/sdk_test_times.tsv), so the suite takes about as long as its longest
test (~21 minutes).

Subcommands:
  shards  how many shards (GitHub output for the select job's matrix)
  plan    one shard's exact test names, from the live --list of the binary
  check   the shard ran exactly the tests it was given, no more, no fewer
  learn   per-test seconds from GitHub job logs of serial runs
"""
from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from pathlib import Path

# A shard's target length. No shard can be shorter than the longest test
# (node_e2e_tests::the_trader_that_realizes_generation_32_publishes_its_segments_checkpoint,
# 21.4 min measured 2026-11-09): with 8 shards every shard is already within
# 2 minutes of it, so more runners would buy nothing.
TARGET_SHARD_SECONDS = 20 * 60
MAX_SHARDS = 8
# Seconds assumed for a test the timing table has never seen.
DEFAULT_SECONDS_FLOOR = 1.0


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
TEST_LINE = re.compile(r"test (\S+) \.\.\. ?(.*)$")
VERDICTS = ("ok", "FAILED")


def learn_times(log_text: str) -> dict[str, float]:
    """Per-test seconds from a GitHub job log of a --test-threads=1 run.

    GitHub stamps a line when it ENDS. A test that prints nothing ends its
    `test NAME ... ok` line when it finishes; a test that prints ends its
    verdict line (`ok` alone) when it finishes. Serially, each test runs from
    the previous test's end (or the `running N tests` line) to its own."""
    import datetime as dt

    times: dict[str, float] = {}
    prev = None
    current = None
    for raw in log_text.splitlines():
        line = ANSI.sub("", raw)
        m = GH_TS.match(line)
        if not m:
            continue
        t = dt.datetime.fromisoformat(m.group(1)[:26])
        body = line[m.end():]
        if prev is None:
            if re.match(r"running \d+ tests?$", body.strip()):
                prev = t
            continue

        def finish(name):
            nonlocal prev
            times[name] = round(max((t - prev).total_seconds(), 0.0), 1)
            prev = t

        tm = TEST_LINE.match(body)
        if tm:
            name, rest = tm.group(1), tm.group(2).strip()
            if current is not None:
                finish(current)
                current = None
            if rest in VERDICTS or rest.startswith("ignored"):
                finish(name)
            else:
                current = name
            continue
        if current is not None and body.strip() in VERDICTS:
            finish(current)
            current = None
            continue
        # The first binary's result line ends the library run.
        if body.startswith("test result:"):
            if current is not None:
                finish(current)
            break
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
        "# makes shards uneven, never skips a test. Refresh from the shards' job logs:",
        "#   python3 ci/sdk_tests.py learn --log <job log> [--log <job log> ...] --out ci/sdk_test_times.tsv",
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


def shard_outputs(times: dict[str, float]) -> list[str]:
    secs = sum(times.values())
    n = shard_count(secs)
    matrix = [{"shard": k, "of": n} for k in range(1, n + 1)]
    return [
        f"sdk_shards={json.dumps(matrix)}",
        f"sdk_summary=~{secs / 60:.0f} min of dsm_sdk library tests on {n} shard(s)",
    ]


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
    times_default = str(here / "sdk_test_times.tsv")
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("shards")
    s.add_argument("--times", default=times_default)

    p = sub.add_parser("plan")
    p.add_argument("--list", required=True)
    p.add_argument("--times", default=times_default)
    p.add_argument("--shard", type=int, required=True)
    p.add_argument("--of", type=int, required=True)

    c = sub.add_parser("check")
    c.add_argument("--log", required=True)
    c.add_argument("--expect", type=int, required=True)

    lr = sub.add_parser("learn")
    lr.add_argument("--log", required=True, action="append")
    lr.add_argument("--source", default="")
    lr.add_argument("--out", required=True)

    args = ap.parse_args()

    if args.cmd == "shards":
        for line in shard_outputs(read_times(Path(args.times))):
            print(line)
        return 0

    if args.cmd == "plan":
        names = parse_list(Path(args.list).read_text())
        if not 1 <= args.shard <= args.of:
            raise SystemExit(f"sdk_tests: shard {args.shard} of {args.of}")
        mine = partition(names, read_times(Path(args.times)), args.of)[args.shard - 1]
        for n in mine:
            print(n)
        print(f"sdk_tests: {len(names)} listed, shard {args.shard}/{args.of} runs {len(mine)}", file=sys.stderr)
        return 0

    if args.cmd == "check":
        ran = ran_count(Path(args.log).read_text(errors="replace"))
        if ran != args.expect:
            print(f"::error::this shard was given {args.expect} tests and the log shows {ran} run")
            return 1
        print(f"sdk_tests: shard ran exactly its {ran} tests")
        return 0

    if args.cmd == "learn":
        times: dict[str, float] = {}
        for log in args.log:
            got = learn_times(Path(log).read_text(errors="replace"))
            if not got:
                raise SystemExit(f"sdk_tests: no serial test run with timestamps in {log}")
            times.update(got)
        write_times(Path(args.out), times, args.source or ", ".join(args.log))
        print(f"sdk_tests: {len(times)} tests, {sum(times.values()) / 60:.1f} min", file=sys.stderr)
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
