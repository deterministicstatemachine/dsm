#!/usr/bin/env python3
# ci/sofi_reachability.py: every public SoFi function has a production caller
# (Gate G1), decided on the call graph.
#
#   python3 ci/sofi_reachability.py --map DIR      (DIR from `make requirement-map`)
#
# A `pub fn` under CORE/sofi passes when a production entry point reaches it:
# the JNI exports, `JNI_OnLoad`, `dsm_init_runtime` and the storage node's
# `main`, through calls rust-analyzer resolved in the Android build's view
# (tools/requirement_map). Production code is ci/requirement_map.py's
# classification: ci/production_text.py's rule, tests/ directories, and files
# their parent declares `#[cfg(test)]`.
#
# The text matcher this replaces counted a call when the name was in scope at
# a call site. It could not see whether the caller itself ran: `first_member`
# passed through `position_leader`, which nothing calls. A caller now counts
# only when production reaches it.
#
# The baseline: ci/sofi_reachability_baseline.txt lists functions that the
# rebuild (R1..R14) has not wired yet, one per line as `path fn  # R<n>`. A
# function that is unreached AND not in the baseline fails. A function that is
# in the baseline AND now reached fails too: its line must be deleted in the
# change that wires it, so the baseline only ever shrinks. R14 deletes the
# file; G1 then passes with no exceptions.
import argparse
import importlib.util
import os
import re
import sys

BASELINE = "ci/sofi_reachability_baseline.txt"
CORE_SOFI = "dsm_client/deterministic_state_machine/dsm/src/sofi/"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=1, help="a requirement_map directory (make requirement-map)")
    args = ap.parse_args()
    spec = importlib.util.spec_from_file_location("requirement_map", "ci/requirement_map.py")
    requirement_map = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(requirement_map)
    the_map = requirement_map.load(args.map)

    sources = {}
    reached, unreached = set(), set()
    for d in the_map["defs"]:
        if d["kind"] != "callable" or d["container"] or d["scope"] != "production" or not d["file"].startswith(CORE_SOFI):
            continue
        if d["file"] not in sources:
            with open(d["file"], encoding="utf-8") as fh:
                sources[d["file"]] = fh.read().split("\n")
        text = "\n".join(sources[d["file"]][d["start_line"] - 1 : d["end_line"]])
        if not re.search(r"^\s*pub fn " + re.escape(d["name"]) + r"\b", text, re.M):
            continue
        key = f"{d['file']} {d['name']}"
        (reached if d["reached"] == "1" else unreached).add(key)

    baseline = set()
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    baseline.add(line)

    failures = []
    for u in sorted(unreached - baseline):
        failures.append(f"[FAIL] no production entry point reaches: {u}")
    for b in sorted(baseline):
        if b in reached:
            failures.append(f"[FAIL] baseline entry is now reached; delete its line: {b}")
        elif b not in unreached:
            failures.append(f"[FAIL] baseline entry is not a pub fn under CORE/sofi: {b}")
    for f in failures:
        print(f)
    still = len(unreached & baseline)
    print(
        f"sofi reachability: {len(reached)} pub fn reached from production, {still} in the baseline"
        + (" (R14 deletes the baseline)" if still else "")
    )
    return len(failures) and 1


if __name__ == "__main__":
    sys.exit(main())
