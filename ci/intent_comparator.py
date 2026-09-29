#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# ci/intent_comparator.py: what the specifications say the code must do (the
# intent manifest, specs/requirements/INTENT_MANIFEST.tsv) against what the
# code does (the requirement map). The map decides nothing about intent and
# this decides nothing about code: one table maps each row's intent and the
# map's reading to an outcome, the outcome to an action, and the policy says
# which outcomes fail.
#
#   python3 ci/intent_comparator.py --map target/requirement-map \
#       [--manifest specs/requirements/INTENT_MANIFEST.tsv] [--built android,node] \
#       [--requirements FILE] [--expect FILE]
#   python3 ci/intent_comparator.py root-queries [--manifest FILE]
#
# `root-queries` prints the (artifact, root, symbol) questions the manifest's
# `root` column asks; `requirement_map index --root-queries` answers them with
# the map's own reachability from that one root (root-queries.tsv).
#
# Requirements come from MASTER and CONFORMANCE §8 through
# ci/conformance_evidence.py (the one Markdown parser); `--requirements` names
# a TSV of `id status` instead (the fixture's). A row whose requirement §8
# holds Partial, Missing or Violated reports a gap as the known hole and does
# not fail.

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import requirement_map as rmap

MANIFEST = "specs/requirements/INTENT_MANIFEST.tsv"
COLUMNS = ("requirement", "symbol", "artifact", "reachability", "lifecycle", "root", "evidence", "exception", "cites")
REACHABILITY = ("MUST_REACH", "MUST_REACH_DIRECT", "MAY_REACH", "MUST_NOT_REACH")
LIFECYCLES = ("active", "target-specific", "deprecated", "test-only")
# Every outcome, and what to do about it.
OUTCOMES = {
    "SATISFIED": "leave it alone",
    "CORRECT": "leave it alone",
    "WIRING_GAP": "wire it in: nothing reaches it",
    "ARTIFACT_GAP": "put it in the build: the build does not compile it",
    "UNDECIDED": "resolve the map's reason: it cannot decide",
    "DIRECT_PATH_GAP": "call it directly: only a dispatch reaches it",
    "ROOT_MISMATCH": "reach it from the named entry point",
    "UNEXPECTED_LIVE_PATH": "cut the path that reaches it",
    "PRODUCTION_LEAK": "cut the production path to test-only code",
    "REMOVAL_CANDIDATE": "remove what reaches it, then delete it",
    "DELETE": "delete it",
    "MISSING_SYMBOL": "correct the row's path, or restore the symbol",
    "AMBIGUOUS_SYMBOL": "name one definition: the path names several",
    "UNSPECIFIED": "declare its intent",
}
# What an UNSPECIFIED definition's reading asks for. Reported only: the map's
# reading never becomes intent (owner ruling, 2026-09-29).
UNSPECIFIED_ACTIONS = {
    "dead": "a removal candidate: no shipped build reaches it; declare its intent or remove it after review",
    "indeterminate": "undecided: the map cannot decide; declare its intent from the specifications",
    "reached": "declare its intent",
}
FAILING = ("WIRING_GAP", "ARTIFACT_GAP", "UNDECIDED", "DIRECT_PATH_GAP", "ROOT_MISMATCH",
           "UNEXPECTED_LIVE_PATH", "PRODUCTION_LEAK", "MISSING_SYMBOL", "AMBIGUOUS_SYMBOL")
# §8 statuses under which a gap is the requirement's known hole.
KNOWN_HOLE = ("Partial", "Missing", "Violated")
# Readings that mean "not compiled into this build".
OUTSIDE_BUILD = ("not-in-artifact",)


class Refused(Exception):
    pass


def _rows(path, columns):
    """A committed TSV's rows (comment lines start with `#`), checked against
    its header."""
    with open(path, encoding="utf-8") as fh:
        lines = [l for l in fh.read().split("\n") if l and not l.startswith("#")]
    if not lines:
        raise Refused(f"{path}: no header")
    header = tuple(lines[0].split("\t"))
    if header != columns:
        raise Refused(f"{path}: columns {header}, not {columns}")
    out = []
    for n, line in enumerate(lines[1:], start=2):
        cells = line.split("\t")
        if len(cells) != len(columns):
            raise Refused(f"{path}: {len(cells)} cells in data row {n - 1}: {line!r}")
        out.append(dict(zip(columns, cells)))
    return out


def read_manifest(path, statuses, artifacts):
    """The manifest's rows, each checked for a shape the comparator can read:
    known values, a requirement MASTER defines (or `-`), and the exception a
    row declaring an exclusion, a deprecation or no requirement must give."""
    rows = _rows(path, COLUMNS)
    faults = []
    seen = set()
    for n, r in enumerate(rows, start=1):
        at = f"{path} row {n} ({r['symbol']})"
        if r["reachability"] not in REACHABILITY:
            faults.append(f"{at}: reachability {r['reachability']!r} is not one of {REACHABILITY}")
        if r["lifecycle"] not in LIFECYCLES:
            faults.append(f"{at}: lifecycle {r['lifecycle']!r} is not one of {LIFECYCLES}")
        if r["artifact"] not in artifacts:
            faults.append(f"{at}: artifact {r['artifact']!r} is not one of the map's {artifacts}")
        if r["requirement"] != "-" and r["requirement"] not in statuses:
            faults.append(f"{at}: {r['requirement']} is no requirement MASTER defines")
        needs_exception = (r["reachability"] == "MUST_NOT_REACH" or r["lifecycle"] in ("deprecated", "target-specific")
                           or r["requirement"] == "-")
        if needs_exception and r["exception"] in ("", "-"):
            faults.append(f"{at}: an exclusion, a deprecation or a row with no requirement gives its exception")
        if r["requirement"] == "-" and r["reachability"] in ("MUST_REACH", "MUST_REACH_DIRECT"):
            faults.append(f"{at}: only a requirement can say a symbol must be reached")
        if r["lifecycle"] == "test-only" and r["reachability"] != "MUST_NOT_REACH":
            faults.append(f"{at}: test-only code is MUST_NOT_REACH in a shipped build")
        if r["cites"] in ("", "-"):
            faults.append(f"{at}: no citation: every intent comes from a spec clause or a CONFORMANCE §8 row")
        key = (r["requirement"], r["symbol"], r["artifact"])
        if key in seen:
            faults.append(f"{at}: a second row for {key}")
        seen.add(key)
    if faults:
        raise Refused("the manifest is malformed:\n  " + "\n  ".join(faults))
    return rows


def requirement_statuses(path):
    if path:
        return {r["id"]: r["status"] for r in _rows(path, ("id", "status"))}
    import conformance_evidence
    try:
        return conformance_evidence.requirement_statuses()
    except ValueError as e:
        raise Refused(str(e))


def root_answers(map_dir):
    """The map's answers to the root queries: (artifact, root, symbol) ->
    (state, code). None when the map was built without any."""
    path = os.path.join(map_dir, "root-queries.tsv")
    if not os.path.exists(path):
        return None
    return {(r["artifact"], r["root"], r["symbol"]): (r["state"], r["code"])
            for r in _rows(path, ("artifact", "root", "symbol", "state", "code"))}


def reading_of(by_path, symbol, artifact):
    """What a row's path names in its artifact: ("missing"|"ambiguous"|
    "no-reading"|"read", reading). Only definitions the build compiles are
    candidates: another profile's definition of the same path (host-only
    code, which the artifact reads as not-in-artifact) is not one it reads.
    With none compiled, the row reads not-in-artifact."""
    defs = by_path.get(symbol, [])
    if not defs:
        return "missing", None
    readings = [d["reach"][artifact] for d in defs if artifact in d["reach"]]
    compiled = [r for r in readings if r["state"] not in OUTSIDE_BUILD]
    if len(compiled) > 1:
        return "ambiguous", None
    if compiled:
        return "read", compiled[0]
    if readings:
        return "read", readings[0]
    return "no-reading", None


def outcome(row, found, reading, root_answer):
    """The one table: a row's intent and the map's reading -> an outcome."""
    if found == "missing":
        return "MISSING_SYMBOL"
    if found == "ambiguous":
        return "AMBIGUOUS_SYMBOL"
    state = reading["state"] if reading is not None else "not-in-artifact"
    code = reading["code"] if reading is not None else "NOT_IN_ARTIFACT"
    if row["lifecycle"] == "deprecated":
        return "REMOVAL_CANDIDATE" if state in ("reached", "indeterminate", "not-built") else "DELETE"
    want = row["reachability"]
    if want == "MAY_REACH":
        return "CORRECT"
    if want == "MUST_NOT_REACH":
        if state == "reached":
            return "PRODUCTION_LEAK" if row["lifecycle"] == "test-only" else "UNEXPECTED_LIVE_PATH"
        if state in ("indeterminate", "not-built"):
            return "UNDECIDED"
        return "CORRECT"
    # MUST_REACH, MUST_REACH_DIRECT
    if state in ("indeterminate", "not-built"):
        return "UNDECIDED"
    if state == "dead":
        return "WIRING_GAP"
    if state in OUTSIDE_BUILD:
        return "ARTIFACT_GAP"
    if want == "MUST_REACH_DIRECT" and code != "REACHED":
        return "DIRECT_PATH_GAP"
    if root_answer is not None:
        root_state, root_code = root_answer
        if root_state == "indeterminate":
            return "UNDECIDED"
        if root_state != "reached":
            return "ROOT_MISMATCH"
        if want == "MUST_REACH_DIRECT" and root_code != "REACHED":
            return "DIRECT_PATH_GAP"
    return "SATISFIED"


def compare(the_map, rows, statuses, answers, built):
    """Every row's outcome, and the production definitions no row names. A
    root is checked to be an entry point of a build this host indexed; a row
    of another build reads not-built, and so UNDECIDED, whatever it names."""
    by_path = collections.defaultdict(list)
    entry_points = collections.defaultdict(set)
    for d in the_map["defs"]:
        if d["path"]:
            by_path[d["path"]].append(d)
        for pair in filter(None, d["root"].split(",")):
            artifact, _, kind = pair.partition(":")
            if kind not in rmap.NOT_ROOTS:
                entry_points[artifact].add(d["path"])
    wrong = [f"{r['symbol']}: {r['root']} is no entry point of the {r['artifact']} build"
             for r in rows if r["root"] != "-" and r["artifact"] in built
             and r["root"] not in entry_points[r["artifact"]]]
    if wrong:
        raise Refused("the manifest names a root that is not an entry point:\n  " + "\n  ".join(wrong))
    results = []
    for r in rows:
        found, reading = reading_of(by_path, r["symbol"], r["artifact"])
        answer = None
        if r["root"] != "-" and found == "read":
            if answers is None:
                raise Refused("the manifest names entry points, and the map answered no root query: build it with "
                              "`requirement_map index --root-queries` (make requirement-map does)")
            key = (r["artifact"], r["root"], r["symbol"])
            if key not in answers:
                raise Refused(f"the map answered no root query for {key}: rebuild it with this manifest's queries")
            answer = answers[key]
        o = outcome(r, found, reading, answer)
        status = statuses.get(r["requirement"])
        hole = o in FAILING and status in KNOWN_HOLE
        results.append({**r, "state": reading["state"] if reading else found, "code": reading["code"] if reading else "-",
                        "outcome": o, "action": OUTCOMES[o], "status": status or "-",
                        "fails": "known-hole" if hole else ("fails" if o in FAILING else "-")})
    named = {(r["symbol"], r["artifact"]) for r in rows}
    unspecified = []
    for d in the_map["defs"]:
        if not d["path"] or not rmap.markable(d):
            continue
        for artifact, reading in d["reach"].items():
            if reading["state"] in OUTSIDE_BUILD + ("not-built",) or (d["path"], artifact) in named:
                continue
            unspecified.append((artifact, d["path"], reading["state"], reading["code"],
                                UNSPECIFIED_ACTIONS[reading["state"]]))
    return results, unspecified


REPORT_COLUMNS = COLUMNS + ("state", "code", "outcome", "action", "status", "fails")


def write_report(results, unspecified, map_dir):
    with open(os.path.join(map_dir, "intent.tsv"), "w", encoding="utf-8") as fh:
        fh.write("\t".join(REPORT_COLUMNS) + "\n")
        for r in results:
            fh.write("\t".join(r[c] for c in REPORT_COLUMNS) + "\n")
    with open(os.path.join(map_dir, "unspecified.tsv"), "w", encoding="utf-8") as fh:
        fh.write("artifact\tpath\tstate\tcode\taction\n")
        for row in sorted(unspecified):
            fh.write("\t".join(row) + "\n")


def check_expected(results, path):
    """The fixture's rows' outcomes against the committed expectation."""
    wanted = [(r["requirement"], r["symbol"], r["artifact"], r["reachability"], r["lifecycle"], r["root"],
               r["outcome"], r["fails"])
              for r in _rows(path, ("requirement", "symbol", "artifact", "reachability", "lifecycle", "root",
                                    "outcome", "fails"))]
    got = [(r["requirement"], r["symbol"], r["artifact"], r["reachability"], r["lifecycle"], r["root"],
            r["outcome"], r["fails"]) for r in results]
    faults = []
    for w, g in zip(wanted, got):
        if w != g:
            faults.append(f"expected {w[6]} ({w[7]}) for {w[:6]}, the comparator says {g[6]} ({g[7]})")
    if len(wanted) != len(got):
        faults.append(f"{len(wanted)} expected rows, {len(got)} manifest rows")
    return faults


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("query", nargs="*", help="root-queries, or nothing to compare")
    ap.add_argument("--map")
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--requirements", help="a TSV of `id status` in place of MASTER and CONFORMANCE §8")
    ap.add_argument("--built", default="", help="artifacts that must have been indexed (CI: android,node)")
    ap.add_argument("--expect", help="the fixture's expected outcomes")
    ap.add_argument("--report", help="where intent.tsv and unspecified.tsv go (default: --map)")
    args = ap.parse_args()
    try:
        if args.query == ["root-queries"]:
            rows = _rows(args.manifest, COLUMNS)
            print("artifact\troot\tsymbol")
            for r in rows:
                if r["root"] != "-":
                    print(f"{r['artifact']}\t{r['root']}\t{r['symbol']}")
            return 0
        if args.query or not args.map:
            ap.error("compare with --map DIR, or print the root queries with `root-queries`")
        the_map = rmap.load(args.map)
        built = rmap.built_artifacts(the_map)
        for a in filter(None, args.built.split(",")):
            if a not in built:
                raise Refused(f"{a} was not indexed on this host, and --built requires it")
        statuses = requirement_statuses(args.requirements)
        rows = read_manifest(args.manifest, statuses, the_map["artifacts"])
        results, unspecified = compare(the_map, rows, statuses, root_answers(args.map), built)
    except Refused as e:
        # On stderr: `root-queries`' stdout is redirected into a file, and a
        # refusal must reach whoever runs it.
        print(f"intent comparator: {e}", file=sys.stderr)
        return 1
    write_report(results, unspecified, args.report or args.map)
    unbuilt = [a for a in the_map["artifacts"] if a not in built]
    counts = collections.Counter(r["outcome"] for r in results)
    print(f"intent: {len(results)} rows")
    for o in OUTCOMES:
        if counts[o]:
            print(f"  {o:<22} {counts[o]:>5}  {OUTCOMES[o]}")
    by_reading = collections.Counter((a, state) for a, _, state, *_ in unspecified)
    for (a, state) in sorted(by_reading):
        print(f"  UNSPECIFIED ({a}, {state}) {by_reading[(a, state)]:>5}  {UNSPECIFIED_ACTIONS[state]} (reported, never fails)")
    for a in unbuilt:
        print(f"  {a}: not indexed on this host; its rows read not-built (UNDECIDED)")
    failing = [r for r in results if r["fails"] == "fails"]
    holes = [r for r in results if r["fails"] == "known-hole"]
    for r in failing:
        print(f"  [{r['outcome']}] {r['requirement']} {r['symbol']} ({r['artifact']}): {r['state']} {r['code']}")
    if holes:
        print(f"  {len(holes)} gap(s) are their requirements' known holes (§8 {'/'.join(KNOWN_HOLE)})")
    faults = check_expected(results, args.expect) if args.expect else []
    for f in faults:
        print(f"  [expected] {f}")
    print(f"{len(failing)} failing row(s)" + (f", {len(faults)} unexpected outcome(s)" if args.expect else ""))
    if args.expect:
        return 1 if faults else 0
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
