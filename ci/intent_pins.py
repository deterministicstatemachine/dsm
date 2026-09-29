#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# ci/intent_pins.py: the approved evidence snapshot of every requirement row of
# the intent manifest (specs/requirements/INTENT_PINS.tsv; owner rulings,
# 2026-09-29). The manifest says what should be true. A pin records, for one
# (requirement, symbol, artifact), the facts someone verified:
#   - the manifest row's cells, and their digest;
#   - the requirement's §8 status, the comparator's outcome and the map's
#     reading;
#   - the definition the path resolves to, and its closure (everything it
#     reaches, generated code included);
#   - the closure of every test its evidence names;
#   - the commit its evidence passed at, and the digest over all of it.
#
# The gate reruns no test. A pin binds the code and the tests' code, so any
# change to either makes the row stale, and only a board run on the tree that
# changed can refresh it: one key at a time, a code refresh by default, and
# any semantic change named with --accept.
#
#   python3 ci/intent_pins.py pin KEY --map DIR --board-log LOG... --tested-at REF
#   python3 ci/intent_pins.py repin KEY --map DIR --board-log LOG... --tested-at REF [--accept CLASS,...]
#   python3 ci/intent_pins.py unpin KEY
#   python3 ci/intent_pins.py pin-unpinned --map DIR --board-log LOG... --tested-at REF
#
# KEY is `requirement|symbol|artifact`. `pin-unpinned` is the one-time
# bootstrap: it creates a pin for every requirement row that has none, and
# never touches one that exists. ci/intent_comparator.py --pins checks every
# pin on every run.

import argparse
import collections
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PINS = "specs/requirements/INTENT_PINS.tsv"
TOOL = "target/release/requirement_map"
MANIFEST_CELLS = ("requirement", "symbol", "artifact", "reachability", "lifecycle", "root", "evidence", "exception",
                  "cites")
FACTS = MANIFEST_CELLS + ("row", "status", "outcome", "reading", "definition", "production", "tests")
COLUMNS = FACTS + ("tested_at", "pin")
# What a change to a pin's facts is, by class. `row` is not a class: it is the
# digest of the manifest cells, which their own classes name.
CLASSES = {
    "code": ("production", "tests"),
    "symbol": ("definition",),
    "reading": ("reading",),
    "outcome": ("outcome",),
    "status": ("status",),
    "root": ("root",),
    "reachability": ("reachability", "lifecycle"),
    "evidence": ("evidence",),
    "citation": ("cites",),
    "exception": ("exception",),
}
# The one class a plain repin accepts: the code changed, and its evidence
# passed on this tree. Every other class is named with --accept.
IMPLICIT = ("code",)
PIN_STATES = {
    "PINNED": "leave it alone",
    "UNPINNED": "pin it on its evidence: ci/intent_pins.py pin KEY",
    "PIN_STALE": "run its evidence on this tree and repin it, naming any change but code with --accept",
    "PIN_TAMPERED": "its digests do not match its facts: restore the committed pin, or repin it",
    "ORPHAN_PIN": "no manifest row has its key: unpin it",
}
HEADER = """# The approved evidence snapshot of every requirement row of the intent
# manifest (specs/requirements/INTENT_MANIFEST.tsv), written by
# ci/intent_pins.py and never by hand: a hand edit fails as PIN_TAMPERED.
# Each row holds the facts one (requirement, symbol, artifact) was verified
# with: the manifest cells and their digest (row), the §8 status, the
# comparator's outcome, the map's reading, the definition the path resolves
# to and its closure (production), each evidence test's closure (tests), the
# commit its evidence passed at (tested_at), and the digest over them all
# (pin). ci/intent_comparator.py --pins fails a row whose facts moved
# (PIN_STALE), a requirement row with no pin (UNPINNED), and a pin whose key
# the manifest no longer has (ORPHAN_PIN).
"""


class Refused(Exception):
    pass


def key_of(row):
    return (row["requirement"], row["symbol"], row["artifact"])


def key_text(key):
    return "|".join(key)


def parse_key(text):
    parts = text.split("|")
    if len(parts) != 3 or not all(parts):
        raise Refused(f"{text!r} is not a key: requirement|symbol|artifact")
    return tuple(parts)


def digests(tool, domain, lines):
    """One Base32 digest per line (its tab-separated cells), from the
    requirement_map binary: a DSM domain-separated BLAKE3."""
    if not lines:
        return []
    if not os.path.isfile(tool):
        raise Refused(f"{tool} is not built: `make requirement-map` builds it")
    with tempfile.TemporaryDirectory() as work:
        src, out = os.path.join(work, "in.tsv"), os.path.join(work, "out.txt")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("".join(line + "\n" for line in lines))
        run = subprocess.run([tool, "digest", "--domain", domain, "--in", src, "--out", out],
                             capture_output=True, text=True)
        if run.returncode != 0:
            raise Refused(f"{tool} digest: {run.stderr.strip()}")
        with open(out, encoding="utf-8") as fh:
            got = fh.read().split("\n")[:-1]
    if len(got) != len(lines):
        raise Refused(f"{tool} digest gave {len(got)} digests for {len(lines)} lines")
    return got


def test_closures(the_map):
    """A test's canonical name (ci/conformance_evidence.py's) -> its closure,
    read from the host test build: a library test by its path, an integration
    test in `<crate>/tests/<stem>.rs` named `crate::stem::rest`, which the map
    holds as `crate::rest` in that file. A name that does not resolve to one
    definition reads `absent:NAME` or `ambiguous:NAME`: the check reports it
    as a moved fact, and no pin is ever written over one."""
    by_path = collections.defaultdict(list)
    dirs = {}
    for d in the_map["defs"]:
        if not d["path"]:
            continue
        if "tests" in d["built_in"].split(","):
            by_path[d["path"]].append(d)
        at = d["file"].find("/src/")
        if at >= 0:
            dirs.setdefault(d["path"].split("::")[0], d["file"][: at + 1])

    def closure(name):
        found = by_path.get(name, [])
        parts = name.split("::")
        if not found and len(parts) >= 3 and parts[0] in dirs:
            file = f"{dirs[parts[0]]}tests/{parts[1]}.rs"
            found = [d for d in by_path.get("::".join([parts[0]] + parts[2:]), []) if d["file"] == file]
        if len(found) > 1:
            return f"ambiguous:{name}"
        return found[0]["closure"] if found else f"absent:{name}"

    return closure


def facts_of(results, the_map, tool):
    """Each requirement row's facts as the map and the comparator read them
    now, keyed by (requirement, symbol, artifact)."""
    rows = [r for r in results if r["requirement"] != "-"]
    closure = test_closures(the_map)
    row_digests = digests(tool, "manifest-row", ["\t".join(r[c] for c in MANIFEST_CELLS) for r in rows])
    out = {}
    for r, row_digest in zip(rows, row_digests):
        tests = "-" if r["evidence"] in ("", "-") else ";".join(closure(t) for t in r["evidence"].split(";"))
        out[key_of(r)] = {
            **{c: r[c] for c in MANIFEST_CELLS},
            "row": row_digest,
            "status": r["status"],
            "outcome": r["outcome"],
            "reading": f"{r['state']}:{r['code']}",
            "definition": r["definition"],
            "production": r["closure"],
            "tests": tests,
        }
    return out


def read_pins(path):
    """The committed pins, keyed; None when the file does not exist."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        lines = [l for l in fh.read().split("\n") if l and not l.startswith("#")]
    if not lines or tuple(lines[0].split("\t")) != COLUMNS:
        raise Refused(f"{path}: the header is not {COLUMNS}")
    pins = {}
    for n, line in enumerate(lines[1:], start=1):
        cells = line.split("\t")
        if len(cells) != len(COLUMNS):
            raise Refused(f"{path}: {len(cells)} cells in pin {n}")
        pin = dict(zip(COLUMNS, cells))
        if key_of(pin) in pins:
            raise Refused(f"{path}: a second pin for {key_text(key_of(pin))}")
        pins[key_of(pin)] = pin
    return pins


def sealed(facts, tested_at, tool):
    """The pin digests of facts: one per entry, over every fact and the
    commit, in column order."""
    lines = ["\t".join([f[c] for c in FACTS] + [t]) for f, t in zip(facts, tested_at)]
    return digests(tool, "row-evidence", lines)


def tampered(pins, tool):
    """Pins whose stored digests are not their stored facts': key -> why."""
    keys = list(pins)
    rows = digests(tool, "manifest-row", ["\t".join(pins[k][c] for c in MANIFEST_CELLS) for k in keys])
    seals = sealed([pins[k] for k in keys], [pins[k]["tested_at"] for k in keys], tool)
    out = {}
    for k, row_digest, seal in zip(keys, rows, seals):
        if pins[k]["row"] != row_digest:
            out[k] = "its row digest is not its manifest cells'"
        elif pins[k]["pin"] != seal:
            out[k] = "its pin digest is not its facts'"
    return out


def moved(old, new):
    """Each class whose facts differ: class -> [(fact, old, new)]."""
    out = collections.OrderedDict()
    for cls, columns in CLASSES.items():
        changes = [(c, old[c], new[c]) for c in columns if old[c] != new[c]]
        if changes:
            out[cls] = changes
    return out


def describe(changes):
    return "; ".join(f"{cls}: " + ", ".join(f"{c} {o} -> {n}" for c, o, n in facts) for cls, facts in changes.items())


def every_build(the_map, built):
    """Refused unless the map indexed every build: a closure is taken over
    every build's edges, so a map missing one reads every pin differently."""
    missing = [a for a in the_map["artifacts"] if a not in built]
    if missing:
        raise Refused(f"pins are read over a map of every build, and {', '.join(missing)} is not indexed here: "
                      "use CI's map (make requirement-map indexes the storage node on Linux only)")


def check(results, the_map, built, pins_path, tool):
    """Every requirement row's pin state, and every orphan pin:
    [(key, state, detail)]."""
    every_build(the_map, built)
    pins = read_pins(pins_path)
    if pins is None:
        raise Refused(f"{pins_path} does not exist: create the pins with `ci/intent_pins.py pin-unpinned`")
    current = facts_of(results, the_map, tool)
    bad = tampered(pins, tool)
    verdicts = []
    for k, facts in current.items():
        if k not in pins:
            verdicts.append((k, "UNPINNED", "no pin"))
        elif k in bad:
            verdicts.append((k, "PIN_TAMPERED", bad[k]))
        else:
            changes = moved(pins[k], facts)
            verdicts.append((k, "PIN_STALE", describe(changes)) if changes else (k, "PINNED", "-"))
    for k in pins:
        if k not in current:
            verdicts.append((k, "ORPHAN_PIN", "the manifest has no requirement row with this key"))
    return verdicts


def write_report(verdicts, out_dir):
    with open(os.path.join(out_dir, "pins.tsv"), "w", encoding="utf-8") as fh:
        fh.write("requirement\tsymbol\tartifact\tstate\taction\tdetail\n")
        for k, state, detail in verdicts:
            fh.write("\t".join(list(k) + [state, PIN_STATES[state], detail]) + "\n")


def summarize(verdicts):
    """Print the pin states; the number of failing ones."""
    counts = collections.Counter(v[1] for v in verdicts)
    print(f"pins: {len(verdicts)}")
    for state in PIN_STATES:
        if counts[state]:
            print(f"  {state:<22} {counts[state]:>5}  {PIN_STATES[state]}")
    failing = [(k, state, detail) for k, state, detail in verdicts if state != "PINNED"]
    for k, state, detail in failing[:200]:
        print(f"  [{state}] {key_text(k)}: {detail}")
    if len(failing) > 200:
        print(f"  ... and {len(failing) - 200} more (pins.tsv)")
    print(f"{len(failing)} failing pin(s)")
    return len(failing)


def write_pins(path, pins, order):
    """The pins, in the manifest's row order (`order`: its keys); a pin whose
    key the manifest no longer holds stays, after them, until it is unpinned
    (the check fails it as ORPHAN_PIN)."""
    rank = {k: n for n, k in enumerate(order)}
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(HEADER)
        fh.write("\t".join(COLUMNS) + "\n")
        for k in sorted(pins, key=lambda k: rank.get(k, len(order))):
            fh.write("\t".join(pins[k][c] for c in COLUMNS) + "\n")


def evidence_failures(facts_list, logs):
    """Why each named test is not evidence in the board logs: not a test,
    ignored, or not run and passed."""
    import conformance_evidence as ce
    index, stems = ce.build_index()
    results = ce.parse_logs(logs, stems)
    out = []
    for facts in facts_list:
        if facts["evidence"] in ("", "-"):
            continue
        for t in facts["evidence"].split(";"):
            if t not in index:
                out.append(f"{key_text(key_of(facts))}: {t} is no test")
                continue
            binary, cargo_path, loc, ignored = index[t]
            outcome = results.get((binary, cargo_path))
            if ignored:
                out.append(f"{key_text(key_of(facts))}: {t} is #[ignore]d ({loc})")
            elif outcome != "ok":
                out.append(f"{key_text(key_of(facts))}: {t} {outcome or 'did not run'} in the board logs")
    return out


def fresh(map_dir, tool):
    """Why the map was not built from this tree, or None when it was: its
    recorded tree hash against the tree's hash over the same files and
    inputs."""
    record = os.path.join(map_dir, "tree")
    if not os.path.exists(record):
        return f"{map_dir} records no tree: build it with make requirement-map"
    with open(record, encoding="utf-8") as fh:
        recorded = fh.read().strip()
    with tempfile.TemporaryDirectory() as work:
        out = os.path.join(work, "tree")
        run = subprocess.run([tool, "fingerprint", "--root", ".", "--files", os.path.join(map_dir, "sources.txt"),
                              "--inputs", os.path.join(map_dir, "inputs.txt"), "--out", out],
                             capture_output=True, text=True)
        if run.returncode != 0:
            raise Refused(f"{tool} fingerprint: {run.stderr.strip()}")
        with open(out, encoding="utf-8") as fh:
            now = fh.read().strip()
    return None if now == recorded else f"the map is of tree {recorded}, this tree is {now}: rebuild it"


def prepare(args):
    """The map's facts for the manifest now, the pins, the manifest's keys in
    order, and the commit the evidence ran at; refused unless the map is of
    this tree and this tree's code is that commit's."""
    import conformance_evidence as ce
    import intent_comparator as ic
    why = fresh(args.map, args.tool)
    if why:
        raise Refused(why)
    sha, why = ce.code_at(args.tested_at)
    if why:
        raise Refused(f"the evidence ran at {sha[:12]}, and {why}")
    evaluated = ic.evaluate(args.map, args.manifest, args.requirements, args.built)
    every_build(evaluated.map, evaluated.built)
    current = facts_of(evaluated.results, evaluated.map, args.tool)
    pins = read_pins(args.pins)
    return current, (pins if pins is not None else {}), [key_of(r) for r in evaluated.results], sha


def seal_new(facts_list, tested_at, tool):
    seals = sealed(facts_list, [tested_at] * len(facts_list), tool)
    return [{**f, "tested_at": tested_at, "pin": seal} for f, seal in zip(facts_list, seals)]


def unresolved(facts_list):
    """Each evidence test the map holds no single definition of: a pin binds a
    test's closure, so it is never written over one it cannot read."""
    out = []
    for facts in facts_list:
        for closure in facts["tests"].split(";"):
            if closure.startswith(("absent:", "ambiguous:")):
                what, name = closure.split(":", 1)
                out.append(f"{key_text(key_of(facts))}: the map holds {'no' if what == 'absent' else 'more than one'} "
                           f"definition of {name}")
    return out


def refuse_evidence(facts_list, logs):
    failures = unresolved(facts_list) + evidence_failures(facts_list, logs)
    if failures:
        raise Refused("the evidence did not pass on this tree:\n  " + "\n  ".join(failures))


def cmd_pin(args):
    current, pins, order, sha = prepare(args)
    key = parse_key(args.key)
    if key not in current:
        raise Refused(f"{key_text(key)} is no requirement row of the manifest")
    if key in pins:
        raise Refused(f"{key_text(key)} is pinned: `repin` it")
    refuse_evidence([current[key]], args.board_log)
    pins[key] = seal_new([current[key]], sha, args.tool)[0]
    write_pins(args.pins, pins, order)
    return f"pinned {key_text(key)} at {sha[:12]}"


def judge_repin(key, old, new, accepted):
    """Why `old` may not be repinned as `new` with the classes `accepted`
    named, or None when it may: every moved class but code is named, and
    nothing named that did not move."""
    unknown = [a for a in accepted if a not in CLASSES or a in IMPLICIT]
    if unknown:
        return f"--accept takes {', '.join(c for c in CLASSES if c not in IMPLICIT)}; not {', '.join(unknown)}"
    changes = moved(old, new)
    unaccepted = [c for c in changes if c not in IMPLICIT and c not in accepted]
    if unaccepted:
        return (f"{key_text(key)} moved beyond its code: {describe(changes)}\n"
                f"  accept each by name, having checked it: --accept {','.join(unaccepted)}")
    idle = [a for a in accepted if a not in changes]
    if idle:
        return f"--accept names {', '.join(idle)}, which did not move for {key_text(key)}"
    return None


def add_unpinned(pins, current):
    """The facts of every requirement row with no pin: the bootstrap's rows.
    A row that has a pin is never among them."""
    return [facts for k, facts in current.items() if k not in pins]


def cmd_repin(args):
    current, pins, order, sha = prepare(args)
    key = parse_key(args.key)
    if key not in pins:
        raise Refused(f"{key_text(key)} has no pin: `pin` it")
    if key not in current:
        raise Refused(f"{key_text(key)} is no requirement row of the manifest: `unpin` it")
    why = judge_repin(key, pins[key], current[key], [a for a in args.accept.split(",") if a])
    if why:
        raise Refused(why)
    changes = moved(pins[key], current[key])
    refuse_evidence([current[key]], args.board_log)
    pins[key] = seal_new([current[key]], sha, args.tool)[0]
    write_pins(args.pins, pins, order)
    return f"repinned {key_text(key)} at {sha[:12]}" + (f": {describe(changes)}" if changes else "")


def cmd_unpin(args):
    import intent_comparator as ic
    key = parse_key(args.key)
    pins = read_pins(args.pins)
    if pins is None or key not in pins:
        raise Refused(f"{key_text(key)} has no pin")
    rows = ic._rows(args.manifest, ic.COLUMNS)
    if key in {key_of(r) for r in rows if r["requirement"] != "-"}:
        raise Refused(f"{key_text(key)} is a requirement row of the manifest: a pin of a live row is only repinned")
    del pins[key]
    order = [key_of(r) for r in rows]
    write_pins(args.pins, pins, order)
    return f"unpinned {key_text(key)}"


def cmd_pin_unpinned(args):
    current, pins, order, sha = prepare(args)
    new = add_unpinned(pins, current)
    if not new:
        raise Refused("every requirement row is pinned")
    refuse_evidence(new, args.board_log)
    for sealed_pin in seal_new(new, sha, args.tool):
        pins[key_of(sealed_pin)] = sealed_pin
    write_pins(args.pins, pins, order)
    return f"pinned {len(new)} unpinned row(s) at {sha[:12]}; {len(pins) - len(new)} existing pin(s) untouched"


def main():
    ap = argparse.ArgumentParser(description="the intent manifest's evidence pins")
    ap.add_argument("command", choices=("pin", "repin", "unpin", "pin-unpinned"))
    ap.add_argument("key", nargs="?", help="requirement|symbol|artifact (pin, repin, unpin)")
    ap.add_argument("--map", help="the requirement map of this tree (make requirement-map, or CI's code-map artifact)")
    ap.add_argument("--board-log", action="append", default=[], help="a `cargo test` log of this tree's board")
    ap.add_argument("--tested-at", help="the commit the board logs were produced at")
    ap.add_argument("--accept", default="", help="repin: the classes besides code that moved, each checked")
    ap.add_argument("--pins", default=PINS)
    ap.add_argument("--manifest", default="specs/requirements/INTENT_MANIFEST.tsv")
    ap.add_argument("--requirements", help="a TSV of `id status` in place of MASTER and CONFORMANCE §8")
    ap.add_argument("--built", default="", help="artifacts that must have been indexed (android,node)")
    ap.add_argument("--tool", default=TOOL)
    args = ap.parse_args()
    import intent_comparator as ic
    try:
        if args.command in ("pin", "repin", "unpin") and not args.key:
            raise Refused(f"{args.command} names one KEY")
        if args.command == "pin-unpinned" and args.key:
            raise Refused("pin-unpinned takes no KEY")
        if args.command != "unpin" and (not args.map or not args.tested_at):
            raise Refused(f"{args.command} needs --map and --tested-at")
        print({"pin": cmd_pin, "repin": cmd_repin, "unpin": cmd_unpin, "pin-unpinned": cmd_pin_unpinned}
              [args.command](args))
    except (Refused, ic.Refused) as e:
        print(f"intent pins: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
