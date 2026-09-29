#!/usr/bin/env python3
# ci/requirement_map.py: the code map over each shipped build's call graph.
#
# tools/requirement_map reads rust-analyzer SCIP indexes of each shipped
# build (Android: the real aarch64-linux-android target; the storage node:
# Linux, built on Linux only) and of the host test build (`make
# requirement-map`), and writes:
#
#   defs.tsv      every definition: its Rust path, BLAKE3 item and closure
#                 hashes, its best state over the artifacts with a reason
#                 code, whether a test reaches it, its entry-point kinds
#   reach.tsv     per artifact: reached, indeterminate, dead, not-built or
#                 not-in-artifact, with a stable code, the step it came by
#                 (the witness, one hop), where, and what established it
#   edges.tsv     every profile's edges, proven or uncertain (with a code)
#   files.tsv     every source file's BLAKE3 hash
#   accounting.tsv, health.tsv   every definition occurrence and every
#                 analyzer log line, accounted for
#
# This module classifies definitions as production or test code
# (ci/production_text.py's rule, plus files under tests/ and files their parent
# declares `#[cfg(test)] mod x;`), writes the map as one HTML page, and answers
# two queries an agent can run before editing:
#
#   python3 ci/requirement_map.py --map DIR --report FILE.html
#   python3 ci/requirement_map.py --map DIR explain <symbol | Rust path | file>
#   python3 ci/requirement_map.py --map DIR impact  <symbol | Rust path | file>
#
# explain: each artifact's state and reason code, the witness path from an
# entry point, callers and callees, and whether tests reach it. impact: what
# changing it disturbs: the production items and entry points whose closure
# holds it, per artifact, and the tests that reach it.
import collections
import csv
import glob
import html
import importlib.util
import os
import re
import subprocess
import sys

PRODUCTION = (
    "dsm_client/deterministic_state_machine/dsm/src/",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/",
    "dsm_storage_node/src/",
)
TEST_DIRS = ("/tests/", "/benches/", "/examples/")
ARTIFACTS = ("android", "node")


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


production_text = _load_module("production_text", "ci/production_text.py")


def _tsv(map_dir, name):
    with open(os.path.join(map_dir, name), encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE))


def load(map_dir, with_edges=0):
    """The map: definitions (lines as ints, classified), each artifact's
    reading of them, the hashed files, the accounting, and on request the
    edges."""
    defs = _tsv(map_dir, "defs.tsv")
    for d in defs:
        d["start_line"] = int(d["start_line"])
        d["end_line"] = int(d["end_line"])
        d["reach"] = {}
    by_symbol = {d["symbol"]: d for d in defs}
    for r in _tsv(map_dir, "reach.tsv"):
        target = by_symbol.get(r["symbol"])
        if target is None:
            raise SystemExit(f"reach.tsv names {r['symbol']!r}, which defs.tsv does not hold")
        target["reach"][r["artifact"]] = r
    classify(defs)
    the_map = {
        "defs": defs,
        "by_symbol": by_symbol,
        "files": _tsv(map_dir, "files.tsv"),
        "accounting": _tsv(map_dir, "accounting.tsv"),
        "health": _tsv(map_dir, "health.tsv"),
    }
    if with_edges:
        the_map["edges"] = _tsv(map_dir, "edges.tsv")
    return the_map


def cfg_test_module_files():
    """Files their parent declares `#[cfg(test)] mod x;` (or `any(…test…)`): test support."""
    gated = set()
    pattern = re.compile(
        r"#\[cfg\((?:any\([^)]*\btest\b[^)]*\)|test)\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
    )
    for root in PRODUCTION:
        for decl in glob.glob(root + "**/*.rs", recursive=1):
            with open(decl, encoding="utf-8") as fh:
                text = fh.read()
            here = os.path.dirname(decl)
            for m in pattern.finditer(text):
                for candidate in (f"{here}/{m.group(1)}.rs", f"{here}/{m.group(1)}/mod.rs"):
                    if os.path.exists(candidate):
                        gated.add(candidate)
    # Files declared inside a `#[cfg(test)] mod name { mod child; … }` block.
    inline = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*\{")
    for root in PRODUCTION:
        for decl in glob.glob(root + "**/*.rs", recursive=1):
            with open(decl, encoding="utf-8") as fh:
                text = fh.read()
            here = os.path.dirname(decl)
            stem = os.path.basename(decl)[:-3]
            base = here if stem in ("lib", "main", "mod") else f"{here}/{stem}"
            for start, end in production_text.test_item_spans(text):
                body = text[start:end]
                head = production_text._skip_ws_and_comments(body, production_text.ATTR.match(body).end())
                while body.startswith("#[", head):
                    head = production_text._skip_ws_and_comments(body, production_text._skip_attribute(body, head))
                m = inline.match(body, head)
                if m:
                    gated.update(glob.glob(f"{base}/{m.group(1)}/**/*.rs", recursive=1))
    # A module file's own submodules are test support too.
    for gated_file in list(gated):
        if gated_file.endswith("/mod.rs"):
            gated.update(glob.glob(os.path.dirname(gated_file) + "/**/*.rs", recursive=1))
    return gated


def test_lines(path):
    """Line numbers (1-based) inside `#[cfg(test)]` items of `path`."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    lines = set()
    for start, end in production_text.test_item_spans(text):
        first = text.count("\n", 0, start) + 1
        last = text.count("\n", 0, end) + 1
        lines.update(range(first, last + 1))
    return lines


def markable(d):
    """What a dead-code mark is about: functions, methods, types, macros and
    module-level constants and statics. Not fields or enum variants (their
    type carries the mark), and not a macro's internal items (a `__`-prefixed
    path), which the code never names."""
    path = d["symbol"].split(" ", 4)[-1]
    if re.search(r"(^|[/#])__\w", path):
        return 0
    if d["kind"] in ("callable", "macro"):
        return 1
    return d["kind"] in ("type", "term") and not d["container"]


def classify(defs):
    """Sets d["scope"] to production, test or other, and d["status"] of each
    production definition from the map's best state over the artifacts:
    reached, indeterminate, test-only (no artifact reaches it; a test does),
    dead, not-built (its artifact's index was not built here), or
    not-in-artifact (no shipped build compiles it)."""
    gated = cfg_test_module_files()
    lines_of = {}
    for d in defs:
        f = d["file"]
        if not f.startswith(PRODUCTION):
            d["scope"], d["status"] = "other", ""
            continue
        if any(t in f for t in TEST_DIRS) or f in gated:
            d["scope"], d["status"] = "test", ""
            continue
        if f not in lines_of:
            lines_of[f] = test_lines(f)
        if d["start_line"] in lines_of[f]:
            d["scope"], d["status"] = "test", ""
            continue
        d["scope"] = "production"
        state = d["state"]
        if state == "dead" and d["tested"] == "1":
            d["status"] = "test-only"
        elif state == "not-shipped":
            d["status"] = "not-in-artifact"
        else:
            d["status"] = state


def display(d):
    owner = f"{d['container']}::" if d["container"] else ""
    implemented = f" (impl {d['trait']})" if d["trait"] else ""
    return f"{owner}{d['name']}{implemented}"


# ---- queries ------------------------------------------------------------------

def find(the_map, query):
    """The definitions a query names: an exact symbol, a Rust path (or its
    tail after `::`), or every definition in a file."""
    by_symbol = the_map["by_symbol"]
    if query in by_symbol:
        return [by_symbol[query]]
    in_file = [d for d in the_map["defs"] if d["file"] == query]
    if in_file:
        return sorted(in_file, key=lambda d: d["start_line"])
    exact = [d for d in the_map["defs"] if d["path"] == query]
    if exact:
        return exact
    return [d for d in the_map["defs"] if d["path"].endswith("::" + query) or d["name"] == query]


def witness(the_map, d, artifact):
    """The path an artifact reached `d` by: entry point first, each step with
    its edge kind and where the index shows it."""
    steps = []
    seen = set()
    current = d
    while current is not None and current["symbol"] not in seen:
        seen.add(current["symbol"])
        r = current["reach"].get(artifact)
        if r is None:
            break
        steps.append((current, r))
        if r["via_kind"] in ("root", "seed", ""):
            break
        current = the_map["by_symbol"].get(r["via"])
    return list(reversed(steps))


# The kinds of entry point that start execution; `undeclared-export` is a
# dead-root candidate, not one of them.
ENTRY_KINDS = {"export", "vm", "load", "main", "test"}


def root_kinds(d, profile):
    """The entry-point kinds a definition has in one profile."""
    kinds = []
    for entry in d["root"].split(","):
        artifact, _, kind = entry.partition(":")
        if artifact == profile:
            kinds.append(kind)
    return kinds


def label(d):
    return d["path"] or f"{display(d)} ({d['file']}:{d['start_line']})"


def explain(the_map, query, out):
    found = find(the_map, query)
    if not found:
        out.write(f"nothing in the map is named {query!r}\n")
        return 1
    edges = the_map.get("edges", [])
    callers = collections.defaultdict(list)
    callees = collections.defaultdict(list)
    for e in edges:
        callers[e["to"]].append(e)
        callees[e["from"]].append(e)
    for d in found:
        out.write(f"symbol: {d['symbol']}\n")
        out.write(f"path: {d['path'] or '(an item inside a function: no path names it)'}\n")
        out.write(f"defined: {d['file']}:{d['start_line']}-{d['end_line']}  kind {d['kind']}  scope {d['scope']}  built in: {d['built_in']}\n")
        out.write(f"item: {d['item']}\nclosure: {d['closure']}\n")
        out.write(f"entry point: {d['root'] if d['root'] else 'none'}\n")
        for artifact in ARTIFACTS:
            r = d["reach"].get(artifact)
            if r is None:
                out.write(f"{artifact}: not applicable (its crates do not hold this file)\n")
                continue
            out.write(f"{artifact}: {r['state']}  {r['code']}  (source: {r['source']})\n")
            if r["reason"]:
                out.write(f"  reason: {r['reason']}\n")
            if r["state"] in ("reached", "indeterminate"):
                for node, step in witness(the_map, d, artifact):
                    how = step["via_kind"] if step["via_kind"] != "root" else f"entry point ({step['via']})"
                    out.write(f"  {how:<18} {label(node)}  [{step['at']}]\n")
        out.write(f"tests: {'a test reaches it' if d['tested'] == '1' else 'no test reaches it'}\n")
        if edges:
            for title, rows, other in (("callers", callers[d["symbol"]], "from"), ("callees", callees[d["symbol"]], "to")):
                shown = sorted({(e["profile"], e[other], e["kind"], e["proof"], e["code"], e["at"]) for e in rows})
                out.write(f"{title}: {len(shown)}\n")
                for profile, sym, kind, proof, code, at in shown[:40]:
                    target = the_map["by_symbol"].get(sym)
                    name = label(target) if target else sym
                    doubt = "" if proof == "proven" else f"  UNCERTAIN {code}"
                    out.write(f"  [{profile}] {kind:<15} {name}  ({at}){doubt}\n")
                if len(shown) > 40:
                    out.write(f"  … {len(shown) - 40} more\n")
        out.write("\n")
    return 0


def impact(the_map, query, out):
    """Everything whose closure holds what the query names: per profile, the
    items that can reach it (callers, transitively), the entry points among
    them, and the tests."""
    found = find(the_map, query)
    if not found:
        out.write(f"nothing in the map is named {query!r}\n")
        return 1
    changed = {d["symbol"] for d in found}
    backward = collections.defaultdict(lambda: collections.defaultdict(set))
    for e in the_map["edges"]:
        backward[e["profile"]][e["to"]].add(e["from"])
    out.write(f"changed: {len(changed)} definition(s): {', '.join(sorted(label(d) for d in found)[:10])}\n")
    for profile in list(ARTIFACTS) + ["tests"]:
        graph = backward.get(profile)
        if graph is None:
            out.write(f"{profile}: no index in this map\n")
            continue
        seen = set(changed)
        queue = collections.deque(changed)
        while queue:
            v = queue.popleft()
            for w in graph.get(v, ()):
                if w not in seen:
                    seen.add(w)
                    queue.append(w)
        affected = [the_map["by_symbol"][s] for s in seen - changed if s in the_map["by_symbol"]]
        roots = sorted(label(d) for d in affected if set(root_kinds(d, profile)) & ENTRY_KINDS)
        dead_roots = sorted(label(d) for d in affected if "undeclared-export" in root_kinds(d, profile))
        production = [d for d in affected if d["scope"] == "production"]
        noun = "test functions" if profile == "tests" else "entry points"
        out.write(f"{profile}: {len(affected)} definitions can reach it; {len(production)} production; {len(roots)} {noun}\n")
        for name in roots[:30]:
            out.write(f"  {noun[:-1]}: {name}\n")
        if len(roots) > 30:
            out.write(f"  … {len(roots) - 30} more\n")
        for name in dead_roots:
            out.write(f"  dead-root candidate (an export nothing declares): {name}\n")
    return 0


REPORT_CSS = """
:root { --bg:#fbfbf9; --fg:#1d1d1b; --muted:#6b6b66; --line:#e2e1dc; --card:#ffffff;
  --live:#1f7a4d; --test:#8a5a00; --dead:#b3261e; --unlinked:#5b5bd6; --none:#6b6b66; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg:#161615; --fg:#ecebe6; --muted:#a3a29c; --line:#34332f; --card:#1f1f1d;
  --live:#5fcf97; --test:#e0b04a; --dead:#ff8a80; --unlinked:#a5a5ff; --none:#a3a29c; } }
body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.45 system-ui, sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:17px; margin:32px 0 8px; }
.sub { color:var(--muted); margin:0 0 16px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
.card b { display:block; font-size:20px; } .card span { color:var(--muted); font-size:12px; }
table { width:100%; border-collapse:collapse; background:var(--card); }
th, td { text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { font-size:12px; color:var(--muted); font-weight:600; }
code { font:12px ui-monospace, monospace; overflow-wrap:anywhere; }
td.hash code { white-space:nowrap; }
.b { display:inline-block; padding:0 6px; border-radius:9px; font-size:11px; font-weight:600;
  border:1px solid currentColor; white-space:nowrap; }
.reached { color:var(--live); } .test-only { color:var(--test); } .dead { color:var(--dead); }
.indeterminate { color:var(--unlinked); } .not-built, .not-in-artifact, .test, .other { color:var(--none); }
details { background:var(--card); border:1px solid var(--line); border-radius:8px; margin:6px 0; }
summary { cursor:pointer; padding:7px 10px; } details table { border-top:1px solid var(--line); }
input { width:100%; box-sizing:border-box; padding:8px 10px; border:1px solid var(--line);
  border-radius:8px; background:var(--card); color:var(--fg); font:inherit; margin:6px 0 10px; }
.wrap { overflow-x:auto; }
"""

REPORT_JS = """
document.querySelectorAll('input[data-filter]').forEach(function (box) {
  box.addEventListener('input', function () {
    var q = box.value.toLowerCase();
    document.querySelectorAll(box.dataset.filter).forEach(function (el) {
      el.hidden = q.length > 0 && el.textContent.toLowerCase().indexOf(q) < 0;
    });
  });
});
"""

STATUS_ORDER = ("dead", "test-only", "indeterminate", "not-built", "not-in-artifact", "reached")


def _badge(status):
    return f'<span class="b {html.escape(status)}">{html.escape(status)}</span>'


def _area(path):
    parts = path.split("/")
    if parts[0] == "dsm_client" and len(parts) > 2:
        return "/".join(parts[:3] if parts[1] == "deterministic_state_machine" else parts[:2])
    return "/".join(parts[:2]) if len(parts) > 2 else parts[0]


def write_report(the_map, path):
    esc = html.escape
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=1, text=1, check=1).stdout.strip()
    prod = [d for d in the_map["defs"] if d["scope"] == "production" and markable(d)]
    counts = collections.Counter(d["status"] for d in prod)
    roots = sorted((d for d in the_map["defs"] if d["root"]), key=lambda d: (d["file"], d["start_line"]))
    files = the_map["files"]
    mapped = [f for f in files if f["indexed"] == "1"]
    unmapped = [f for f in files if f["indexed"] != "1"]
    measures = collections.defaultdict(dict)
    for row in the_map["accounting"]:
        measures[row["profile"]][row["measure"]] = row["value"]
    out = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        f"<title>Code Map</title><style>{REPORT_CSS}</style></head><body><main>",
        "<h1>Code map</h1>",
        f"<p class=sub>Commit <code>{esc(head)}</code>. Every source file hashed with BLAKE3. Each shipped build's call "
        "graph from rust-analyzer, computed separately: Android (the real <code>aarch64-linux-android</code> target, "
        "<code>jni,bluetooth</code>) and the storage node (Linux; built on Linux only). Every definition is reached, "
        "dead or indeterminate in each build, with a stable reason code.</p>",
        "<div class=cards>",
    ]
    cards = [("source files hashed", len(files)), ("mapped", len(mapped))]
    for artifact in ARTIFACTS:
        m = measures.get(artifact)
        if m is not None:
            cards.append((f"{artifact}: {m['built']}", m["roots"]))
    cards += [(f"{k} production items", counts.get(k, 0)) for k in STATUS_ORDER]
    for label_, value in cards:
        out.append(f"<div class=card><b>{esc(str(value))}</b><span>{esc(label_)}</span></div>")
    out.append("</div>")

    out.append("<h2>Accounting</h2><p class=sub>Every definition occurrence each index emitted, and every line of the "
               "analyzer's log, accounted for.</p><div class=wrap><table><thead><tr><th>Profile</th><th>Measure</th>"
               "<th>Value</th></tr></thead><tbody>")
    for row in the_map["accounting"]:
        out.append(f"<tr><td>{esc(row['profile'])}</td><td>{esc(row['measure'])}</td><td>{esc(row['value'])}</td></tr>")
    for row in the_map["health"]:
        if row["count"] != "0":
            out.append(f"<tr><td>{esc(row['profile'])}</td><td>log: {esc(row['category'])}</td><td>{esc(row['count'])}</td></tr>")
    out.append("</tbody></table></div>")

    out.append("<h2>Entry points</h2><p class=sub>Where each build's execution starts: <code>Java_*</code> exports a "
               "Kotlin <code>external fun</code> declares, <code>JNI_OnLoad</code>, load-time constructors, a binary's "
               "<code>main</code>. An export nothing declares is a dead-root candidate.</p><div class=wrap><table>"
               "<thead><tr><th>Entry point</th><th>Kind</th><th>File</th></tr></thead><tbody>")
    for d in roots:
        out.append(f"<tr><td><code>{esc(display(d))}</code></td><td>{esc(d['root'])}</td>"
                   f"<td><code>{esc(d['file'])}:{d['start_line']}</code></td></tr>")
    out.append("</tbody></table></div>")

    for status, what in (("dead", "no path of any kind from any build's entry points, and no test reaches it"),
                         ("test-only", "shipped code only tests reach"),
                         ("indeterminate", "the index cannot decide; the code says why"),
                         ("not-built", "its build's index was not made on this host")):
        rows = sorted({(d["file"], display(d), d["kind"], d["start_line"], d["code"]) for d in prod if d["status"] == status})
        out.append(f"<h2>{esc(status.capitalize())} production items ({len(rows)})</h2><p class=sub>{esc(what)}.</p>")
        out.append(f"<input data-filter='#{status} tbody tr' placeholder='Filter'><div class=wrap><table id={status}>"
                   "<thead><tr><th>File</th><th>Item</th><th>Kind</th><th>Code</th></tr></thead><tbody>")
        for f, item, kind, line, code in rows:
            out.append(f"<tr><td><code>{esc(f)}:{line}</code></td><td><code>{esc(item)}</code></td><td>{esc(kind)}</td>"
                       f"<td><code>{esc(code)}</code></td></tr>")
        out.append("</tbody></table></div>")

    out.append("<h2>Production files</h2><input data-filter='#files details' placeholder='Filter files and items'><div id=files>")
    by_file = {}
    for d in prod:
        by_file.setdefault(d["file"], []).append(d)
    for f in sorted(by_file):
        items = sorted(by_file[f], key=lambda d: d["start_line"])
        tally = collections.Counter(d["status"] for d in items if d["status"] != "reached")
        note = ", ".join(f"{v} {k}" for k, v in sorted(tally.items()))
        out.append(f"<details><summary><code>{esc(f)}</code> — {len(items)} items{(' · ' + esc(note)) if note else ''}</summary>")
        out.append("<div class=wrap><table><thead><tr><th>Item</th><th>Kind</th><th>Lines</th>"
                   + "".join(f"<th>{a}</th>" for a in ARTIFACTS) + "<th>Closure</th></tr></thead><tbody>")
        for d in items:
            cells = ""
            for a in ARTIFACTS:
                r = d["reach"].get(a)
                cells += f"<td>{_badge(r['state']) if r else '—'}<br><code>{esc(r['code']) if r else ''}</code></td>"
            out.append(f"<tr><td><code>{esc(display(d))}</code></td><td>{esc(d['kind'])}</td>"
                       f"<td>{d['start_line']}–{d['end_line']}</td>{cells}"
                       f"<td class=hash><code title='{esc(d['closure'])}'>{esc(d['closure'][:10])}…</code></td></tr>")
        out.append("</tbody></table></div></details>")
    out.append("</div>")
    areas = {}
    for f in unmapped:
        areas.setdefault(_area(f["path"]), []).append(f)
    out.append(f"<h2>Not mapped to a call graph ({len(unmapped)} files)</h2><p class=sub>Hashed, but no symbol index "
               "covers them: the frontend, the Android Kotlin layer, and crates the workspace excludes.</p>")
    for area in sorted(areas, key=lambda a: -len(areas[a])):
        listed = sorted(areas[area], key=lambda f: f["path"])
        out.append(f"<details><summary><code>{esc(area)}</code> — {len(listed)} files</summary><div class=wrap><table>"
                   "<thead><tr><th>File</th><th>BLAKE3</th></tr></thead><tbody>")
        for f in listed:
            out.append(f"<tr><td><code>{esc(f['path'])}</code></td><td class=hash><code title='{esc(f['file'])}'>{esc(f['file'][:10])}…</code></td></tr>")
        out.append("</tbody></table></div></details>")
    out.append(f"<script>{REPORT_JS}</script></main></body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=1, help="a requirement_map directory (make requirement-map)")
    ap.add_argument("--report", help="write the map as one HTML page here")
    ap.add_argument("query", nargs="*", help="explain|impact <symbol | Rust path | file>")
    args = ap.parse_args()
    if args.query:
        if len(args.query) != 2 or args.query[0] not in ("explain", "impact"):
            ap.error("a query is: explain <what> | impact <what>")
        command, what = args.query
        the_map = load(args.map, with_edges=1)
        run = explain if command == "explain" else impact
        return run(the_map, what, sys.stdout)
    if not args.report:
        ap.error("give --report FILE.html, or a query")
    the_map = load(args.map)
    write_report(the_map, args.report)
    prod = [d for d in the_map["defs"] if d["scope"] == "production" and markable(d)]
    counts = collections.Counter(d["status"] for d in prod)
    shown = ", ".join(f"{counts.get(k, 0)} {k}" for k in STATUS_ORDER)
    print(f"code map: {len(the_map['files'])} source files, production items: {shown}; {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
