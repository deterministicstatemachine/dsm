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

TEST_DIRS = ("/tests/", "/benches/", "/examples/")


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


production_text = _load_module("production_text", "ci/production_text.py")


def _tsv(map_dir, name):
    with open(os.path.join(map_dir, name), encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE))


def _tsv_if_written(map_dir, name):
    """A table only a full index writes (a fixture's map has none): None
    when absent."""
    if not os.path.exists(os.path.join(map_dir, name)):
        return None
    return _tsv(map_dir, name)


def load(map_dir, with_edges=0):
    """The map: definitions (lines as ints, classified), each artifact's
    reading of them, the hashed files and the accounting when the index wrote
    them, and on request the edges."""
    defs = _tsv(map_dir, "defs.tsv")
    for d in defs:
        d["start_line"] = int(d["start_line"])
        d["end_line"] = int(d["end_line"])
        d["reach"] = {}
    by_symbol = {d["symbol"]: d for d in defs}
    artifacts = []
    for r in _tsv(map_dir, "reach.tsv"):
        if r["artifact"] not in artifacts:
            artifacts.append(r["artifact"])
        target = by_symbol.get(r["symbol"])
        if target is None:
            raise SystemExit(f"reach.tsv names {r['symbol']!r}, which defs.tsv does not hold")
        target["reach"][r["artifact"]] = r
    # The shipped builds' crates, as each build's `cargo tree` gave them; a
    # fixture's map ships nothing.
    crates = _tsv_if_written(map_dir, "artifacts.tsv")
    production = tuple(sorted({c["source"] for c in crates})) if crates else ()
    classify(defs, production)
    the_map = {
        "defs": defs,
        "by_symbol": by_symbol,
        # The artifacts the map read, as it wrote them: the shipped builds for
        # a full index, the one fixture build for a fixture's map.
        "artifacts": artifacts,
        "files": _tsv_if_written(map_dir, "files.tsv"),
        "accounting": _tsv_if_written(map_dir, "accounting.tsv"),
        "health": _tsv_if_written(map_dir, "health.tsv"),
    }
    if with_edges:
        the_map["edges"] = _tsv(map_dir, "edges.tsv")
    return the_map


def cfg_test_module_files(production):
    """Files their parent declares `#[cfg(test)] mod x;` (or `any(…test…)`): test support."""
    gated = set()
    pattern = re.compile(
        r"#\[cfg\((?:any\([^)]*\btest\b[^)]*\)|test)\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
    )
    for root in production:
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
    for root in production:
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


def classify(defs, production):
    """Sets d["scope"] to production, test or other, and d["status"] of each
    production definition from the map's best state over the artifacts:
    reached, indeterminate, test-only (no artifact reaches it; a test does),
    dead, not-built (its artifact's index was not built here), or
    not-in-artifact (no shipped build compiles it)."""
    gated = cfg_test_module_files(production)
    lines_of = {}
    for d in defs:
        f = d["file"]
        if not f.startswith(production):
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
        for artifact in the_map["artifacts"]:
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
    for profile in list(the_map["artifacts"]) + ["tests"]:
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
    missing = [n for n in ("files", "accounting", "health") if the_map[n] is None]
    if missing:
        raise SystemExit(f"the report needs a full index's {', '.join(missing)} tables")
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
    for artifact in the_map["artifacts"]:
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
                   + "".join(f"<th>{a}</th>" for a in the_map["artifacts"]) + "<th>Closure</th></tr></thead><tbody>")
        for d in items:
            cells = ""
            for a in the_map["artifacts"]:
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



# ---- the adversarial checks -----------------------------------------------------
#
# An independent reading of what the map wrote: every statement no correct map
# can make, and the committed facts it must keep. It shares no code with the
# Rust producer; each rule is read from the tables alone, and a failure names
# the rule, the definition and the artifact.

DISPATCH_KINDS = ("trait-dispatch", "self-type")
VALUE_KINDS = ("construct", "member-of")
TYPE_DISPATCH_KINDS = ("type-argument", "associated-of")
STATE_CODES = {
    "reached": ("REACHED", "REACHED_VIA_DISPATCH"),
    "dead": ("DEAD_NO_ROOT_PATH",),
    "not-in-artifact": ("NOT_IN_ARTIFACT",),
    "not-built": ("IND_PROFILE_NOT_BUILT",),
}
NOT_ROOTS = ("undeclared-export", "unread-declaration", "undecided-gate")
# Every rule a check can name. A fault under any other name is the checker's
# own error, and tools/requirement_map/rules.tsv records each one's cases.
CHECK_RULES = (
    "state-code",
    "reached-outside-its-build",
    "dead-with-a-witness",
    "root-not-recorded",
    "root-not-reached",
    "unreached-after-a-proven-edge",
    "witness-through-unreached",
    "witness-cycle",
    "witness-names-nothing",
    "witness-step-not-a-proven-edge",
    "dispatch-without-evidence",
    "direct-reach-through-a-dispatch",
    "dispatch-reach-without-a-dispatch",
    "sentinel-lost",
    "entry-point-new",
    "entry-point-lost",
    "indeterminate-jump",
)


def contradictions(the_map):
    """Every contradiction in the map, as (rule, definition, artifact, detail)."""
    proven = collections.defaultdict(set)
    out_of = collections.defaultdict(lambda: collections.defaultdict(set))
    into = collections.defaultdict(lambda: collections.defaultdict(set))
    for e in the_map["edges"]:
        if e["proof"] == "proven":
            proven[(e["profile"], e["from"], e["to"])].add(e["kind"])
            out_of[e["profile"]][e["from"]].add((e["to"], e["kind"]))
            into[e["profile"]][e["to"]].add((e["from"], e["kind"]))
    faults = []
    for d in the_map["defs"]:
        who = d["path"] or d["symbol"]
        built = set(filter(None, d["built_in"].split(",")))
        roots = {}
        for pair in filter(None, d["root"].split(",")):
            artifact, _, kind = pair.partition(":")
            roots[artifact] = kind
        for artifact, r in d["reach"].items():
            state, code = r["state"], r["code"]
            here = []
            if state == "indeterminate":
                if not code.startswith("IND_") or code == "IND_PROFILE_NOT_BUILT":
                    here.append(("state-code", f"indeterminate with {code}"))
            elif code not in STATE_CODES.get(state, ()):
                here.append(("state-code", f"{state} with {code}"))
            if state == "reached" and artifact not in built:
                here.append(("reached-outside-its-build", f"built in {sorted(built)}"))
            if state == "dead" and r["via"]:
                here.append(("dead-with-a-witness", r["via"]))
            if r["via_kind"] == "root" and roots.get(artifact) != r["via"]:
                here.append(("root-not-recorded", f"{r['via']} vs {roots.get(artifact)}"))
            if artifact in roots and roots[artifact] not in NOT_ROOTS and state not in ("reached", "not-built"):
                here.append(("root-not-reached", f"a {roots[artifact]} root that is {state}"))
            if state == "reached":
                here.extend(witness_faults(the_map, d, artifact, proven, out_of, into))
            faults.extend((rule, who, artifact, detail) for rule, detail in here)
    faults.extend(closure_faults(the_map, proven))
    unknown = sorted({rule for rule, _, _, _ in faults} - set(CHECK_RULES))
    if unknown:
        raise SystemExit(f"the check named rules it does not declare: {unknown}")
    return faults


def closure_faults(the_map, proven):
    """Reached is closed under every proven step that is not a dispatch: a
    reached definition's proven reference (or value, member, impl or type
    step) leads to a reached definition. One that does not is a false Dead or
    a false Indeterminate."""
    by_symbol = the_map["by_symbol"]
    faults = []
    for (artifact, frm, to), kinds in proven.items():
        steps = kinds - set(DISPATCH_KINDS)
        if not steps:
            continue
        a, b = by_symbol.get(frm), by_symbol.get(to)
        # An endpoint with no definition has no reading to check; the counts
        # (`no-definition`, undefined_endpoints) account for every one.
        if a is None or b is None:
            continue
        ra, rb = a["reach"].get(artifact), b["reach"].get(artifact)
        if ra is None or rb is None or ra["state"] != "reached" or rb["state"] == "reached":
            continue
        faults.append(("unreached-after-a-proven-edge", b["path"] or to, artifact,
                       f"{rb['state']} {rb['code']}, after a proven {'/'.join(sorted(steps))} from reached {a['path'] or frm}"))
    return faults


def witness_faults(the_map, d, artifact, proven, out_of, into):
    """What is wrong with a reached definition's witness: every step a proven
    edge of this artifact from a reached node; the chain ending at an entry
    point of this artifact; each dispatch step with its evidence reached; a
    `REACHED` chain holding no dispatch step and a `REACHED_VIA_DISPATCH`
    chain holding one."""
    by_symbol = the_map["by_symbol"]
    faults = []
    direct = d["reach"][artifact]["code"] == "REACHED"
    dispatched = 0
    seen = set()
    node = d
    while 1:
        r = node["reach"].get(artifact)
        if r is None or r["state"] != "reached":
            faults.append(("witness-through-unreached", node["symbol"]))
            return faults
        if r["via_kind"] == "root":
            break
        if node["symbol"] in seen:
            faults.append(("witness-cycle", node["symbol"]))
            return faults
        seen.add(node["symbol"])
        pred = by_symbol.get(r["via"])
        if pred is None:
            faults.append(("witness-names-nothing", r["via"]))
            return faults
        if r["via_kind"] not in proven.get((artifact, r["via"], node["symbol"]), set()):
            faults.append(("witness-step-not-a-proven-edge", f"{r['via_kind']} {r['via']} -> {node['symbol']}"))
            return faults
        if r["via_kind"] in DISPATCH_KINDS:
            dispatched += 1
            missing = dispatch_evidence_missing(the_map, node, artifact, out_of, into)
            if missing:
                faults.append(("dispatch-without-evidence", f"{node['symbol']}: {missing}"))
        node = pred
    if direct and dispatched:
        faults.append(("direct-reach-through-a-dispatch", f"{dispatched} dispatch step(s) in its witness"))
    if not direct and not dispatched:
        faults.append(("dispatch-reach-without-a-dispatch", "no dispatch step in its witness"))
    return faults


def dispatch_evidence_missing(the_map, impl, artifact, out_of, into):
    """For an impl reached by dispatch, its Self type (where its `member-of`
    or `associated-of` edge leads) must have evidence from another reached
    definition: a value (`construct`, `member-of`) for a method taking `self`,
    a dispatch by type (`type-argument`, `associated-of`) for an associated
    function. The reason it is missing, or an empty string."""
    by_symbol = the_map["by_symbol"]
    owners = [(to, k) for (to, k) in out_of[artifact].get(impl["symbol"], ()) if k in ("member-of", "associated-of")]
    if not owners:
        return "no Self type recorded"
    for to, kind in owners:
        needed = VALUE_KINDS if kind == "member-of" else TYPE_DISPATCH_KINDS
        members = {frm for frm, k in into[artifact].get(to, ()) if k in ("member-of", "associated-of")}
        for frm, k in into[artifact].get(to, ()):
            # Evidence must be a reached definition: an endpoint with no
            # definition (counted by undefined_endpoints) has no reading and
            # so is never evidence.
            witness = by_symbol.get(frm)
            if (k in needed and frm != impl["symbol"] and witness is not None
                    and witness["reach"].get(artifact, {}).get("state") == "reached"
                    and not reached_through_dispatch_into(the_map, witness, artifact, members)):
                return ""
    kind = owners[0][1]
    return "no reached " + ("value" if kind == "member-of" else "dispatch by type") + " of its Self type"


def reached_through_dispatch_into(the_map, d, artifact, members):
    """Whether `d`'s witness passes through a dispatch into one of `members`
    (the Self type's own methods): evidence that rests on the dispatch it
    would establish proves nothing."""
    by_symbol = the_map["by_symbol"]
    seen = set()
    node = d
    while node is not None and node["symbol"] not in seen:
        seen.add(node["symbol"])
        r = node["reach"].get(artifact, {})
        if r.get("via_kind") in DISPATCH_KINDS and node["symbol"] in members:
            return 1
        if r.get("via_kind") in (None, "", "root", "seed"):
            return 0
        node = by_symbol.get(r.get("via"))
    return 0


def _committed(path):
    with open(path, encoding="utf-8") as fh:
        return [r for r in csv.DictReader((l for l in fh if not l.startswith("#")), delimiter="\t", quoting=csv.QUOTE_NONE)]


def built_artifacts(the_map):
    """The artifacts this map read with an index (not `not-built`)."""
    states = collections.defaultdict(set)
    for d in the_map["defs"]:
        for artifact, r in d["reach"].items():
            states[artifact].add(r["state"])
    return [a for a in the_map["artifacts"] if states[a] - {"not-built"}]


def root_set(the_map, artifact):
    out = set()
    for d in the_map["defs"]:
        for pair in filter(None, d["root"].split(",")):
            a, _, kind = pair.partition(":")
            if a == artifact:
                out.add((kind, d["path"] or d["symbol"]))
    return out


def undefined_endpoints(the_map, artifact):
    """The symbols an artifact's edges name that defs.tsv holds no definition
    of, as (workspace, outside). Outside ones are other crates' (`Vec`,
    std): outside the map by design. Workspace ones are the map's blind spot:
    code a build script generates (prost types) or a macro's own tokens write.
    No reading exists to check at either, so the checks skip them, and these
    counts say how much they skip."""
    by_symbol = the_map["by_symbol"]
    ours = {" ".join(d["symbol"].split(" ", 4)[:4]) for d in the_map["defs"]}
    workspace, outside = set(), set()
    for e in the_map["edges"]:
        if e["profile"] != artifact:
            continue
        for s in (e["from"], e["to"]):
            if s in by_symbol:
                continue
            (workspace if " ".join(s.split(" ", 4)[:4]) in ours else outside).add(s)
    return workspace, outside


def reading_counts(the_map, artifact):
    """Each state and code's readings, and the undefined edge endpoints (state
    `no-definition`, code WORKSPACE_SYMBOL or OUTSIDE_SYMBOL)."""
    counts = collections.Counter()
    for d in the_map["defs"]:
        r = d["reach"].get(artifact)
        if r is not None:
            counts[(r["state"], r["code"])] += 1
    workspace, outside = undefined_endpoints(the_map, artifact)
    counts[("no-definition", "WORKSPACE_SYMBOL")] = len(workspace)
    counts[("no-definition", "OUTSIDE_SYMBOL")] = len(outside)
    return counts


def check(the_map, sentinels, roots, counts, out):
    """The contradictions, the sentinels, the entry points and the counts.
    The number of failures."""
    failures = 0
    faults = contradictions(the_map)
    out.write(f"contradictions: {len(faults)}\n")
    for rule, who, artifact, detail in faults[:200]:
        out.write(f"  [{rule}] {artifact} {who}: {detail}\n")
    failures += len(faults)
    built = built_artifacts(the_map)
    by_path = collections.defaultdict(list)
    for d in the_map["defs"]:
        if d["path"]:
            by_path[d["path"]].append(d)
    if sentinels:
        rows = _committed(sentinels)
        lost = []
        for s in rows:
            if s["artifact"] not in built:
                continue
            # Only definitions the artifact reads: one outside its crates (a
            # build script's `main`) may share the path.
            found = [d["reach"][s["artifact"]] for d in by_path.get(s["path"], []) if s["artifact"] in d["reach"]]
            got = [f"{r.get('state')} {r.get('code')}" for r in found]
            if got != [f"{s['state']} {s['code']}"]:
                lost.append(f"  [sentinel-lost] {s['artifact']} {s['path']}: expected {s['state']} {s['code']}, read {got or 'nothing'} ({s['why']})")
        checked = sum(1 for s in rows if s["artifact"] in built)
        out.write(f"sentinels: {checked} checked, {len(lost)} lost\n" + "".join(l + "\n" for l in lost))
        failures += len(lost)
    if roots:
        committed = collections.defaultdict(set)
        for r in _committed(roots):
            committed[r["artifact"]].add((r["kind"], r["path"]))
        for artifact in built:
            now = root_set(the_map, artifact)
            added = sorted(now - committed[artifact])
            gone = sorted(committed[artifact] - now)
            out.write(f"entry points ({artifact}): {len(now)}, {len(added)} unexplained new, {len(gone)} lost\n")
            for kind, path in added:
                out.write(f"  [entry-point-new] {kind}: {path}\n")
            for kind, path in gone:
                out.write(f"  [entry-point-lost] {kind}: {path}\n")
            failures += len(added) + len(gone)
    if counts:
        committed = collections.defaultdict(dict)
        for r in _committed(counts):
            committed[r["artifact"]][(r["state"], r["code"])] = int(r["count"])
        for artifact in built:
            now = reading_counts(the_map, artifact)
            before = committed[artifact]
            out.write(f"readings ({artifact}): before -> now\n")
            for key in sorted(set(now) | set(before)):
                b, n = before.get(key, 0), now.get(key, 0)
                allowed = max(3, b // 10)
                # What the map cannot decide, or cannot see, may not grow unexplained.
                jump = abs(n - b) > allowed and key[0] in ("indeterminate", "no-definition")
                mark = "  [indeterminate-jump]" if jump else ""
                out.write(f"  {key[0]:<16} {key[1]:<24} {b:>6} -> {n:>6}{mark}\n")
                failures += int(jump)
    out.write(f"{failures} failure(s)\n")
    return failures


def print_committed(the_map, out):
    """The entry points and counts this map reads, in the committed files'
    form, for a person to review and commit: never written by the check."""
    built = built_artifacts(the_map)
    out.write("# ci/requirement_map.roots.tsv\nartifact\tkind\tpath\n")
    for artifact in built:
        for kind, path in sorted(root_set(the_map, artifact)):
            out.write(f"{artifact}\t{kind}\t{path}\n")
    out.write("\n# ci/requirement_map.counts.tsv\nartifact\tstate\tcode\tcount\n")
    for artifact in built:
        for (state, code), n in sorted(reading_counts(the_map, artifact).items()):
            out.write(f"{artifact}\t{state}\t{code}\t{n}\n")

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=1, help="a requirement_map directory (make requirement-map)")
    ap.add_argument("--report", help="write the map as one HTML page here")
    ap.add_argument("--sentinels", help="check: the committed known-good readings")
    ap.add_argument("--roots", help="check: the committed entry points")
    ap.add_argument("--counts", help="check: the committed readings per state and code")
    ap.add_argument("query", nargs="*", help="explain|impact <symbol | Rust path | file>, check, or print-committed")
    args = ap.parse_args()
    if args.query == ["check"]:
        the_map = load(args.map, with_edges=1)
        return 1 if check(the_map, args.sentinels, args.roots, args.counts, sys.stdout) else 0
    if args.query == ["print-committed"]:
        print_committed(load(args.map, with_edges=1), sys.stdout)
        return 0
    if args.query:
        if len(args.query) != 2 or args.query[0] not in ("explain", "impact"):
            ap.error("a query is: explain <what> | impact <what> | check | print-committed")
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
