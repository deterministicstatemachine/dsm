#!/usr/bin/env python3
# ci/requirement_map.py: the code map over the backend's call graph.
#
# tools/requirement_map reads a rust-analyzer SCIP index of the Android
# build's view of the workspace (`make requirement-map`) and writes the graph:
# files.tsv (every source file in the repository, its BLAKE3 hash, whether the
# index maps its symbols), defs.tsv (every definition, its BLAKE3 item and
# closure hashes, whether a production entry point reaches it, whether a test
# reaches it) and edges.tsv. This module:
#
#   - classifies every definition in the production crates as test code
#     (ci/production_text.py's rule, plus files under tests/ and files their
#     parent declares `#[cfg(test)] mod x;`) or production code, and every
#     production item as live (a production entry point reaches it), test-only
#     (only tests reach it), unlinked (an impl of an outside trait on a type
#     the index cannot see, so the graph cannot decide) or dead (nothing
#     reaches it);
#   - writes the map as one HTML page.
#
#   python3 ci/requirement_map.py --map DIR --report FILE.html
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


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


production_text = _load_module("production_text", "ci/production_text.py")


def load(map_dir):
    """The map the report reads: every definition (dicts, lines as ints,
    classified) and every hashed source file."""
    with open(os.path.join(map_dir, "defs.tsv"), encoding="utf-8") as fh:
        defs = list(csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE))
    for d in defs:
        d["start_line"] = int(d["start_line"])
        d["end_line"] = int(d["end_line"])
    with open(os.path.join(map_dir, "files.tsv"), encoding="utf-8") as fh:
        files = list(csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE))
    classify(defs)
    return {"defs": defs, "files": files}


def cfg_test_module_files():
    """Files their parent declares `#[cfg(test)] mod x;` (or `any(…test…)`): test support."""
    gated = set()
    pattern = re.compile(
        r"#\[cfg\((?:any\([^)]*\btest\b[^)]*\)|test)\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
    )
    for root in PRODUCTION:
        for decl in glob.glob(root + "**/*.rs", recursive=True):
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
        for decl in glob.glob(root + "**/*.rs", recursive=True):
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
                    gated.update(glob.glob(f"{base}/{m.group(1)}/**/*.rs", recursive=True))
    # A module file's own submodules are test support too.
    for gated_file in list(gated):
        if gated_file.endswith("/mod.rs"):
            gated.update(glob.glob(os.path.dirname(gated_file) + "/**/*.rs", recursive=True))
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
    production definition to live, test-only or dead."""
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
        if d["reached"] == "1":
            d["status"] = "live"
        elif d["tested"] == "1":
            d["status"] = "test-only"
        elif d["unlinked"] == "1":
            d["status"] = "unlinked"
        else:
            d["status"] = "dead"


def display(d):
    owner = f"{d['container']}::" if d["container"] else ""
    implemented = f" (impl {d['trait']})" if d["trait"] else ""
    return f"{owner}{d['name']}{implemented}"


# ---- the report ---------------------------------------------------------------

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
.live { color:var(--live); } .test-only { color:var(--test); } .dead { color:var(--dead); }
.unlinked { color:var(--unlinked); } .test, .other { color:var(--none); }
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

STATUS_ORDER = ("dead", "test-only", "unlinked", "live")


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
    unique = {(d["status"], d["file"], display(d), d["kind"]) for d in prod}
    counts = {k: sum(1 for u in unique if u[0] == k) for k in STATUS_ORDER}
    roots = sorted((d for d in the_map["defs"] if d["root"] != "-"), key=lambda d: (d["file"], d["start_line"]))
    files = the_map["files"]
    mapped = [f for f in files if f["indexed"] == "1"]
    unmapped = [f for f in files if f["indexed"] != "1"]
    out = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        f"<title>Code Map</title><style>{REPORT_CSS}</style></head><body><main>",
        "<h1>Code map</h1>",
        f"<p class=sub>Commit <code>{esc(head)}</code>. Every source file in the repository hashed with BLAKE3; "
        "the Rust backend (<code>dsm</code>, <code>dsm_sdk</code> in the Android build's view with "
        "<code>jni,bluetooth</code>, <code>dsm_storage_node</code>, and the workspace's other crates) mapped to "
        "its call graph from rust-analyzer, every definition hashed with the closure of everything it reaches.</p>",
        "<div class=cards>",
    ]
    cards = [
        ("source files hashed", len(files)),
        ("mapped to the call graph", len(mapped)),
        ("not yet mapped", len(unmapped)),
        ("production entry points", len(roots)),
    ] + [(f"{k} production items", counts[k]) for k in STATUS_ORDER]
    for label, value in cards:
        out.append(f"<div class=card><b>{value}</b><span>{esc(label)}</span></div>")
    out.append("</div>")

    out.append("<h2>Entry points</h2><p class=sub>Where production execution starts: exported symbols "
               "(<code>#[no_mangle]</code>, read from each item's parsed attributes) and the <code>main</code> "
               "of production binaries.</p><div class=wrap><table><thead><tr><th>Entry point</th><th>Kind</th>"
               "<th>File</th></tr></thead><tbody>")
    for d in roots:
        out.append(f"<tr><td><code>{esc(display(d))}</code></td><td>{esc(d['root'])}</td>"
                   f"<td><code>{esc(d['file'])}:{d['start_line']}</code></td></tr>")
    out.append("</tbody></table></div>")

    for status, what in (("dead", "nothing reaches it: no entry point and no test"),
                         ("test-only", "shipped code that only tests reach"),
                         ("unlinked", "an impl of an outside trait on a type the index cannot see; the graph cannot decide")):
        rows = sorted({(d["file"], display(d), d["kind"], d["start_line"]) for d in prod if d["status"] == status})
        out.append(f"<h2>{esc(status.capitalize())} production items ({counts[status]})</h2><p class=sub>{esc(what)}.</p>")
        out.append(f"<input data-filter='#{status} tbody tr' placeholder='Filter'><div class=wrap><table id={status}>"
                   "<thead><tr><th>File</th><th>Item</th><th>Kind</th></tr></thead><tbody>")
        for f, item, kind, line in rows:
            out.append(f"<tr><td><code>{esc(f)}:{line}</code></td><td><code>{esc(item)}</code></td><td>{esc(kind)}</td></tr>")
        out.append("</tbody></table></div>")

    out.append("<h2>Production files</h2><input data-filter='#files details' placeholder='Filter files and items'><div id=files>")
    by_file = {}
    for d in prod:
        by_file.setdefault(d["file"], []).append(d)
    for f in sorted(by_file):
        items = sorted(by_file[f], key=lambda d: d["start_line"])
        tally = {k: sum(1 for d in items if d["status"] == k) for k in ("dead", "test-only", "unlinked")}
        note = ", ".join(f"{v} {k}" for k, v in tally.items() if v)
        out.append(f"<details><summary><code>{esc(f)}</code> — {len(items)} items{(' · ' + esc(note)) if note else ''}</summary>")
        out.append("<div class=wrap><table><thead><tr><th>Item</th><th>Kind</th><th>Lines</th><th>Status</th>"
                   "<th>Closure</th></tr></thead><tbody>")
        for d in items:
            out.append(f"<tr><td><code>{esc(display(d))}</code></td><td>{esc(d['kind'])}</td>"
                       f"<td>{d['start_line']}–{d['end_line']}</td><td>{_badge(d['status'])}</td>"
                       f"<td class=hash><code title='{esc(d['closure'])}'>{esc(d['closure'][:10])}…</code></td></tr>")
        out.append("</tbody></table></div></details>")
    out.append("</div>")

    areas = {}
    for f in unmapped:
        areas.setdefault(_area(f["path"]), []).append(f)
    out.append(f"<h2>Not yet mapped to the call graph ({len(unmapped)} files)</h2><p class=sub>Hashed, but no "
               "symbol index covers them yet: the frontend (stage 1b), the Android Kotlin layer and the "
               "cross-layer links (stage 1c), and crates the workspace excludes.</p>")
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
    ap.add_argument("--report", required=1, help="write the map as one HTML page here")
    args = ap.parse_args()
    the_map = load(args.map)
    write_report(the_map, args.report)
    prod = [d for d in the_map["defs"] if d["scope"] == "production" and markable(d)]
    unique = {(d["status"], d["file"], display(d), d["kind"]) for d in prod}
    counts = ", ".join(f"{sum(1 for u in unique if u[0] == k)} {k}" for k in STATUS_ORDER)
    print(f"code map: {len(the_map['files'])} source files, {counts}; {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
