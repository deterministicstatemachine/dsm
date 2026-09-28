#!/usr/bin/env python3
# ci/requirement_map.py: the requirement map over the backend's call graph.
#
# tools/requirement_map reads a rust-analyzer SCIP index of the Android
# build's view of the workspace (`make requirement-map`) and writes the graph:
# defs.tsv (every definition, its BLAKE3 item and closure hashes, whether a
# production entry point reaches it, whether a test reaches it) and edges.tsv.
# This module, used by ci/conformance_evidence.py --map DIR:
#
#   - classifies every definition in the production crates as test code
#     (ci/production_text.py's rule, plus files under tests/ and files their
#     parent declares `#[cfg(test)] mod x;`) or production code, and every
#     production item as live (a production entry point reaches it), test-only
#     (only tests reach it), unlinked (an impl of an outside trait on a type
#     the index cannot see, so the graph cannot decide) or dead (nothing
#     reaches it);
#   - resolves each conformance row's Code and Test cells to definitions;
#   - computes each row's seal with the tool.
#
#   python3 ci/requirement_map.py --map DIR --stats   (resolution and marking counts)
import csv
import glob
import html
import importlib.util
import os
import re
import subprocess
import sys
import tempfile

PRODUCTION = (
    "dsm_client/deterministic_state_machine/dsm/src/",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/",
    "dsm_storage_node/src/",
)
TEST_DIRS = ("/tests/", "/benches/", "/examples/")
DOT = "·"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


production_text = _load_module("production_text", "ci/production_text.py")


def load(map_dir):
    """The graph: definitions (dicts, lines as ints) and the adjacency."""
    with open(os.path.join(map_dir, "defs.tsv"), encoding="utf-8") as fh:
        defs = list(csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE))
    for d in defs:
        d["start_line"] = int(d["start_line"])
        d["end_line"] = int(d["end_line"])
    adjacency = {}
    with open(os.path.join(map_dir, "edges.tsv"), encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE):
            adjacency.setdefault(row["from"], set()).add(row["to"])
    by_file = {}
    for d in defs:
        by_file.setdefault(d["file"], []).append(d)
    classify(defs)
    return {"defs": defs, "by_file": by_file, "adjacency": adjacency}


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


# ---- resolving the conformance tables' cells --------------------------------


def _candidates(the_map, path, names):
    """Definitions in `path` named by `names` (["item"] or ["Type", "item"]).
    A single name prefers an item over a field of the same name, and names an
    inline module (`pub mod class { … }`, which has no definition of its own)
    when nothing else in the file carries it."""
    in_file = the_map["by_file"].get(path, [])
    named = [d for d in in_file if d["name"] == names[-1]]
    if len(names) == 2:
        return [d for d in named if d["container"].split("<")[0] == names[0]]
    items = [d for d in named if not (d["kind"] == "term" and d["container"])]
    if items or named:
        return items or named
    inline = f"/{names[0]}/"
    return [d for d in in_file if inline in d["symbol"].split(" ", 4)[-1] and markable(d)]


def resolve_canonical(the_map, ce, ref):
    """`crate::m::n::Item` or `crate::m::n::Type::method` -> definitions."""
    segs = ref.split("::")
    crate, path = segs[0], segs[1:]
    if crate not in ce.CRATES:
        return []
    for k in range(len(path), -1, -1):
        f = ce.module_file(crate, path[:k])
        if f is None:
            continue
        rest = path[k:]
        if not rest:
            return [d for d in the_map["by_file"].get(f, []) if d["scope"] == "production" and markable(d)]
        if len(rest) > 2:
            return []
        return _candidates(the_map, f, rest)
    return []


def resolve_prose(the_map, ce, cell):
    """A prose cell, `crate · path/file.rs · name` segments separated by `;`
    (the crate carries over from the previous segment) -> [(name, definitions)]."""
    out = []
    crate = None
    for segment in cell.split(";"):
        parts = [p.strip() for p in segment.split(DOT)]
        if len(parts) >= 3 and parts[0] in ce.CRATES:
            crate, file_part, names_part = parts[0], parts[1], DOT.join(parts[2:])
        elif len(parts) == 2 and crate:
            file_part, names_part = parts
        else:
            continue
        path = f"{ce.CRATES[crate]}/src/{file_part.strip('`')}"
        for name in re.findall(r"`([^`]+)`", names_part):
            clean = re.sub(r"(\(| =).*$", "", name).strip()
            names = [n for n in clean.split("::") if n]
            if not names or len(names) > 2:
                out.append((name, []))
                continue
            out.append((name, _candidates(the_map, path, names)))
    return out


def resolve_code_cell(the_map, ce, cell):
    """[(name, definitions)] for every item a Code cell names, in cell order."""
    out = []
    for ref in ce.refs(cell):
        if ce.CANON.match(ref) and ref.split("::")[0] in ce.CRATES:
            out.append((ref, resolve_canonical(the_map, ce, ref)))
    if DOT in cell:
        out.extend(resolve_prose(the_map, ce, cell))
    return out


def resolve_test(the_map, ce, ref, index):
    """A canonical test name -> the test function's definition."""
    entry = index.get(ref)
    if entry is None:
        return []
    loc = entry[2]
    path, line = loc.rsplit(":", 1)
    line = int(line)
    name = ref.split("::")[-1]
    return [
        d
        for d in the_map["by_file"].get(path, [])
        if d["name"] == name and d["kind"] == "callable" and d["start_line"] <= line <= d["end_line"]
    ]


SEAL_HEADER = "Seal"
STORAGE_SPEC = "specs/DSM_Storage_Node_Specification.md"
UNREACHED_HEADING = "## 9 Production code no entry point reaches"
ROW_ID = re.compile(r"^\| (MR-[A-Z]+-\d{4}(?:\s*[\u2013-]\s*(?:MR-[A-Z]+-)?\d{4})?|STOR-014/L\d+) \|")


def _cells(line):
    return [c.strip() for c in line.strip()[1:-1].split("|")]


def requirement_payload(ce, master, storage_lines, row_id):
    """The requirement text a row is about: its MASTER §8 rows, or for a
    STOR-014/L<n> row the storage specification's line n."""
    m = re.fullmatch(r"STOR-014/L(\d+)", row_id)
    if m:
        n = int(m.group(1))
        return f"{STORAGE_SPEC}:{n}\x1f{storage_lines[n - 1]}"
    parts = []
    for i in ce.id_range(row_id):
        cells = master.get(i)
        parts.append(" | ".join(cells) if cells else i)
    return "\x1e".join(parts)


def named_symbols(the_map, ce, row, index):
    """(symbols in cell order, [(name, definitions)] of the Code cell)."""
    code = resolve_code_cell(the_map, ce, row[2] if len(row) > 2 else "")
    symbols = []
    for _, found in code:
        symbols.extend(sorted({d["symbol"] for d in found}))
    for ref in ce.refs(row[3] if len(row) > 3 else ""):
        if ce.is_cargo_test_ref(ref):
            symbols.extend(sorted({d["symbol"] for d in resolve_test(the_map, ce, ref, index)}))
    return symbols, code


def compute_seals(map_dir, payloads):
    """payloads: [(row_id, requirement, row, symbols)] -> {row_id: seal}."""
    with tempfile.TemporaryDirectory() as tmp:
        rows_path, out_path = os.path.join(tmp, "rows.tsv"), os.path.join(tmp, "seals.tsv")
        with open(rows_path, "w", encoding="utf-8") as fh:
            for row_id, requirement, row, symbols in payloads:
                fields = [row_id, requirement, row, *symbols]
                for f in fields:
                    if "\t" in f or "\n" in f:
                        raise ValueError(f"{row_id}: a sealed field holds a tab or a newline")
                fh.write("\t".join(fields) + "\n")
        tool = os.environ.get("REQUIREMENT_MAP_BIN")
        command = [tool] if tool else ["cargo", "run", "--locked", "--quiet", "--release", "-p", "requirement_map", "--"]
        subprocess.run(command + ["seal", "--map", map_dir, "--rows", rows_path, "--out", out_path], check=1)
        with open(out_path, encoding="utf-8") as fh:
            return dict(line.rstrip("\n").split("\t") for line in fh if line.strip())


def unreached_section(the_map, ce):
    marked = [d for d in the_map["defs"] if d["scope"] == "production" and markable(d) and d["status"] != "live"]
    crate_of = {v + "/src/": k for k, v in ce.CRATES.items()}
    rows = set()
    for d in marked:
        root = next(r for r in crate_of if d["file"].startswith(r))
        rows.add((d["status"], crate_of[root], d["file"][len(root):], display(d), d["kind"]))
    order = {"dead": 0, "test-only": 1, "unlinked": 2}
    rows = sorted(rows, key=lambda r: (order[r[0]], r[1], r[2], r[3], r[4]))
    counts = {k: sum(1 for r in rows if r[0] == k) for k in order}
    lines = [
        UNREACHED_HEADING,
        "",
        "Generated by `ci/conformance_evidence.py --map DIR --write` from the call graph `tools/requirement_map` "
        "builds out of a rust-analyzer index of the Android build's view (`dsm_sdk` with `jni,bluetooth`), "
        "`dsm` and `dsm_storage_node`. Entry points: the JNI exports, `JNI_OnLoad`, `dsm_init_runtime` and the "
        "storage node's `main`. **dead**: nothing reaches it, no entry point and no test. **test-only**: shipped "
        "code only tests reach, a test seam in production. **unlinked**: an impl of an outside trait on a type the "
        "index cannot see, which the graph cannot decide. Fields and enum variants are marked through their type. "
        "CI fails when this list and the code disagree.",
        "",
        f"{counts['dead']} dead, {counts['test-only']} test-only, {counts['unlinked']} unlinked.",
        "",
        "| Status | Crate | File | Item | Kind |",
        "|---|---|---|---|---|",
    ]
    lines += [f"| {st} | {cr} | {fi} | `{it}` | {ki} |" for st, cr, fi, it, ki in rows]
    return "\n".join(lines) + "\n"


def check(map_dir, ce, req, gaps, write, report=None):
    """Checks 6 (reachable), 7 (sealed), 8 (marked). Returns (failures, gaps).
    With `report`, also writes the map as one HTML page there."""
    the_map = load(map_dir)
    failures = []
    master = {r[0]: r for r in ce.table_rows(ce.section(req, "## 8 Canonical requirements", "### 8.5")) if re.fullmatch(r"MR-[A-Z]+-\d{4}", r[0])}
    with open(STORAGE_SPEC, encoding="utf-8") as fh:
        storage_lines = fh.read().split("\n")
    index, _ = ce.build_index()
    head, per_req = gaps[: gaps.index("## 8 Per-requirement results")], gaps[gaps.index("## 8 Per-requirement results"):]
    tail = ""
    if UNREACHED_HEADING in per_req:
        per_req, tail = per_req[: per_req.index(UNREACHED_HEADING)], per_req[per_req.index(UNREACHED_HEADING):]
    lines = per_req.split("\n")
    payloads, row_at, resolved = [], {}, {}
    for n, line in enumerate(lines):
        m = ROW_ID.match(line)
        if not m:
            continue
        cells = _cells(line)
        row_id = cells[0]
        symbols, code = named_symbols(the_map, ce, cells, index)
        payloads.append((row_id, requirement_payload(ce, master, storage_lines, row_id), " | ".join(cells[:5]), symbols))
        row_at[row_id] = (n, cells)
        resolved[row_id] = code
        if cells[1] == "Met":
            for name, found in code:
                if not found:
                    failures.append(f"{ce.GAPS} §8 {row_id}: Met names {name}, which the call graph does not contain")
                elif not any(d["reached"] == "1" for d in found):
                    states = sorted({d.get("status") or d["scope"] for d in found})
                    failures.append(f"{ce.GAPS} §8 {row_id}: Met names {name}, which no production entry point reaches ({', '.join(states)})")
    seals = compute_seals(map_dir, payloads)
    header_at = next(n for n, line in enumerate(lines) if line.startswith("| MR-ID | Status |"))
    has_column = _cells(lines[header_at])[-1] == SEAL_HEADER
    for row_id, (n, cells) in row_at.items():
        recorded = cells[5] if has_column and len(cells) > 5 else ""
        if recorded != seals[row_id]:
            if write:
                lines[n] = "| " + " | ".join(cells[:5] + [seals[row_id]]) + " |"
            else:
                failures.append(
                    f"{ce.GAPS} §8 {row_id}: the seal no longer matches: its requirement, its row, or the code or "
                    f"tests it names changed since it was sealed. Re-verify the finding, then reseal with --write"
                )
    if write and not has_column:
        lines[header_at] = lines[header_at].rstrip() + f" {SEAL_HEADER} |"
        lines[header_at + 1] = lines[header_at + 1].rstrip() + "---|"
    per_req = "\n".join(lines)
    section = unreached_section(the_map, ce)
    if tail != section:
        if write:
            tail = section
        else:
            failures.append(f"{ce.GAPS} {UNREACHED_HEADING[3:]}: the list differs from the call graph; run --write")
    if not per_req.endswith("\n\n"):
        per_req = per_req.rstrip("\n") + "\n\n"
    if report:
        rows = [(rid, cells[1], resolved[rid], seals[rid]) for rid, (_, cells) in row_at.items()]
        write_report(the_map, ce, rows, report)
    return failures, head + per_req + tail


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
.b { display:inline-block; padding:0 6px; border-radius:9px; font-size:11px; font-weight:600;
  border:1px solid currentColor; white-space:nowrap; }
.live { color:var(--live); } .test-only { color:var(--test); } .dead { color:var(--dead); }
.unlinked { color:var(--unlinked); } .unresolved, .test, .other { color:var(--none); }
details { background:var(--card); border:1px solid var(--line); border-radius:8px; margin:6px 0; }
summary { cursor:pointer; padding:7px 10px; } details table { border-top:1px solid var(--line); }
input { width:100%; box-sizing:border-box; padding:8px 10px; border:1px solid var(--line);
  border-radius:8px; background:var(--card); color:var(--fg); font:inherit; margin:6px 0 10px; }
.wrap { overflow-x:auto; }
td.seal code { white-space:nowrap; }
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


def _badge(status):
    return f'<span class="b {html.escape(status)}">{html.escape(status)}</span>'


def _coverage(the_map, rows):
    """Row IDs whose named code reaches an item (below it) or is reached
    through it (above it)."""
    forward = the_map["adjacency"]
    backward = {}
    for a, targets in forward.items():
        for b in targets:
            backward.setdefault(b, set()).add(a)
    covered = {}
    for rid, _, code, _ in rows:
        start = {d["symbol"] for _, found in code for d in found}
        for graph in (forward, backward):
            seen, queue = set(start), list(start)
            while queue:
                for nxt in graph.get(queue.pop(), ()):
                    if nxt not in seen:
                        seen.add(nxt)
                        queue.append(nxt)
            for symbol in seen:
                covered.setdefault(symbol, set()).add(rid)
    return covered


def write_report(the_map, ce, rows, path):
    esc = html.escape
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=1, text=1).stdout.strip()
    covered = _coverage(the_map, rows)
    prod = [d for d in the_map["defs"] if d["scope"] == "production" and markable(d)]
    unique = {(d["status"], d["file"], display(d), d["kind"]) for d in prod}
    counts = {k: sum(1 for u in unique if u[0] == k) for k in ("live", "test-only", "dead", "unlinked")}
    unspecified = [d for d in prod if d["status"] == "live" and not covered.get(d["symbol"])]
    statuses = {}
    for _, st, _, _ in rows:
        statuses[st] = statuses.get(st, 0) + 1
    out = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        f"<title>Requirement Map</title><style>{REPORT_CSS}</style></head><body><main>",
        "<h1>Requirement map</h1>",
        f"<p class=sub>Commit <code>{esc(head)}</code>. The call graph of <code>dsm</code>, <code>dsm_sdk</code> "
        "(Android view: <code>jni,bluetooth</code>) and <code>dsm_storage_node</code>, from rust-analyzer; "
        "every finding sealed with BLAKE3 to its requirement and the closure of the code and tests it names.</p>",
        "<div class=cards>",
    ]
    for label, value in (("findings sealed", len(rows)), *((f"findings {k}", v) for k, v in sorted(statuses.items())),
                         ("live items", counts["live"]), ("test-only items", counts["test-only"]),
                         ("dead items", counts["dead"]), ("unlinked items", counts["unlinked"]),
                         ("live items no finding covers", len(unspecified))):
        out.append(f"<div class=card><b>{value}</b><span>{esc(label)}</span></div>")
    out.append("</div>")

    out.append("<h2>Findings</h2><input data-filter='#findings tbody tr' placeholder='Filter findings'>")
    out.append("<div class=wrap><table id=findings><thead><tr><th>Finding</th><th>Status</th><th>Code it names</th><th>Seal</th></tr></thead><tbody>")
    for rid, st, code, seal in rows:
        named = []
        for name, found in code:
            state = sorted({d.get("status") or d["scope"] for d in found}) if found else ["unresolved"]
            named.append(f"<code>{esc(name)}</code> " + " ".join(_badge(x) for x in state))
        out.append(f"<tr><td><code>{esc(rid)}</code></td><td>{esc(st)}</td><td>{'<br>'.join(named) or '—'}</td>"
                   f"<td class=seal><code title='{esc(seal)}'>{esc(seal[:10])}…</code></td></tr>")
    out.append("</tbody></table></div>")

    out.append("<h2>Files</h2><input data-filter='#files details' placeholder='Filter files and items'><div id=files>")
    by_file = {}
    for d in prod:
        by_file.setdefault(d["file"], []).append(d)
    for f in sorted(by_file):
        items = sorted(by_file[f], key=lambda d: d["start_line"])
        tally = {k: sum(1 for d in items if d["status"] == k) for k in ("dead", "test-only")}
        note = ", ".join(f"{v} {k}" for k, v in tally.items() if v)
        out.append(f"<details><summary><code>{esc(f)}</code> — {len(items)} items{(' · ' + esc(note)) if note else ''}</summary>")
        out.append("<div class=wrap><table><thead><tr><th>Item</th><th>Kind</th><th>Lines</th><th>Status</th><th>Findings covering it</th></tr></thead><tbody>")
        for d in items:
            ids = sorted(covered.get(d["symbol"], ()))
            shown = ", ".join(ids[:6]) + (f" and {len(ids) - 6} more" if len(ids) > 6 else "")
            out.append(f"<tr><td><code>{esc(display(d))}</code></td><td>{esc(d['kind'])}</td>"
                       f"<td>{d['start_line']}–{d['end_line']}</td><td>{_badge(d['status'])}</td><td>{esc(shown) or '—'}</td></tr>")
        out.append("</tbody></table></div></details>")
    out.append("</div>")

    out.append(f"<h2>Live code no finding covers ({len(unspecified)})</h2>")
    out.append("<p class=sub>Reached from a production entry point, but neither named by a finding nor above or below "
               "anything a finding names: behaviour the specifications do not account for (CODE → SPEC).</p>")
    out.append("<input data-filter='#unspecified tbody tr' placeholder='Filter'><div class=wrap><table id=unspecified>"
               "<thead><tr><th>File</th><th>Item</th><th>Kind</th></tr></thead><tbody>")
    for d in sorted(unspecified, key=lambda d: (d["file"], d["start_line"])):
        out.append(f"<tr><td><code>{esc(d['file'])}</code></td><td><code>{esc(display(d))}</code></td><td>{esc(d['kind'])}</td></tr>")
    out.append(f"</tbody></table></div><script>{REPORT_JS}</script></main></body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))


def stats(the_map, ce):
    gaps = ce.read(ce.GAPS)
    rows = [r for r in ce.table_rows(ce.section(gaps, "## 8 Per-requirement results")) if re.match(r"(MR-[A-Z]+-\d{4}|STOR-014/L)", r[0])]
    index, _ = ce.build_index()
    named = resolved = met_named = met_unresolved = 0
    unresolved_examples = []
    for r in rows:
        for name, found in resolve_code_cell(the_map, ce, r[2] if len(r) > 2 else ""):
            named += 1
            resolved += bool(found)
            if r[1] == "Met":
                met_named += 1
                met_unresolved += not found
            if not found and len(unresolved_examples) < 12:
                unresolved_examples.append(f"{r[0]} ({r[1]}): {name}")
    tests = [t for r in rows for t in ce.refs(r[3] if len(r) > 3 else "") if ce.is_cargo_test_ref(t)]
    tests_resolved = sum(1 for t in tests if resolve_test(the_map, ce, t, index))
    prod = [d for d in the_map["defs"] if d["scope"] == "production" and markable(d)]
    counts = {}
    for d in prod:
        counts[d["status"]] = counts.get(d["status"], 0) + 1
    print(f"code items named: {named}, resolved {resolved}; on Met rows {met_named}, unresolved {met_unresolved}")
    print(f"test names: {len(tests)}, resolved {tests_resolved}")
    print("production items:", counts)
    for e in unresolved_examples:
        print("  unresolved:", e)


def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=1)
    ap.add_argument("--stats", action="store_const", const=1, default=0)
    args = ap.parse_args()
    ce = _load_module("conformance_evidence", "ci/conformance_evidence.py")
    the_map = load(args.map)
    if args.stats:
        stats(the_map, ce)
    return 0


if __name__ == "__main__":
    sys.exit(main())
