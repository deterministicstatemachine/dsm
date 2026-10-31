#!/usr/bin/env python3
# ci/sofi_reachability.py: every public SoFi function, method and item has a
# production caller or user (Gate G1, SoFi §37, and rule T1, SoFi §35;
# MR-SOFI-0273, MR-SOFI-0268; owner ruling 2026-10-27).
#
# WHAT IS CHECKED. Every `pub fn` under CORE/sofi, free or an inherent
# method, and every `pub` struct, enum, const, static, type alias and trait,
# that is not test code. A trait's methods and a trait impl's are reached
# through the trait and carry no visibility of their own; they are not in the
# set. An item's references inside its own definition, and inside its own
# `impl` blocks, header included, do not count: they name it without using
# it.
#
# A CALLER IS A REFERENCE THE COMPILER'S NAME RESOLUTION RESOLVES TO THE
# FUNCTION, never a file that spells its name. The index is rust-analyzer's
# SCIP index of the workspace, from the pinned toolchain's own rust-analyzer:
# name resolution and type inference resolve `x.method()` to the impl it
# calls, so a method is told apart from every other method of that name. The
# text matcher this replaces counted only free functions, because a
# method's callers cannot be told apart by name; spec §41.3 correction 2
# records the defects the text matcher had before that.
#
# Production code is every reference outside test code: not under a tests/
# directory, not in a *_tests.rs file, not in a file whose own `mod`
# declaration is cfg(test)-gated, and not inside a `#[cfg(test)]`-attributed
# item (ci/production_text.py). A function's references inside its own body
# do not count, and neither does a `use` of it.
#
# The baseline: ci/sofi_reachability_baseline.txt lists functions the
# rebuild has not wired yet, one per line as `path name` (a method as
# `path Type::name`). A function that is unused and not in the baseline
# fails; a baseline entry that now has a caller fails until its line is
# deleted, so the baseline only shrinks.
#
# usage: sofi_reachability.py [INDEX.scip]
#   With no argument the workspace is indexed here (rust-analyzer scip).
import glob
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

WORKSPACE = "dsm_client/deterministic_state_machine"
ROOTS = [
    "dsm_client/deterministic_state_machine/dsm/src",
    "dsm_client/deterministic_state_machine/dsm_sdk/src",
    "dsm_storage_node/src",
]
CORE_SOFI = "dsm_client/deterministic_state_machine/dsm/src/sofi/"
BASELINE = "ci/sofi_reachability_baseline.txt"
# What the shipped builds enable (scripts/verify_16kb_support.sh builds the
# SDK with `--features jni,bluetooth`); code behind them is production code.
FEATURES = ["dsm_sdk/jni", "dsm_sdk/bluetooth"]

DEFINITION, IMPORT = 0x1, 0x2


# ── SCIP, read by hand: the index is protobuf, and only four messages and
# seven fields of it are needed (github.com/sourcegraph/scip, scip.proto). ──
def _varint(buf, i):
    shift, value = 0, 0
    while True:
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, i
        shift += 7


def _fields(buf):
    """(field number, wire type, value) of each field of one message."""
    i, n = 0, len(buf)
    while i < n:
        key, i = _varint(buf, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(buf, i)
        elif wire == 2:
            length, i = _varint(buf, i)
            value = buf[i : i + length]
            i += length
        elif wire == 1:
            value, i = buf[i : i + 8], i + 8
        elif wire == 5:
            value, i = buf[i : i + 4], i + 4
        else:
            raise ValueError(f"SCIP: unsupported wire type {wire}")
        yield number, wire, value


def _packed_int32(value, wire):
    if wire == 0:
        return [value]
    out, i = [], 0
    while i < len(value):
        v, i = _varint(value, i)
        out.append(v)
    return out


def read_index(path):
    """{relative_path: [(start_line, symbol, roles)]} of every document."""
    data = open(path, "rb").read()
    documents = {}
    for number, _wire, value in _fields(data):
        if number != 2:  # Index.documents
            continue
        relative, occurrences = None, []
        for dn, dw, dv in _fields(value):
            if dn == 1:  # Document.relative_path
                relative = dv.decode("utf-8")
            elif dn == 2:  # Document.occurrences
                rng, symbol, roles = [], "", 0
                for on, ow, ov in _fields(dv):
                    if on == 1:  # Occurrence.range
                        rng.extend(_packed_int32(ov, ow))
                    elif on == 2:  # Occurrence.symbol
                        symbol = ov.decode("utf-8")
                    elif on == 3:  # Occurrence.symbol_roles
                        roles = ov
                if rng and symbol:
                    occurrences.append((rng[0], symbol, roles))
        if relative is not None:
            documents[relative] = occurrences
    return documents


def index_workspace(out):
    config = os.path.join(os.path.dirname(out), "rust-analyzer.json")
    with open(config, "w") as f:
        # Its own target subdirectory, so the index never waits on a build.
        json.dump({"cargo": {"features": FEATURES, "targetDir": True}}, f)
    subprocess.run(
        ["rust-analyzer", "scip", WORKSPACE, "--output", out, "--config-path", config],
        check=True,
    )


# ── Production code ─────────────────────────────────────────────────────────
def cfg_test_module_files():
    """Files declared `#[cfg(test)] mod x;` by their parent: test support."""
    gated = set()
    for decl in [f for r in ROOTS for f in glob.glob(r + "/**/*.rs", recursive=True)]:
        text = open(decl, encoding="utf-8").read()
        pattern = (
            r"#\[cfg\((?:any\([^)]*\btest\b[^)]*\)|test)\)\]\s*"
            r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
        )
        for m in re.finditer(pattern, text):
            here = os.path.dirname(decl)
            for candidate in (f"{here}/{m.group(1)}.rs", f"{here}/{m.group(1)}/mod.rs"):
                if os.path.exists(candidate):
                    gated.add(candidate)
    return gated


def load_production_text():
    spec = importlib.util.spec_from_file_location("production_text", "ci/production_text.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PT = load_production_text()
GATED = cfg_test_module_files()


def is_production_file(path):
    return (
        any(path.startswith(r + "/") for r in ROOTS)
        and "/tests/" not in path
        and not path.endswith("_tests.rs")
        and path not in GATED
    )


_lines_cache = {}


def test_lines(path):
    """The 0-based lines inside `#[cfg(test)]`-attributed items of `path`."""
    if path not in _lines_cache:
        text = open(path, encoding="utf-8").read()
        lines = set()
        for start, end in PT.test_item_spans(text):
            first = text.count("\n", 0, start)
            last = text.count("\n", 0, end)
            lines.update(range(first, last + 1))
        _lines_cache[path] = lines
    return _lines_cache[path]


def body_lines(text, line):
    """The 0-based lines of the item whose first token is on `line`."""
    offsets = [0]
    for m in re.finditer("\n", text):
        offsets.append(m.end())
    start = offsets[line]
    end = PT._item_end(text, start)
    return set(range(line, text.count("\n", 0, end) + 1))


PUB_FN = re.compile(r"^\s*pub\s+(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")
PUB_ITEM = re.compile(r"^\s*pub\s+(struct|enum|const|static|type|trait)\s+(\w+)")
IMPL_HEADER = re.compile(r"^\s*(?:unsafe\s+)?impl\b")


def public_sofi_functions(documents):
    """{symbol: (path, display name, definition line, is a fn)} of every pub
    fn and pub item under CORE/sofi that is not test code."""
    found = {}
    for rel, occurrences in documents.items():
        path = os.path.normpath(os.path.join(WORKSPACE, rel))
        if not path.startswith(CORE_SOFI) or not is_production_file(path):
            continue
        lines = open(path, encoding="utf-8").read().split("\n")
        tests = test_lines(path)
        for line, symbol, roles in occurrences:
            if not roles & DEFINITION or line in tests:
                continue
            item = PUB_ITEM.match(lines[line])
            if item and item.group(2) in symbol and not symbol.endswith(")."):
                found[symbol] = (path, f"{item.group(1)} {item.group(2)}", line, False)
                continue
            if not symbol.endswith(")."):
                continue
            m = PUB_FN.match(lines[line])
            if not m:
                continue
            # An inherent method is `…module/impl#[Type]method().`; a free
            # function `…module/function().`.
            descriptor = symbol.rsplit(" ", 1)[-1]
            owner = re.search(r"impl#\[([^\]]+)\]\w+\(\)\.$", descriptor)
            name = f"{owner.group(1)}::{m.group(1)}" if owner else m.group(1)
            found[symbol] = (path, name, line, True)
    return found


def main():
    if len(sys.argv) > 1:
        documents = read_index(sys.argv[1])
    else:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "index.scip")
            index_workspace(out)
            documents = read_index(out)

    targets = public_sofi_functions(documents)
    callers = {symbol: 0 for symbol in targets}
    # Each item's own impl blocks: (path, lines) of every block whose header
    # names it.
    own_impls = {}
    for rel, occurrences in documents.items():
        path = os.path.normpath(os.path.join(WORKSPACE, rel))
        if not is_production_file(path):
            continue
        text = None
        for line, symbol, roles in occurrences:
            if symbol not in targets or targets[symbol][3] or roles & DEFINITION:
                continue
            if text is None:
                text = open(path, encoding="utf-8").read()
                lines = text.split("\n")
            if IMPL_HEADER.match(lines[line]):
                own_impls.setdefault(symbol, []).append((path, body_lines(text, line)))
    for rel, occurrences in documents.items():
        path = os.path.normpath(os.path.join(WORKSPACE, rel))
        if not is_production_file(path):
            continue
        tests = test_lines(path)
        text = open(path, encoding="utf-8").read()
        lines = text.split("\n")
        for line, symbol, roles in occurrences:
            if symbol not in callers or roles & (DEFINITION | IMPORT) or line in tests:
                continue
            defined_in, _name, defined_at, is_fn = targets[symbol]
            if defined_in == path and line in body_lines(text, defined_at):
                continue
            if not is_fn and any(
                path == block_path and line in block
                for block_path, block in own_impls.get(symbol, [])
            ):
                continue
            callers[symbol] += 1

    keys = {symbol: f"{targets[symbol][0]} {targets[symbol][1]}" for symbol in targets}
    unused = sorted(keys[s] for s, n in callers.items() if n == 0)
    used = {keys[s] for s, n in callers.items() if n > 0}

    baseline = set()
    if os.path.exists(BASELINE):
        for line in open(BASELINE, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                baseline.add(line)

    failed = False
    for u in unused:
        if u not in baseline:
            print("[FAIL] no production caller:", u)
            failed = True
    for b in sorted(baseline):
        if b in used:
            print("[FAIL] baseline entry now has a caller; delete its line:", b)
            failed = True
        elif b not in unused:
            print("[FAIL] baseline entry is not a pub fn under CORE/sofi:", b)
            failed = True
    if not targets:
        print("[FAIL] the index named no public SoFi function: it did not index CORE/sofi")
        failed = True
    fns = [s for s in targets if targets[s][3]]
    methods = sum(1 for s in fns if "::" in targets[s][1])
    print(
        f"sofi reachability: {len(used)} of {len(targets)} reachable: {len(fns)} pub fn "
        f"({methods} of them methods) and {len(targets) - len(fns)} pub items; "
        f"{len([u for u in unused if u in baseline])} in the baseline"
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
