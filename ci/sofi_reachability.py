#!/usr/bin/env python3
# ci/sofi_reachability.py: every public SoFi function has a production caller
# (Gate G1). Production code is every .rs file under CORE, SDK and NODE,
# excluding tests/ directories, *_tests.rs, every `#[cfg(test)]`-attributed
# item (ci/production_text.py), and every file whose own `mod` declaration is
# cfg(test)-gated — a fixture module is test support wherever it lives.
#
# The baseline: ci/sofi_reachability_baseline.txt lists functions that the
# rebuild (R1..R14) has not wired yet, one per line as `path fn  # R<n>`. A
# function that is unused AND not in the baseline fails. A function that is
# in the baseline AND now has a caller fails too: its line must be deleted in
# the change that wires it, so the baseline only ever shrinks. R14 deletes the
# file; G1 then passes with no exceptions.
#
# A CALLER IS A CALL THE COMPILER WOULD RESOLVE TO THIS FUNCTION, not a file
# that happens to spell its name. Spec §41.3 correction 2 recorded the defect
# this replaces and required the fix before step 5: the old matcher was a bare
# `name(` regex, so `smt/tree.rs::get` was "reachable" through 1,086 calls to
# `sqlite::get`, `::verify` through `sphincs::verify`, `::reachable` through
# `bitcoin_query_routes::reachable` and `::apply` through `recipient_dispatch`.
# Four functions with no caller at all passed a gate that exists to catch
# exactly that. So a call counts only when the name is IN SCOPE at the call:
#
#   1. the defining file itself (minus its own `fn name` definitions);
#   2. a file that imports the item from a sofi path — `use dsm::sofi::x::name`,
#      or `use super::x::{name}` / `use crate::...` from inside CORE/sofi;
#   3. a module-qualified call `m::name(` where `m` was imported from a sofi
#      path (`use dsm::sofi::derive;` then `derive::vault_id(..)`);
#   4. a fully qualified call `..sofi::..::name(`;
#   5. a glob `use <sofi path>::*` brings everything into scope — counted
#      conservatively, so a glob can only ever make the gate more permissive
#      for the file that wrote it.
#
# Comments and `use` statements are stripped before counting calls, so prose
# in a doc comment is not a reference and a re-export is not a use. A function
# passed by value as a whole argument (`, name,` / `(name)`) counts: R8 hands
# recognizers to a locator scan without calling them.
import glob
import importlib.util
import os
import re
import sys

roots = [
    "dsm_client/deterministic_state_machine/dsm/src",
    "dsm_client/deterministic_state_machine/dsm_sdk/src",
    "dsm_storage_node/src",
]
baseline_path = "ci/sofi_reachability_baseline.txt"
CORE_SOFI = "/dsm/src/sofi/"


def cfg_test_module_files():
    """Files declared `#[cfg(test)] mod x;` by their parent: test support."""
    gated = set()
    for decl in [f for r in roots for f in glob.glob(r + "/**/*.rs", recursive=True)]:
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


def production_text(path):
    """The file with every `#[cfg(test)]`-attributed item removed."""
    spec = importlib.util.spec_from_file_location("production_text", "ci/production_text.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.production_text(path)


def without_prose(text):
    text = re.sub(r"//.*", "", text)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


gated = cfg_test_module_files()
files = [
    f
    for r in roots
    for f in glob.glob(r + "/**/*.rs", recursive=True)
    if "/tests/" not in f and not f.endswith("_tests.rs") and f not in gated
]
body = {f: without_prose(production_text(f)) for f in files}


def reaches_sofi(path, inside_sofi):
    """A `use` path that resolves into CORE/sofi."""
    if "sofi::" in path or path.startswith("sofi"):
        return True
    return inside_sofi and re.match(r"(super|self|crate)\b", path) is not None


imported_items, imported_mods, glob_importers = {}, {}, set()
for f, text in body.items():
    inside = CORE_SOFI in f
    items, mods = set(), set()
    for raw in re.findall(r"\buse\s+([^;]*);", text):
        path = " ".join(raw.split())
        if not reaches_sofi(path, inside):
            continue
        if path.rstrip().endswith("*"):
            glob_importers.add(f)
            continue
        if "{" in path:
            names = path[path.index("{") + 1 : path.rindex("}")]
            for item in names.split(","):
                item = item.strip().split(" as ")[0].strip()
                if item and "{" not in item:
                    leaf = item.split("::")[-1]
                    items.add(leaf)
                    mods.add(leaf)
        else:
            leaf = path.split("::")[-1].split(" as ")[0].strip()
            items.add(leaf)
            mods.add(leaf)
    imported_items[f], imported_mods[f] = items, mods


def call_count(caller, name, defining_file):
    """Calls of `name` in `caller` that the compiler would resolve to it."""
    text = body[caller]
    total = 0
    if caller == defining_file or caller in glob_importers or name in imported_items[caller]:
        bare = len(re.findall(r"(?<![\w:])" + name + r"\s*(?:::<[^>]*>)?\(", text))
        bare += len(re.findall(r"[,(]\s*" + name + r"\s*[,)]", text))
        if caller == defining_file:
            bare -= len(re.findall(r"\bfn\s+" + name + r"\s*[(<]", text))
        total += max(bare, 0)
    for module in imported_mods[caller]:
        total += len(
            re.findall(
                r"\b" + re.escape(module) + r"\s*::\s*" + name + r"\s*(?:::<[^>]*>)?\(",
                text,
            )
        )
    total += len(re.findall(r"\bsofi\s*::(?:\w+\s*::)*" + name + r"\s*(?:::<[^>]*>)?\(", text))
    return total


unused, used = [], set()
for f in sorted(g for g in files if CORE_SOFI in g):
    for m in re.finditer(r"^pub fn (\w+)", body[f], re.M):
        name = m.group(1)
        key = f"{f} {name}"
        if sum(call_count(g, name, f) for g in files) == 0:
            unused.append(key)
        else:
            used.add(key)

baseline = {}
if os.path.exists(baseline_path):
    for line in open(baseline_path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            baseline[line] = True

failed = False
for u in unused:
    if u not in baseline:
        print("[FAIL] no production caller:", u)
        failed = True
for b in baseline:
    if b in used:
        print("[FAIL] baseline entry now has a caller; delete its line:", b)
        failed = True
    elif b not in unused:
        print("[FAIL] baseline entry is not a pub fn under CORE/sofi:", b)
        failed = True
still = [u for u in unused if u in baseline]
print(
    f"sofi reachability: {len(used)} pub fn reachable, {len(still)} in the baseline"
    + (" (R14 deletes the baseline)" if still else ""),
)
sys.exit(1 if failed else 0)
