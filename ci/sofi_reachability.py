#!/usr/bin/env python3
# ci/sofi_reachability.py: every public SoFi function has a production caller
# (Gate G1). Production code is every .rs file under CORE, SDK and NODE,
# excluding tests/ directories and everything after the first #[cfg(test)]
# in a file.
#
# The baseline: ci/sofi_reachability_baseline.txt lists functions that the
# rebuild (R1..R14) has not wired yet, one per line as `path fn  # R<n>`. A
# function that is unused AND not in the baseline fails. A function that is
# in the baseline AND now has a caller fails too: its line must be deleted in
# the change that wires it, so the baseline only ever shrinks. R14 deletes the
# file; G1 then passes with no exceptions.
#
# A "caller" is a call `name(` or a function passed by value as a whole
# argument `, name,` / `(name)` (R8 hands recognizers to a locator scan
# without calling them), in production code with comments and `use`
# statements stripped: prose in a comment is not a reference (the gate no
# longer reads `walk (` in a doc comment as a call, R4/R5), and a re-export
# is not a use.
import glob
import os
import re
import sys

roots = [
    "dsm_client/deterministic_state_machine/dsm/src",
    "dsm_client/deterministic_state_machine/dsm_sdk/src",
    "dsm_storage_node/src",
]
baseline_path = "ci/sofi_reachability_baseline.txt"


def prod(path):
    t = open(path, encoding="utf-8").read()
    i = t.find("#[cfg(test)]")
    t = t if i < 0 else t[:i]
    # Comments are prose, not references; a `use` is not a use.
    t = re.sub(r"//.*", "", t)
    return re.sub(r"\buse\s[^;]*;", "", t)


files = [
    f
    for r in roots
    for f in glob.glob(r + "/**/*.rs", recursive=True)
    if "/tests/" not in f and not f.endswith("_tests.rs")
]
text = {f: prod(f) for f in files}

unused = []
used = set()
for f in sorted(g for g in files if "/dsm/src/sofi/" in g):
    for m in re.finditer(r"^pub fn (\w+)", text[f], re.M):
        name = m.group(1)
        call = re.compile(
            r"\b" + name + r"\s*(::<[^>]*>)?\(" + r"|[,(]\s*" + name + r"\s*[,)]"
        )
        # A definition `fn name(` matches the call pattern; a generic one
        # `fn name<T>(` does not. Subtract whatever the definitions matched,
        # never a fixed one.
        defn = re.compile(r"\bfn\s+" + name + r"\s*\(")
        n = sum(len(call.findall(t)) - len(defn.findall(t)) for g, t in text.items())
        key = f"{f} {m.group(1)}"
        if n == 0:
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
