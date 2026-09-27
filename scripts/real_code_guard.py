#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No-fakes guard: the build refuses placeholders, fabricated results and boolean literals.

Every Rust crate's build script, the Android `preBuild` and the frontend's `build`,
`type-check` and `start` scripts run this over their own sources. A source line that holds a
forbidden token and is not already recorded in the baseline fails the build.

The baseline (`scripts/real_code_baseline.txt`) records the occurrences that existed when the
guard was introduced, one line each: rule, path, and a hash of the line's text. It only
shrinks. An occurrence is allowed while its exact line text is recorded for that file; editing
the line, or adding a new one, makes it a violation. `--write-baseline` rewrites the file from
the tree and can only remove entries: a baseline holding an entry that the reference baseline
(the one on `origin/main`) does not hold is itself a violation, and so is a guard that differs
from the reference guard.

Usage:
  real_code_guard.py [--root DIR] [--scope DIR ...]   check (default: every scope)
  real_code_guard.py --write-baseline                 shrink the baseline to what the tree holds
  real_code_guard.py --self-test                      every rule against its samples
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections import Counter

GUARD_PATH = "scripts/real_code_guard.py"
BUILD_SNIPPET = "scripts/real_code_guard_build.rs"
BASELINE_PATH = "scripts/real_code_baseline.txt"

# The code this repository ships and tests. Configuration formats (JSON, TOML, YAML) and
# tooling scripts are outside it.
SCOPES = [
    "dsm_client/deterministic_state_machine/dsm",
    "dsm_client/deterministic_state_machine/dsm_sdk",
    "dsm_storage_node",
    "tools",
    "crates",
    "dsm_client/frontend",
    "dsm_client/android",
]

EXTENSIONS = {
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".java": "kotlin",
    ".ts": "web",
    ".tsx": "web",
    ".js": "web",
    ".jsx": "web",
    ".mjs": "web",
    ".cjs": "web",
}

# Build output, dependencies and generated code: nothing in them is written by hand.
SKIP_DIRS = {"target", "build", "node_modules", ".git", ".gradle", "dist", "coverage", "generated", ".cxx"}
SKIP_PATHS = {
    "dsm_client/frontend/src/proto/dsm_app_pb.ts",
}
SKIP_PREFIXES = (
    "dsm_client/android/app/src/main/assets/",
)

LANGS_ALL = ("rust", "kotlin", "web")

# (id, languages, regex, what it stands for)
RULES = [
    ("bool-literal", LANGS_ALL, r"\b(true|false)\b",
     "a boolean literal: compute the value from the thing it is about"),
    ("tautology", LANGS_ALL, r"\b(0\s*==\s*0|1\s*==\s*1|0\s*!=\s*0|1\s*!=\s*1|0\s*==\s*1|1\s*==\s*0)\b",
     "a constant condition standing in for a boolean literal"),
    ("stand-in-word", LANGS_ALL,
     r"(?<![A-Za-z])([Pp]laceholders?|PLACEHOLDER|[Dd]ummy|DUMMY|[Ss]tub(bed|s)?|STUB|[Ff]ake[ds]?|FAKE|[Mm]ock(ed|s|k)?|MOCK)(?![a-z])",
     "a placeholder, stub, fake, dummy or mock"),
    ("stand-in-phrase", LANGS_ALL,
     r"(?i)\b(for now|in a real implementation|in production this would|not implemented yet|stand-in|stand in for|simulated?)\b",
     "a note that the code does the lesser thing"),
    ("marker", LANGS_ALL, r"\b(TODO|FIXME|HACK|XXX)\b",
     "a TODO / FIXME / HACK marker: fix it or file an issue"),
    ("rust-bool-default", ("rust",), r"\bbool\s*::\s*default\b",
     "a boolean literal spelled as a default"),
    ("rust-zero-id", ("rust",), r"\[\s*0(u8)?\s*;\s*32\s*\]",
     "a zero 32-byte value: a fabricated hash or id"),
    ("rust-empty-ok", ("rust",), r"Ok\(\s*(vec!\[\s*\]|Vec::new\(\))\s*\)",
     "an empty result returned as an answer"),
    ("rust-unfinished", ("rust",), r"\b(todo|unimplemented)!\s*\(",
     "an unfinished body"),
    ("rust-default-on-error", ("rust",), r"\.unwrap_or(_else|_default)?\s*\(",
     "a fabricated default in place of an error or a missing value"),
    ("rust-error-discarded", ("rust",),
     r"\.ok\(\)|\bResult::ok\b|\.map_err\(\s*\|_\||\bErr\(\s*_\s*\)|\bErr\(\s*\(\)\s*\)|\.is_(err|ok)\(\)|\bcatch_unwind\b",
     "an error discarded, reduced to a yes/no, or caught and dropped"),
    ("rust-error-to-log", ("rust",),
     r"Err\([^)]*\)\s*=>\s*\{?\s*(log::|tracing::)?(warn|info|debug|trace)!",
     "an error downgraded to a log line"),
    ("rust-lint-allow", ("rust",), r"#!?\[\s*allow\s*\(",
     "a suppressed lint"),
    ("rust-ignored-test", ("rust",), r"#\[\s*ignore\b",
     "a test that does not run"),
    ("rust-discarded-result", ("rust",), r"\blet\s+_\s*(=|:)",
     "a result thrown away unread"),
    ("rust-test-feature", ("rust",), r"feature\s*=\s*\"(testing|test-utils)\"",
     "a test seam compiled into shipped code"),
    ("kotlin-suppress", ("kotlin",), r"@Suppress(Warnings)?\s*\(",
     "a suppressed warning"),
    ("kotlin-ignored-test", ("kotlin",), r"@Ignore\b",
     "a test that does not run"),
    ("kotlin-error-discarded", ("kotlin",),
     r"\brunCatching\b|\.getOrNull\(|\.getOrDefault\(|\.getOrElse\(|catch\s*\(\s*_\s*:",
     "an error discarded or turned into a default"),
    ("empty-catch", ("kotlin", "web"), r"catch\s*(\([^)]*\))?\s*\{\s*\}",
     "an error swallowed"),
    ("web-bool-number", ("web",), r"(^|[^\w)\]=!<>])!!?\s*[01]\b|\bBoolean\(\s*[01]?\s*\)",
     "a boolean literal spelled as a number"),
    ("web-type-escape", ("web",), r"@ts-(ignore|expect-error|nocheck)|eslint-disable|\bas\s+any\b",
     "a type or lint check switched off"),
    ("web-skipped-test", ("web",), r"\b(it|test|describe)\.(skip|only)\b|\bx(it|describe)\s*\(",
     "a test that does not run, or runs alone"),
    ("web-test-double", ("web",), r"\bjest\.(fn|mock|spyOn|doMock)\b",
     "a test double in place of the real code"),
    ("web-error-discarded", ("web",),
     r"catch\s*\{|catch\s*\(\s*_|\.catch\(\s*\(\s*\)\s*=>|\bvoid\s+[\w.]+\s*\(",
     "an error discarded, or a promise's failure left unread"),
    ("web-fabricated-default", ("web",), r"(\?\?|\|\|)\s*(''|\"\"|0\b|\[\]|\{\})",
     "a fabricated default in place of a missing value"),
    ("error-hiding-note", LANGS_ALL,
     r"(?i)\bnon-fatal\b|\bbest[- ]effort\b|\bignor(e|es|ed|ing) (the |this |any )?errors?\b|\bswallow",
     "a note that an error is being hidden"),
]

COMPILED = [(rid, langs, re.compile(rx), why) for rid, langs, rx, why in RULES]

# In web code an input's `placeholder` attribute and the DOM `.placeholder` property are the
# HTML feature of that name, not a stand-in; only those two spellings are exempt, and only there.
WEB_PLACEHOLDER_ATTR = re.compile(r"\bplaceholder\s*=|\.placeholder\b")

FINES = (
    "Every violation is recorded and penalized: the owner issues fines to any agent that\n"
    "introduces a placeholder, a fabricated result or a boolean literal, and to any agent that\n"
    "edits, weakens or works around this guard. Only the owner changes the guard.\n"
    "Rewrite the line so it computes the real value, or leave the hole visible."
)


def line_hash(text):
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:16]


def rel(root, path):
    return os.path.relpath(path, root).replace(os.sep, "/")


def skipped(relpath):
    if relpath in SKIP_PATHS or relpath.startswith(SKIP_PREFIXES):
        return 1
    return 0


def code_files(root, scopes):
    for scope in scopes:
        base = os.path.join(root, scope)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                lang = EXTENSIONS.get(os.path.splitext(name)[1])
                if lang is None:
                    continue
                path = os.path.join(dirpath, name)
                relpath = rel(root, path)
                if skipped(relpath):
                    continue
                yield relpath, path, lang


def scan(root, scopes):
    """Every hit in scope: (rule, path, line hash) -> [(line number, text)]."""
    hits = {}
    files = list(code_files(root, scopes))
    # The snippet every crate's build script compiles in is Rust code in every scope.
    files.append((BUILD_SNIPPET, os.path.join(root, BUILD_SNIPPET), "rust"))
    for relpath, path, lang in files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for number, text in enumerate(fh, 1):
                for rid, langs, rx, _why in COMPILED:
                    probe = text
                    if lang == "web" and rid == "stand-in-word":
                        probe = WEB_PLACEHOLDER_ATTR.sub(" ", text)
                    if lang in langs and rx.search(probe):
                        hits.setdefault((rid, relpath, line_hash(text)), []).append((number, text.rstrip("\n")))
    return hits


def parse_baseline(text):
    counts = Counter()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        rid, relpath, digest = line.split("\t")
        counts[(rid, relpath, digest)] += 1
    return counts


def read_baseline(root):
    path = os.path.join(root, BASELINE_PATH)
    if not os.path.exists(path):
        return Counter()
    with open(path, encoding="utf-8") as fh:
        return parse_baseline(fh.read())


def git_show(root, ref, path):
    """The bytes of `path` at `ref`, or None when git, the ref or the path is not there."""
    try:
        out = subprocess.run(
            ["git", "-C", root, "show", "%s:%s" % (ref, path)],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def in_scope(relpath, scopes):
    for scope in scopes:
        if relpath == scope or relpath.startswith(scope.rstrip("/") + "/"):
            return 1
    return 0


def wiring_problems(root):
    """The guard is wired into every build that compiles guarded code. Removing a call is
    itself a violation, reported by whichever build still runs the guard."""
    problems = []

    def text(relpath):
        path = os.path.join(root, relpath)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()

    snippet = text(BUILD_SNIPPET)
    if snippet is None or 'Command::new("python3")' not in snippet or GUARD_PATH not in snippet:
        problems.append("%s no longer runs %s" % (BUILD_SNIPPET, GUARD_PATH))
    for scope in SCOPES:
        base = os.path.join(root, scope)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            if "Cargo.toml" not in filenames:
                continue
            crate = rel(root, dirpath)
            manifest = text(crate + "/Cargo.toml") or ""
            if not re.search(r"^\[package\]", manifest, re.M):
                continue
            if re.search(r"^\s*build\s*=", manifest, re.M):
                problems.append("%s/Cargo.toml overrides its build script" % crate)
            build = text(crate + "/build.rs")
            if build is None or "real_code_guard_build.rs" not in build or "real_code_guard()" not in build:
                problems.append("%s/build.rs does not run the real-code guard" % crate)
    gradle = text("dsm_client/android/app/build.gradle.kts") or ""
    for needle in ('tasks.register<Exec>("realCodeGuard")', "dependsOn(realCodeGuard)", GUARD_PATH):
        if needle not in gradle:
            problems.append("dsm_client/android/app/build.gradle.kts lost %s" % needle)
    package = text("dsm_client/frontend/package.json") or ""
    for script in ("prestart", "prebuild", "pretype-check", "pretest"):
        m = re.search(r'"%s"\s*:\s*"([^"]*)"' % re.escape(script), package)
        if not m or "real_code_guard.py" not in m.group(1):
            problems.append("dsm_client/frontend/package.json: %s does not run the real-code guard" % script)
    ci = text(".github/workflows/ci.yml") or ""
    if "python3 scripts/real_code_guard.py --reference origin/main" not in ci:
        problems.append(".github/workflows/ci.yml no longer runs the guard against main")
    hook = text(".githooks/pre-commit") or ""
    if "real_code_guard.py" not in hook:
        problems.append(".githooks/pre-commit no longer runs the guard")
    return problems


def check(root, scopes, reference):
    problems = wiring_problems(root)
    baseline = read_baseline(root)

    ref_guard = git_show(root, reference, GUARD_PATH)
    if ref_guard is not None:
        with open(os.path.join(root, GUARD_PATH), "rb") as fh:
            if fh.read() != ref_guard:
                problems.append("%s differs from %s's guard: only the owner changes the guard" % (GUARD_PATH, reference))
    ref_baseline_bytes = git_show(root, reference, BASELINE_PATH)
    if ref_baseline_bytes is not None:
        ref_baseline = parse_baseline(ref_baseline_bytes.decode("utf-8"))
        grown = baseline - ref_baseline
        for (rid, relpath, digest), n in sorted(grown.items()):
            problems.append("%s: the baseline gained %d entr%s for rule %s that %s's baseline does not hold"
                            % (relpath, n, "y" if n == 1 else "ies", rid, reference))

    hits = scan(root, scopes)
    for key, occurrences in sorted(hits.items()):
        allowed = baseline.get(key, 0)
        if len(occurrences) > allowed:
            rid = key[0]
            why = next(w for r, _l, _x, w in COMPILED if r == rid)
            for number, text in occurrences[allowed:]:
                problems.append("%s:%d: [%s] %s\n    %s" % (key[1], number, rid, why, text.strip()))
    return problems


def write_baseline(root, reference):
    """Rewrite the baseline from the tree. Once the reference (main) holds a baseline, the result
    never holds more of an entry than it does: the baseline only loses entries. Before main
    holds one, this records the tree as it stands (the guard's introduction)."""
    hits = scan(root, SCOPES)
    tree = Counter({key: len(v) for key, v in hits.items()})
    ref_bytes = git_show(root, reference, BASELINE_PATH)
    if ref_bytes is not None:
        tree = tree & parse_baseline(ref_bytes.decode("utf-8"))
    lines = [
        "# real-code baseline: occurrences that predate the guard. It only shrinks.",
        "# rule<TAB>path<TAB>sha256(line)[:16], one line per occurrence.",
    ]
    for (rid, relpath, digest), n in sorted(tree.items()):
        lines.extend(["%s\t%s\t%s" % (rid, relpath, digest)] * n)
    with open(os.path.join(root, BASELINE_PATH), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return sum(tree.values())


# Each rule, a line it must refuse, and a line it must pass. The samples are built from pieces
# so this file never holds a forbidden token on a line of its own that another tool could copy.
SAMPLES = {
    "bool-literal": ("rust", "    Ok(" + "tr" + "ue)", "    Ok(verified)"),
    "tautology": ("rust", "    if 1 " + "== 1 {", "    if n == 1 {"),
    "stand-in-word": ("web", "  const " + "dum" + "my = 3;", "  const summary = 3;"),
    "stand-in-phrase": ("rust", "    // " + "for " + "now return the head", "    // return the head"),
    "marker": ("kotlin", "    // " + "TO" + "DO wire it", "    // wire it"),
    "rust-bool-default": ("rust", "    let ok = " + "bool::" + "default();", "    let ok = verify(x);"),
    "rust-zero-id": ("rust", "    let id = [" + "0u8; " + "32];", "    let id = [7u8; 32];"),
    "rust-empty-ok": ("rust", "    return " + "Ok(vec!" + "[]);", "    return Ok(rows);"),
    "rust-unfinished": ("rust", "    " + "to" + "do!()", "    compute()"),
    "rust-default-on-error": ("rust", "    x." + "unwrap_" + "or(0)", "    x?"),
    "rust-error-discarded": ("rust", "    if x." + "is_" + "err() {", "    x?;"),
    "rust-error-to-log": ("rust", "        Err(e) => " + "log::" + "warn!(\"{e}\"),", "        Err(e) => return Err(e),"),
    "rust-lint-allow": ("rust", "#[" + "allow(dead_code)]", "#[derive(Debug)]"),
    "rust-ignored-test": ("rust", "#[" + "ignore]", "#[test]"),
    "rust-discarded-result": ("rust", "    " + "let _" + " = send();", "    send()?;"),
    "rust-test-feature": ("rust", '#[cfg(feature = "' + "test" + 'ing")]', '#[cfg(feature = "jni")]'),
    "kotlin-suppress": ("kotlin", "@" + "Suppress(\"UNUSED\")", "@Keep"),
    "kotlin-ignored-test": ("kotlin", "@" + "Ignore", "@Test"),
    "kotlin-error-discarded": ("kotlin", "    val v = x." + "getOr" + "Null()", "    val v = x.getOrThrow()"),
    "empty-catch": ("kotlin", "} catch (e: Exception) " + "{}", "} catch (e: Exception) { throw e }"),
    "web-bool-number": ("web", "  const open = " + "!" + "0;", "  const open = count > 0;"),
    "web-type-escape": ("web", "  const x = y " + "as " + "any;", "  const x = y as Row;"),
    "web-skipped-test": ("web", "it." + "skip('x', () => {});", "it('x', () => {});"),
    "web-test-double": ("web", "jest." + "fn()", "run()"),
    "web-error-discarded": ("web", "  } " + "catch {", "  } catch (e) { throw e; }"),
    "web-fabricated-default": ("web", "  const n = v " + "?? " + "'';", "  const n = v;"),
    "error-hiding-note": ("rust", "    // " + "non-" + "fatal: keep going", "    // the caller retries"),
}


def self_test():
    failures = []
    for rid, langs, rx, _why in COMPILED:
        if rid not in SAMPLES:
            failures.append("rule %s has no samples" % rid)
            continue
        lang, bad, good = SAMPLES[rid]
        if lang not in langs:
            failures.append("rule %s: sample language %s is not one it covers" % (rid, lang))
        if not rx.search(bad):
            failures.append("rule %s does not refuse %r" % (rid, bad))
        if rx.search(good):
            failures.append("rule %s refuses the clean line %r" % (rid, good))
    for rid in SAMPLES:
        if rid not in [r for r, _l, _x, _w in COMPILED]:
            failures.append("samples for a rule that does not exist: %s" % rid)
    return failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    ap.add_argument("--scope", action="append")
    ap.add_argument("--reference", default="origin/main")
    ap.add_argument("--write-baseline", action="store_const", const=1, default=0)
    ap.add_argument("--self-test", action="store_const", const=1, default=0)
    args = ap.parse_args()
    root = os.path.abspath(args.root)

    if args.self_test:
        failures = self_test()
        for f in failures:
            print("[real-code self-test] " + f)
        print("[real-code self-test] %d rules, %d failures" % (len(COMPILED), len(failures)))
        return 1 if failures else 0

    if args.write_baseline:
        n = write_baseline(root, args.reference)
        print("[real-code] baseline written: %d occurrences" % n)
        return 0

    scopes = args.scope or SCOPES
    for scope in scopes:
        if not in_scope(scope, SCOPES):
            print("[real-code] %s is not a guarded scope" % scope)
            return 1
    problems = check(root, scopes, args.reference)
    if problems:
        print("\nBLOCKED by the real-code guard (%s)\n" % GUARD_PATH)
        for p in problems:
            print("  " + p)
        print("\n%d violation%s.\n%s\n" % (len(problems), "" if len(problems) == 1 else "s", FINES))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
