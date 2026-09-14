#!/usr/bin/env python3
"""CI layer selector — decides which validation layers a run executes.

Reads ci/layers.toml (the dependency map) and either a git diff or an
explicit file list, and prints GitHub Actions outputs:

    full=true|false            everything runs
    core|sdk|jni_android|storage|frontend|formal|sdk_node_protocol=true|false
    rust=true|false            any Rust layer selected (gates job)
    rust_matrix=<json>         the include-list for the Rust test matrix
    summary=<text>             one line for the job log

Precedence (ci/layers.toml documents the same order):
  1. FULL: event push/schedule, preset FULL, a [full_triggers] path, or an
     unmapped path (unknown = FULL).
  2. Surface mapping: every surface a file matches (multi-match).
  3. Escalation closure over [escalation].
  A preset other than FULL means "pretend that surface changed": the closure
  of that surface, regardless of the diff.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ALL_LAYERS = ["CORE", "SDK", "JNI_ANDROID", "STORAGE", "FRONTEND", "FORMAL", "SDK_NODE_PROTOCOL"]
RUST_LAYERS = {"CORE", "SDK", "JNI_ANDROID", "STORAGE", "FORMAL", "SDK_NODE_PROTOCOL"}
PRESETS = ["FULL", "CORE", "SDK", "STORAGE", "JNI_ANDROID", "FRONTEND", "FORMAL"]


def load_map(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def glob_to_regex(glob: str) -> re.Pattern:
    """`**` spans directories, `*` and `?` do not. Anchored to the whole path."""
    out = ""
    i = 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif glob.startswith("**", i):
            out += ".*"
            i += 2
        elif c == "*":
            out += "[^/]*"
            i += 1
        elif c == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(c)
            i += 1
    return re.compile("^" + out + "$")


def matches_any(path: str, globs: list[str]) -> bool:
    return any(glob_to_regex(g).match(path) for g in globs)


def closure(seed: set[str], escalation: dict[str, list[str]]) -> set[str]:
    out = set(seed)
    frontier = list(seed)
    while frontier:
        layer = frontier.pop()
        for dep in escalation.get(layer, []):
            if dep not in out:
                out.add(dep)
                frontier.append(dep)
    return out


def select(cfg: dict, files: list[str], event: str, preset: str | None) -> tuple[set[str], bool, str]:
    """Return (layers, full, reason)."""
    if event in ("push", "schedule"):
        return set(ALL_LAYERS), True, f"event={event}: FULL always"
    if preset:
        preset = preset.strip().upper()
        if preset == "FULL":
            return set(ALL_LAYERS), True, "preset=FULL"
        if preset not in PRESETS:
            return set(ALL_LAYERS), True, f"preset={preset!r} unknown: FULL"
        layers = closure({preset}, cfg["escalation"])
        return layers, False, f"preset={preset}: pretend {preset} changed → {sorted(layers)}"

    ignored = cfg.get("ignored", {}).get("paths", [])
    considered = [f for f in files if not matches_any(f, ignored)]
    if not considered:
        # Nothing but ignored files (or an empty diff). Nothing to prove; the
        # cheapest honest answer is still to run FULL rather than nothing.
        return set(ALL_LAYERS), True, "no mapped changes: FULL"

    full_globs = cfg["full_triggers"]["paths"]
    for f in considered:
        if matches_any(f, full_globs):
            return set(ALL_LAYERS), True, f"FULL trigger: {f}"

    seed: set[str] = set()
    for f in considered:
        hit = [name for name, globs in cfg["surfaces"].items() if matches_any(f, globs)]
        if not hit:
            return set(ALL_LAYERS), True, f"unmapped path: {f} → FULL"
        seed.update(hit)

    layers = closure(seed, cfg["escalation"])
    return layers, False, f"changed {sorted(seed)} → {sorted(layers)}"


def rust_matrix(cfg: dict, layers: set[str]) -> list[dict]:
    snp = cfg["sdk_node_protocol"]
    lib_filters = " ".join(snp["lib_filters"])
    integration = " ".join(f"--test {t}" for t in snp["integration_tests"])
    include = []
    for group, spec in cfg["groups"].items():
        if not any(w in layers for w in spec["when"]):
            continue
        if any(u in layers for u in spec.get("unless", [])):
            continue
        run = spec["run"].replace("{lib_filters}", lib_filters).replace("{integration_tests}", integration)
        include.append({"group": group, "run": run})
    return include


def changed_files(base: str, head: str) -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def outputs(cfg: dict, layers: set[str], full: bool, reason: str) -> list[str]:
    lines = [f"full={'true' if full else 'false'}"]
    for layer in ALL_LAYERS:
        lines.append(f"{layer.lower()}={'true' if layer in layers else 'false'}")
    lines.append(f"rust={'true' if layers & RUST_LAYERS else 'false'}")
    lines.append(f"rust_matrix={json.dumps(rust_matrix(cfg, layers))}")
    lines.append(f"summary={reason}")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", default=str(Path(__file__).with_name("layers.toml")))
    ap.add_argument("--event", required=True)
    ap.add_argument("--preset", default="")
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--files", nargs="*", help="explicit changed files (instead of a git diff)")
    args = ap.parse_args()
    cfg = load_map(Path(args.map))
    if args.files is not None:
        files = args.files
    elif args.event in ("push", "schedule") or (args.preset and args.preset.strip()):
        files = []
    else:
        if not args.base:
            print("select_layers: no base for a diff → FULL", file=sys.stderr)
            files, args.event = [], "push"
        else:
            files = changed_files(args.base, args.head)
    layers, full, reason = select(cfg, files, args.event, args.preset or None)
    for line in outputs(cfg, layers, full, reason):
        print(line)
    print(f"select_layers: {reason}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
