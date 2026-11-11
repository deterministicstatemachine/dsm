#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The walkthrough's terminal steps, checked so they never go stale.

Each step is a tape (tools/walkthrough/tapes/*.tape, in VHS's tape format).
What a tape types is what a developer types, so:

    check_tapes.py          every `make <target>` a tape types is a documented
                            target of the Makefile (`make help` lists it)
    check_tapes.py --run    also runs every command the tapes type, in step
                            order, in one bash session from the repo root,
                            failing on the first command that fails (CI's
                            developer-path job runs this)

A command no CI runner can run is named in NOT_RUN, with why.
"""

import os
import re
import shlex
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TAPES = os.path.join(ROOT, "tools", "walkthrough", "tapes")

# Commands a tape types that CI does not run, and why.
NOT_RUN = {
    "make doctor": "reports every prerequisite of the machine, Android and iOS tooling "
    "included, which a CI runner for this path does not install",
}

TYPE = re.compile(r'^Type\s+(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)\s*$')
MAKE = re.compile(r"\bmake\s+(?:-s\s+)?([a-z][a-z0-9-]*)")


def commands(path):
    """Each command the tape types: the text typed before each Enter."""
    out, typed = [], []
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            line = line.strip()
            m = TYPE.match(line)
            if m:
                text = m.group(1) if m.group(1) is not None else m.group(2)
                typed.append(text.replace('\\"', '"'))
            elif line == "Enter":
                if not typed:
                    raise SystemExit(f"{path}:{number}: Enter with nothing typed")
                out.append((number, "".join(typed)))
                typed = []
    if typed:
        raise SystemExit(f"{path}: typed text never entered: {''.join(typed)!r}")
    return out


def documented_targets():
    targets = set()
    with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^([a-zA-Z0-9_-]+):.*?## ", line)
            if m:
                targets.add(m.group(1))
    return targets


def main(argv):
    run = "--run" in argv
    tapes = sorted(f for f in os.listdir(TAPES) if f.startswith("ep") and f.endswith(".tape"))
    if not tapes:
        raise SystemExit(f"no tapes in {TAPES}")
    targets = documented_targets()
    problems = []
    script = ["set -euo pipefail", "cd " + shlex.quote(ROOT)]
    for tape in tapes:
        path = os.path.join(TAPES, tape)
        script.append("echo " + shlex.quote(f"[tapes] {tape}"))
        for number, command in commands(path):
            for target in MAKE.findall(command):
                if target not in targets:
                    problems.append(f"{tape}:{number}: `make {target}` is not a documented Makefile target")
            if command in NOT_RUN:
                script.append("echo " + shlex.quote(f"[tapes] not run here: {command}"))
                continue
            script.append("echo " + shlex.quote(f"[tapes] $ {command}"))
            script.append(command)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"[tapes] {len(tapes)} tapes; every make target they type is documented")
    if not run:
        return 0
    return subprocess.run(["bash", "-c", "\n".join(script)], check=False).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
