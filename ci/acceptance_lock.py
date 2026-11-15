#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# ci/acceptance_lock.py: the acceptance lock (owner, 2026-11-04; changed by the
# owner, 2026-11-15). See specs/README.md.
#
# On 2026-11-15 the owner ruled that a receiver keeps each payer's last proven
# state and checks the payer's steps from that state forward ("Yes, lift it"),
# and gave permission to change this file ("Okay, I'm giving you permission to
# change it."). The checks that refused a kept frontier, a loop over a payer's
# positions and a second step beside the one asked for are gone with that
# ruling, as are the one-hop tests whose assertions it reverses.
#
# What stays locked: the amendments the owner never made (A31, S35) and A28's
# first-spend exception stay out of the specifications; the explainer keeps
# Amendment A14, which still defines how each step is validated; and this file
# changes only with the owner's words, so a copy that differs from the
# reference is refused.
#
#   python3 ci/acceptance_lock.py [--root DIR] [--reference REF]
#
# --reference refuses a copy of this file that differs from REF's.

import argparse
import re
import subprocess
import sys
from pathlib import Path

EXPLAINER = "specs/DSM_High_Level_Explainer.md"
SOFI = "specs/SoFi_Settlement_Specification.md"
REQUIREMENTS = "specs/requirements/MASTER_REQUIREMENTS.md"
SELF = "ci/acceptance_lock.py"

FORBIDDEN_AMENDMENTS = re.compile(r"Amendment (A31|S35)\b")

# A28's exception, in the words the explainer held it in.
FORBIDDEN_RULE = "An offered step at position 2 is held to the step before it"


def read(root, path, problems):
    file = root / path
    if not file.is_file():
        problems.append(f"{path}: missing")
        return ""
    return file.read_text(encoding="utf-8", errors="replace")


def check_specifications(root, problems):
    explainer = read(root, EXPLAINER, problems)
    if "Amendment A14" not in explainer:
        problems.append(f"{EXPLAINER}: no longer states 'Amendment A14'")
    if FORBIDDEN_RULE in explainer:
        problems.append(f"{EXPLAINER}: states A28's first-spend exception")
    for path in (EXPLAINER, SOFI, REQUIREMENTS):
        for number, line in enumerate(read(root, path, problems).splitlines(), 1):
            found = FORBIDDEN_AMENDMENTS.search(line)
            if found:
                problems.append(f"{path}:{number}: {found.group(0)}")


def check_self(root, reference, problems):
    shown = subprocess.run(
        ["git", "-C", str(root), "show", f"{reference}:{SELF}"],
        capture_output=True,
    )
    if shown.returncode == 0 and shown.stdout != (root / SELF).read_bytes():
        problems.append(f"{SELF}: differs from {reference}; this lock changes only on the owner's words")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--reference")
    args = parser.parse_args()
    root = Path(args.root).resolve()

    problems = []
    check_specifications(root, problems)
    if args.reference:
        check_self(root, args.reference, problems)

    if problems:
        print("BLOCKED by the acceptance lock (ci/acceptance_lock.py, specs/README.md)\n")
        for problem in problems:
            print(f"  {problem}")
        print(
            f"\n{len(problems)} violation(s). Acceptance changes only on the owner's own words "
            "naming the change."
        )
        sys.exit(1)
    print("acceptance lock: holds as the owner set it on 2026-11-15")


if __name__ == "__main__":
    main()
