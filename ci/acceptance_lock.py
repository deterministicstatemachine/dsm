#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# ci/acceptance_lock.py: one-hop acceptance is locked (owner, 2026-11-04).
#
# DSM Amendment A14 is the authority: a receiver validates a peer's step from
# that step's own parent and reads nothing behind it. No agent changes this
# without the owner's own words naming the change. See specs/README.md.
#
# This refuses what brought a walk back before: the identifiers of the A19
# frontier and the A31 walk, a position loop from the start of a history, the
# amendments themselves, and the loss of the tests that fail when a check reads
# behind the step it was asked about. A31 deleted those tests to pass. The tests
# are the behavioural lock, since a renamed walk still reads what they count.
#
#   python3 ci/acceptance_lock.py [--root DIR] [--reference REF]
#
# --reference refuses a copy of this file that differs from REF's.

import argparse
import re
import subprocess
import sys
from pathlib import Path

CORE = "dsm_client/deterministic_state_machine"
EXPLAINER = "specs/DSM_High_Level_Explainer.md"
SOFI = "specs/SoFi_Settlement_Specification.md"
REQUIREMENTS = "specs/requirements/MASTER_REQUIREMENTS.md"
VERIFIER = f"{CORE}/dsm/src/economic/peer_lineage.rs"
HANDLERS = f"{CORE}/dsm_sdk/src/handlers/mod.rs"
SELF = "ci/acceptance_lock.py"

SOURCE_TREES = (f"{CORE}/dsm/src", f"{CORE}/dsm_sdk/src")

FORBIDDEN_IDENTIFIERS = (
    # The A19 frontier.
    "PeerFrontier",
    "PeerFrontiers",
    "frontier_below",
    "validate_peer_lineage",
    "validate_peer_prefix",
    "ValidatedPrefix",
    "PrefixStop",
    "WALK_STEP_BUDGET",
    # The A31 walk.
    "validated_to",
    "validated_to_inner",
    "validated_position",
    "steps_validated",
    "VALIDATION_STEP_BUDGET",
)

# A verifier loop over positions from the first one is a walk of the history.
WALK_LOOP = re.compile(r"\bfor\s+\w+\s+in\s+\(?\s*1\s*\.\.")

FORBIDDEN_AMENDMENTS = re.compile(r"Amendment (A31|S35)\b")

REQUIRED_TESTS = {
    f"{CORE}/dsm_sdk/src/handlers/one_hop_verification_tests.rs": (
        "every_acceptance_reads_only_the_senders_paying_position",
        "a_credits_source_is_one_step",
        "a_contact_with_a_history_pays_in_one_step_after_the_add",
        "a_read_checks_only_the_step_it_asks_about",
        "the_same_payment_costs_every_receiver_the_same",
        "acceptance_cost_is_one_position_whatever_the_history",
    ),
    f"{CORE}/dsm_sdk/src/handlers/node_e2e_tests.rs": (
        "resolving_another_traders_position_reads_only_that_position",
    ),
}


def read(root, path, problems):
    file = root / path
    if not file.is_file():
        problems.append(f"{path}: missing")
        return ""
    return file.read_text(encoding="utf-8", errors="replace")


def check_identifiers(root, problems):
    pattern = re.compile(r"\b(" + "|".join(FORBIDDEN_IDENTIFIERS) + r")\b")
    for tree in SOURCE_TREES:
        for file in sorted((root / tree).rglob("*.rs")):
            text = file.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                found = pattern.search(line)
                if found:
                    where = file.relative_to(root)
                    problems.append(f"{where}:{number}: {found.group(1)}")


def check_verifier(root, problems):
    text = read(root, VERIFIER, problems)
    for number, line in enumerate(text.splitlines(), 1):
        if WALK_LOOP.search(line):
            problems.append(f"{VERIFIER}:{number}: a loop over positions from the first")


def check_specifications(root, problems):
    explainer = read(root, EXPLAINER, problems)
    for needed in ("Amendment A14", "one-hop acceptance restored"):
        if needed not in explainer:
            problems.append(f"{EXPLAINER}: no longer states {needed!r}")
    for path in (EXPLAINER, SOFI, REQUIREMENTS):
        for number, line in enumerate(read(root, path, problems).splitlines(), 1):
            found = FORBIDDEN_AMENDMENTS.search(line)
            if found:
                problems.append(f"{path}:{number}: {found.group(0)}")


def check_tests(root, problems):
    for path, names in REQUIRED_TESTS.items():
        text = read(root, path, problems)
        for name in names:
            if not re.search(rf"\basync fn {name}\(", text):
                problems.append(f"{path}: the test {name} is gone")
    if "mod one_hop_verification_tests;" not in read(root, HANDLERS, problems):
        problems.append(f"{HANDLERS}: one_hop_verification_tests is not compiled")


def check_self(root, reference, problems):
    shown = subprocess.run(
        ["git", "-C", str(root), "show", f"{reference}:{SELF}"],
        capture_output=True,
    )
    if shown.returncode == 0 and shown.stdout != (root / SELF).read_bytes():
        problems.append(f"{SELF}: differs from {reference}; only the owner changes this lock")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--reference")
    args = parser.parse_args()
    root = Path(args.root).resolve()

    problems = []
    check_identifiers(root, problems)
    check_verifier(root, problems)
    check_specifications(root, problems)
    check_tests(root, problems)
    if args.reference:
        check_self(root, args.reference, problems)

    if problems:
        print("BLOCKED by the acceptance lock (ci/acceptance_lock.py, specs/README.md)\n")
        for problem in problems:
            print(f"  {problem}")
        print(
            f"\n{len(problems)} violation(s). One-hop acceptance (DSM Amendment A14) changes only "
            "on the owner's own words naming the change."
        )
        sys.exit(1)
    print("acceptance lock: one-hop acceptance holds")


if __name__ == "__main__":
    main()
