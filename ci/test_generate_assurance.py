#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# ci/test_generate_assurance.py: the security-assurance record states only what
# was executed for the commit it names, and says so of everything else.

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "generate-assurance.py"
MATRIX = ROOT / "specs" / "requirements" / "VERIFICATION_MATRIX.md"


def head():
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], stdout=subprocess.PIPE, encoding="utf-8").stdout.strip()


def first_named_test():
    for line in MATRIX.read_text().splitlines():
        if line.startswith("| MR-"):
            names = re.findall(r"`([A-Za-z_][\w:]*::[\w:]+)`", line.split("|")[3])
            if names:
                return names[0]
    raise AssertionError("the matrix names no test")


def generate(run_dir, *extra):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--run-dir", str(run_dir), "--generated-at", "2026-10-31T00:00:00Z", "--skip-execution", *extra],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
    )


def evidence(run_dir):
    doc = json.loads((run_dir / "assurance.cdx.json").read_text())
    out = {}
    for e in doc["declarations"]["evidence"]:
        out[e["bom-ref"]] = {d["name"]: d["contents"]["attachment"]["content"] for d in e["data"]}
    return doc, out


class AssuranceRecord(unittest.TestCase):
    def test_a_board_log_that_does_not_name_the_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            log = run / "board.log"
            log.write_text(f"Checking out 0000000000000000000000000000000000000000\ntest {first_named_test().split('::', 1)[1]} ... ok\n")
            out = generate(run, "--board-log", str(log))
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("does not name commit", out.stderr)
            self.assertFalse((run / "assurance.cdx.json").exists())

    def test_a_board_log_of_this_commit_decides_its_named_tests(self):
        name = first_named_test()
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            log = run / "board.log"
            log.write_text(f"git checkout --progress --force {head()}\ntest {name.split('::', 1)[1]} ... ok\n")
            out = generate(run, "--board-log", str(log))
            self.assertEqual(out.returncode, 0, out.stderr)
            _, ev = evidence(run)
            decided = [e for e in ev.values() if e.get("tests", "").startswith(f"{name}=")]
            self.assertTrue(decided, "the named test is in the record")
            self.assertIn(f"{name}=pass", decided[0]["tests"])
            self.assertEqual(ev["ev-board"]["status"], "pass")

    def test_without_a_board_log_no_named_test_is_reported_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            out = generate(run)
            self.assertEqual(out.returncode, 0, out.stderr)
            _, ev = evidence(run)
            tests = [e for ref, e in ev.items() if ref.startswith("ev-tests-")]
            self.assertTrue(tests)
            self.assertFalse([e for e in tests if e["status"] == "pass"])
            self.assertEqual(ev["ev-board"]["status"], "incomplete")

    def test_skipped_checks_say_skipped_and_hardware_says_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            self.assertEqual(generate(run).returncode, 0)
            doc, ev = evidence(run)
            for check in ("lean", "conformance-evidence", "real-code-guard", "sphincs-map", "tla"):
                self.assertEqual(ev[f"ev-check-{check}"]["status"], "skipped", check)
            hardware = [e for ref, e in ev.items() if ref.startswith("ev-hw-")]
            self.assertEqual(len(hardware), 6)
            self.assertEqual({e["status"] for e in hardware}, {"not-run"})
            self.assertEqual(doc["specVersion"], "1.7")
            self.assertEqual({c["type"] for c in doc["components"]}, {"application", "device", "firmware"})
            for e in ev.values():
                self.assertEqual(e["commit"], head())


if __name__ == "__main__":
    unittest.main()
