#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# ci/test_generate_assurance.py: the security-assurance record states only what
# was executed for the commit it names, and says so of everything else.

import importlib.util
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
GAPS = ROOT / "specs" / "requirements" / "CONFORMANCE_GAPS.md"


def generator():
    spec = importlib.util.spec_from_file_location("generate_assurance", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def board(text):
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "board.log"
        log.write_text(text)
        return generator().board_results(str(log))


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
            crate, path = name.split("::", 1)
            log.write_text(
                f"git checkout --progress --force {head()}\n"
                f"     Running unittests src/lib.rs (target/release/deps/{crate}-0f1e2d3c)\n"
                f"test {path} ... ok\n"
            )
            out = generate(run, "--board-log", str(log))
            self.assertEqual(out.returncode, 0, out.stderr)
            _, ev = evidence(run)
            decided = [e for e in ev.values() if e.get("tests", "").startswith(f"{name}=")]
            self.assertTrue(decided, "the named test is in the record")
            self.assertIn(f"{name}=pass", decided[0]["tests"])
            self.assertEqual(ev["ev-board"]["status"], "pass")

    def test_each_result_is_named_by_the_crate_and_binary_cargo_ran_it_in(self):
        results = board(
            "     Running unittests src/lib.rs (target/release/deps/dsm_storage_node-0a1b2c)\n"
            "test api::tests::serves ... ok\n"
            "     Running unittests src/main.rs (target/release/deps/storage_node-0a1b2d)\n"
            "test config::tests::loads ... ok\n"
            "     Running tests/no_clock_reads.rs (target/release/deps/no_clock_reads-0a1b2e)\n"
            "test no_node_source_reads_a_clock ... ok\n"
            "     Running unittests src/lib.rs (target/release/deps/dsm-0a1b2f)\n"
            "test no_node_source_reads_a_clock ... FAILED\n"
        )
        self.assertEqual(results["dsm_storage_node::api::tests::serves"], "pass")
        self.assertEqual(results["dsm_storage_node::config::tests::loads"], "pass")
        self.assertEqual(results["dsm_storage_node::no_clock_reads::no_node_source_reads_a_clock"], "pass")
        self.assertEqual(results["dsm::no_node_source_reads_a_clock"], "fail")
        self.assertNotIn("storage_node::config::tests::loads", results)
        self.assertNotIn("dsm::no_clock_reads::no_node_source_reads_a_clock", results)

    def test_a_result_behind_a_tests_own_output_is_read_from_its_binarys_summary(self):
        stamp = "2026-10-29T12:00:00.1234567Z "
        results = board(
            f"{stamp}     Running unittests src/lib.rs (target/release/deps/dsm_sdk-0b1c2d)\n"
            f"{stamp}test inbox::tests::speaks_then_passes ... [INFO] waiter stopped\n"
            f"{stamp}ok\n"
            f"{stamp}test inbox::tests::speaks_then_fails ... thread panicked\n"
            f"{stamp}FAILED\n"
            f"{stamp}test inbox::tests::quiet ... ok\n"
            f"{stamp}test inbox::tests::left_out ... ignored\n"
            f"{stamp}\n"
            f"{stamp}failures:\n"
            f"{stamp}\n"
            f"{stamp}failures:\n"
            f"{stamp}    inbox::tests::speaks_then_fails\n"
            f"{stamp}\n"
            f"{stamp}test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out\n"
            f"{stamp}     Running tests/aborts.rs (target/release/deps/aborts-0b1c2e)\n"
            f"{stamp}test the_process_dies_here ... about to abort\n"
        )
        self.assertEqual(results["dsm_sdk::inbox::tests::speaks_then_passes"], "pass")
        self.assertEqual(results["dsm_sdk::inbox::tests::speaks_then_fails"], "fail")
        self.assertEqual(results["dsm_sdk::inbox::tests::quiet"], "pass")
        self.assertEqual(results["dsm_sdk::inbox::tests::left_out"], "skipped")
        self.assertNotIn("dsm_sdk::aborts::the_process_dies_here", results)
        self.assertEqual(generator().board_status(results), "fail")

    def test_a_formal_artifact_takes_the_verdict_of_the_specifications_it_names(self):
        ga = generator()
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "tla-check.log"
            log.write_text(
                "  Running TLC: DSM_tiny (DSM_tiny.cfg) ...\n"
                "    PASSED (445427 states, 134183 distinct, depth 10)\n"
                "  Running TLC: DSM/crossing-settles-reachable (DSM_CrossingSettles.cfg) ...\n"
                "    FAILED [expected-to-fail] (1691629 states, 98968 distinct, depth 13)\n"
                "  Running TLC: OfflineFinality (DSM_OfflineFinality.cfg) ...\n"
                "    PASSED (6000 states, 900 distinct, depth 9)\n"
            )
            results = ga.tla_results(str(log))
        self.assertEqual(results["DSM_CrossingSettles.cfg"], "fail")
        self.assertEqual(results["DSM.tla"], "fail")
        self.assertEqual(results["DSM_OfflineFinality.tla"], "pass")
        self.assertEqual(ga.formal_tla_status("`tla/DSM_OfflineFinality.tla`", results, "fail"), "pass")
        self.assertEqual(ga.formal_tla_status("`tla/DSM.tla` (`DSM_CrossingSettles.cfg`)", results, "fail"), "fail")
        self.assertEqual(ga.formal_tla_status("`tla/DSM_Unchecked.tla`", results, "fail"), "incomplete")
        self.assertEqual(ga.formal_tla_status("TLA+ `DSM_tiny`: TLC model check", results, "fail"), "pass")
        self.assertEqual(ga.formal_tla_status("TLA+ `LeaderFromCommittedSet`", results, "fail"), "incomplete")
        self.assertEqual(ga.formal_tla_status("TLA+ `LeaderFromCommittedSet`", results, "pass"), "pass")
        shorthand = "TLA `DSM_OfflineFinality.tla` (reachable by `_Missing.cfg`)"
        self.assertEqual(ga.formal_tla_status(shorthand, results, "pass"), "incomplete")
        self.assertEqual(ga.formal_tla_status("TLA `DSM.tla` (`_tiny.cfg`)", results, "pass"), "fail")

    def test_a_requirements_status_is_its_row_in_the_per_requirement_results(self):
        ga = generator()
        text = (
            "## 6 Records\n\n| MR-ID | Was | Now |\n|---|---|---|\n"
            "| MR-DSM-0001 | Violated | Met | an earlier table: what the row was |\n"
            "| MR-DSM-0009 | Missing | Met | named only in the earlier table |\n\n"
            "## 8 Per-requirement results\n\n| MR-ID | Status | Code | Test | Note |\n|---|---|---|---|---|\n"
            "| MR-DSM-0001 | Met | code | test | — |\n"
            "| MR-DSM-0002 | Not code | — | — | superseded |\n\n"
            "## 9 After\n\n| MR-DSM-0003 | Violated | a later table |\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            gaps = Path(tmp) / "CONFORMANCE_GAPS.md"
            gaps.write_text(text)
            ga.GAPS = gaps
            self.assertEqual(ga.requirement_statuses(), {"MR-DSM-0001": "Met", "MR-DSM-0002": "Not code"})
            gaps.write_text("## 6 Records\n\n| MR-DSM-0001 | Violated | Met |\n")
            with self.assertRaises(SystemExit):
                ga.requirement_statuses()

    def test_the_repositorys_own_statuses_agree_with_its_totals(self):
        # The row that showed the fault: superseded by an amendment, and once read as Violated
        # from an earlier table that shows what it was.
        statuses = generator().requirement_statuses()
        self.assertEqual(statuses["MR-DSM-0275"], "Not code")
        counted = {}
        for status in statuses.values():
            counted[status] = counted.get(status, 0) + 1
        totals = re.search(r"\| \*\*All\*\* \| \*\*\d+\*\* \| \*\*\d+\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|", GAPS.read_text())
        self.assertIsNotNone(totals)
        partial, missing, violated, not_code = (int(x) for x in totals.groups())
        self.assertEqual((counted.get("Partial", 0), counted.get("Missing", 0), counted.get("Violated", 0), counted.get("Not code", 0)), (partial, missing, violated, not_code))

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

    def test_skipped_checks_say_skipped_and_hardware_says_what_the_repository_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            self.assertEqual(generate(run).returncode, 0)
            doc, ev = evidence(run)
            for check in ("lean", "conformance-evidence", "real-code-guard", "sphincs-map", "tla"):
                self.assertEqual(ev[f"ev-check-{check}"]["status"], "skipped", check)
            hardware = {ref: e for ref, e in ev.items() if ref.startswith("ev-hw-")}
            self.assertEqual(len(hardware), 6)
            gaps = GAPS.read_text()
            for ref, e in hardware.items():
                # Every hardware row says what the records hold; none is decided by this run.
                self.assertIn(e["status"], ("recorded", "not-run"), ref)
                self.assertTrue(e["reason"], ref)
                if e["status"] == "recorded":
                    # A recorded property names sections of CONFORMANCE_GAPS.md that exist.
                    self.assertEqual(e["executed"], "recorded", ref)
                    sections = re.findall(r"§(\d+\.\d+)", e["record"])
                    self.assertTrue(sections, ref)
                    for n in sections:
                        self.assertIn(f"\n### {n} ", gaps, f"{ref} names §{n}")
                else:
                    self.assertEqual(e["executed"], "never", ref)
                    self.assertNotIn("record", e, ref)
            report = (run / "assurance-report.md").read_text()
            self.assertNotIn("hardware stage has not started", report)
            self.assertEqual(doc["specVersion"], "1.7")
            self.assertEqual({c["type"] for c in doc["components"]}, {"application", "device", "firmware"})
            for e in ev.values():
                self.assertEqual(e["commit"], head())


if __name__ == "__main__":
    unittest.main()
