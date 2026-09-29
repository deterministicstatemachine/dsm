#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The evidence pins (ci/intent_pins.py) prove what they refuse.

The check is read over the fixture's map (make requirement-map-fixture), which
indexes every build it has; the pins are sealed from its facts by the same
digests the pin commands write. Each case plants one change in a copy of the
fixture's manifest, requirements or pins and names the state and the change
class the check must report. The repin rule, the bootstrap rule, the board
evidence and the test names are read the same way, and the integration-test
naming over the repository's own map (make requirement-map). Run after both
maps are built; the Code map job does.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import intent_comparator as ic  # noqa: E402
import intent_pins as ip  # noqa: E402

# The map directory make builds (MAP): the repository's map, and the
# fixture's under it.
REPO_MAP = os.environ["MAP"]
FIXTURE_MAP = os.path.join(REPO_MAP, "fixture", "map")
FIXTURE = "tools/requirement_map/fixture"
MANIFEST = f"{FIXTURE}/intent.tsv"
REQUIREMENTS = f"{FIXTURE}/requirements.tsv"
# Real `cargo test` runs of single tests, captured whole (see the evidence test).
BOARD_LOGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "board-logs")
# The commit these pins are taken at: this tree's.
TESTED_AT = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()


def evaluated(manifest=MANIFEST, requirements=REQUIREMENTS):
    e = ic.evaluate(FIXTURE_MAP, manifest, requirements, "")
    return e.map, e.built, e.results


def sealed_pins(results, the_map):
    facts = ip.facts_of(results, the_map, ip.TOOL)
    return {ip.key_of(p): p for p in ip.seal_new(list(facts.values()), TESTED_AT, ip.TOOL)}


class Pins(unittest.TestCase):
    def setUp(self):
        for built in (FIXTURE_MAP, REPO_MAP):
            if not os.path.isfile(os.path.join(built, "defs.tsv")):
                self.fail(f"{built} is not built: make requirement-map-fixture and make requirement-map build them")
        self.work = tempfile.mkdtemp()
        self.the_map, self.built, self.results = evaluated()
        self.pins = sealed_pins(self.results, self.the_map)
        self.order = [ip.key_of(r) for r in self.results]

    def tearDown(self):
        shutil.rmtree(self.work)

    def copy(self, path, name, find=None, replace=None):
        out = os.path.join(self.work, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if find is not None:
            self.assertEqual(text.count(find), 1, f"{find!r} in {path}")
            text = text.replace(find, replace)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
        return out

    def states(self, pins, manifest=MANIFEST, requirements=REQUIREMENTS):
        path = os.path.join(self.work, "pins.tsv")
        ip.write_pins(path, pins, self.order)
        the_map, built, results = evaluated(manifest, requirements)
        return {k: (state, detail) for k, state, detail in ip.check(results, the_map, built, path, ip.TOOL)}

    def row_line(self, key):
        with open(MANIFEST, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        for line in lines:
            if line.split("\t")[:3] == list(key):
                return line
        self.fail(f"no manifest row {key}")

    def test_pins_sealed_from_the_facts_now_read_pinned(self):
        states = self.states(self.pins)
        rows = [r for r in ic._rows(MANIFEST, ic.COLUMNS) if r["requirement"] != "-"]
        self.assertEqual(len(states), len(rows))
        self.assertEqual({v[0] for v in states.values()}, {"PINNED"})

    def test_a_moved_manifest_cell_is_stale_under_its_class(self):
        key = next(iter(self.pins))
        line = self.row_line(key)
        cells = line.split("\t")
        for column, value, classes in (
            ("cites", cells[8] + " (moved)", "citation"),
            ("evidence", "probe::gates::tests::test_only", "code, evidence"),
        ):
            edited = list(cells)
            edited[ic.COLUMNS.index(column)] = value
            manifest = self.copy(MANIFEST, "intent.tsv", line, "\t".join(edited))
            state, detail = self.states(self.pins, manifest)[key]
            self.assertEqual(state, "PIN_STALE", column)
            self.assertEqual(", ".join(part.split(":")[0] for part in detail.split("; ")), classes, detail)

    def test_a_status_change_is_stale(self):
        requirements = self.copy(REQUIREMENTS, "requirements.tsv", "MR-FIX-0001\tMet", "MR-FIX-0001\tPartial")
        states = self.states(self.pins, requirements=requirements)
        for key, (state, detail) in states.items():
            if key[0] == "MR-FIX-0001":
                self.assertEqual((state, detail), ("PIN_STALE", "status: status Met -> Partial"))
            else:
                self.assertEqual(state, "PINNED", key)

    def test_a_hand_edit_is_tampered(self):
        key = next(iter(self.pins))
        parent = subprocess.run(["git", "rev-parse", "HEAD~1"], capture_output=True, text=True,
                                check=True).stdout.strip()
        for column, value in (("status", "Violated"), ("row", self.pins[key]["pin"]), ("tested_at", parent)):
            edited = dict(self.pins)
            edited[key] = {**self.pins[key], column: value}
            state = self.states(edited)[key][0]
            self.assertEqual(state, "PIN_TAMPERED", column)

    def test_a_code_change_under_a_pin_is_stale_as_code(self):
        key = next(iter(self.pins))
        other = next(p["production"] for k, p in self.pins.items() if p["production"] != self.pins[key]["production"])
        then = {**self.pins[key], "production": other}
        edited = dict(self.pins)
        edited[key] = ip.seal_new([{c: then[c] for c in ip.FACTS}], TESTED_AT, ip.TOOL)[0]
        state, detail = self.states(edited)[key]
        self.assertEqual(state, "PIN_STALE")
        self.assertTrue(detail.startswith("code: production "), detail)

    def test_an_orphan_pin_and_an_unpinned_row(self):
        key = next(iter(self.pins))
        dropped = {k: p for k, p in self.pins.items() if k != key}
        self.assertEqual(self.states(dropped)[key], ("UNPINNED", "no pin"))
        line = self.row_line(key)
        manifest = self.copy(MANIFEST, "intent.tsv", line + "\n", "")
        state = self.states(self.pins, manifest)[key][0]
        self.assertEqual(state, "ORPHAN_PIN")

    def test_repin_accepts_code_and_named_classes_only(self):
        key = next(iter(self.pins))
        now = self.pins[key]
        other = next(p for k, p in self.pins.items() if p["production"] != now["production"])
        self.assertIsNone(ip.judge_repin(key, now, {**now, "production": other["production"], "tests": other["tests"]}, []))
        refused = ip.judge_repin(key, now, {**now, "status": "Partial"}, [])
        self.assertIsNotNone(refused, "a status change repinned with nothing named")
        self.assertIn("moved beyond its code: status: status", refused)
        self.assertIn("--accept status", refused)
        self.assertIsNone(ip.judge_repin(key, now, {**now, "status": "Partial"}, ["status"]))
        self.assertIn("did not move", ip.judge_repin(key, now, now, ["root"]))
        self.assertIn("--accept takes", ip.judge_repin(key, now, now, ["code"]))
        self.assertIn("--accept takes", ip.judge_repin(key, now, now, ["everything"]))

    def test_the_bootstrap_never_touches_a_pin(self):
        facts = ip.facts_of(self.results, self.the_map, ip.TOOL)
        self.assertEqual(ip.add_unpinned(self.pins, facts), [])
        key = next(iter(self.pins))
        some = {k: p for k, p in self.pins.items() if k != key}
        self.assertEqual([ip.key_of(f) for f in ip.add_unpinned(some, facts)], [key])

    def test_evidence_counts_only_a_test_that_passed_on_the_board(self):
        import conformance_evidence as ce
        index = ce.build_index()[0]
        # A row of the repository's manifest whose evidence is one library
        # test, read against real board logs: each a `cargo test` run of the
        # test it names, captured whole with the flags the gate runs
        # (ci/fixtures/board-logs). passed.log ran it; not-run.log's filter
        # matched nothing; failed.log ran a node-backed test with no database
        # (its harness refuses); killed.log was stopped mid-test.
        facts = next(r for r in ic._rows(ic.MANIFEST, ic.COLUMNS)
                     if r["evidence"] == "dsm::route_chain::tests::an_unread_leader_is_missing_and_no_other_seat_stands_in")
        library = facts["evidence"]
        node_backed = "dsm_sdk::handlers::token_routes::tests::bytes_that_are_not_a_token_policy_are_not_published"
        killed = "dsm_sdk::handlers::node_e2e_tests::a_sofi_trade_executes_end_to_end"
        for name in (library, node_backed, killed):
            self.assertIn(name, index)

        def failures(name, log):
            return ip.evidence_failures([{**facts, "evidence": name}], [os.path.join(BOARD_LOGS, log)])

        self.assertEqual(failures(library, "passed.log"), [])
        self.assertIn(f"{library} did not run", failures(library, "not-run.log")[0])
        self.assertIn(f"{node_backed} failed", failures(node_backed, "failed.log")[0])
        self.assertIn(f"{killed} crashed", failures(killed, "killed.log")[0])
        # A test's pass is its own: another test's log is no evidence for it.
        self.assertIn(f"{library} did not run", failures(library, "failed.log")[0])
        # A name no test has: the premise is asserted, not assumed.
        missing = library + "_renamed"
        self.assertNotIn(missing, index)
        self.assertIn("is no test", ip.evidence_failures([{**facts, "evidence": missing}], [])[0])

    def test_a_test_name_resolves_to_its_closure(self):
        # The fixture's build compiles no test code (expected.tsv reads its
        # one test absent): a name that resolves to nothing is ABSENT.
        self.assertEqual(ip.test_closures(self.the_map)("probe::gates::tests::test_only"),
                         "absent:probe::gates::tests::test_only")
        repo = ic.rmap.load(REPO_MAP)
        closure = ip.test_closures(repo)
        library = "dsm::route_chain::tests::only_links_of_one_chain_count_toward_final"
        found = [d for d in repo["defs"] if d["path"] == library]
        self.assertEqual(len(found), 1)
        self.assertEqual(closure(library), found[0]["closure"])
        # An integration test, `crate::stem::name`, is held as `crate::name`
        # in `<crate>/tests/<stem>.rs`.
        at = [d for d in repo["defs"] if d["path"] == "dsm::each_position_of_each_identity_is_its_own_cell"
              and d["file"].endswith("dsm/tests/economic_lineage_register.rs")]
        self.assertEqual(len(at), 1)
        self.assertEqual(closure("dsm::economic_lineage_register::each_position_of_each_identity_is_its_own_cell"),
                         at[0]["closure"])
        # A library test renamed away: nothing in the map is held under it.
        gone = library + "_renamed"
        self.assertEqual([d for d in repo["defs"] if d["path"] == gone], [])
        self.assertEqual(closure(gone), f"absent:{gone}")
        self.assertEqual(ip.unresolved([{**self.pins[next(iter(self.pins))], "tests": closure(gone)}])[0]
                         .split(": ", 1)[1], f"the map holds no definition of {gone}")

    def test_the_gate_verifies_every_new_changed_or_missing_pin(self):
        rows = ic._rows(MANIFEST, ic.COLUMNS)
        self.assertEqual(ip.to_verify(rows, self.pins, self.pins), [])
        key = next(iter(self.pins))
        dropped = {k: p for k, p in self.pins.items() if k != key}
        changed = {**self.pins, key: {**self.pins[key], "pin": "ANOTHER"}}
        for head, base, why in ((dropped, self.pins, "missing"), (self.pins, dropped, "new"),
                                (changed, self.pins, "changed")):
            self.assertEqual([ip.key_of(r) for r in ip.to_verify(rows, head, base)], [key], why)
        # A row with no requirement carries no pin, and is never verified.
        self.assertNotIn("-", {r["requirement"] for r in ip.to_verify(rows, {}, {})})

    def test_the_gate_runs_exactly_the_named_tests(self):
        import conformance_evidence as ce
        index = ce.build_index()[0]
        library = "dsm::route_chain::tests::an_unread_leader_is_missing_and_no_other_seat_stands_in"
        integration = "dsm::economic_lineage_register::each_position_of_each_identity_is_its_own_cell"
        node = "dsm_storage_node::cells_keep_everything::only_malformed_requests_are_refused"
        flags = ["--", "--exact", "--nocapture", "--test-threads=1"]
        self.assertEqual(ip.cargo_runs([library, integration, node], index), [
            ["cargo", "test", "--locked", "--release", "-p", "dsm", "--lib", *flags,
             "route_chain::tests::an_unread_leader_is_missing_and_no_other_seat_stands_in"],
            ["cargo", "test", "--locked", "--release", "-p", "dsm", "--test", "economic_lineage_register", *flags,
             "each_position_of_each_identity_is_its_own_cell"],
            ["cargo", "test", "--locked", "--release", "-p", "dsm_storage_node", "--test", "cells_keep_everything",
             *flags, "only_malformed_requests_are_refused"],
        ])

    def test_the_pins_of_a_commit_are_read_from_it(self):
        # The repository's first commit holds no pins file: nothing is pinned
        # there.
        first = subprocess.run(["git", "rev-list", "--max-parents=0", "HEAD"], capture_output=True, text=True,
                               check=True).stdout.split()[0]
        self.assertEqual(ip.pins_at(first, ip.PINS), {})
        # A ref that names no commit here: the premise is asserted, not assumed.
        absent = f"{TESTED_AT}-renamed"
        self.assertNotEqual(subprocess.run(["git", "rev-parse", "--verify", "--quiet", absent],
                                           capture_output=True).returncode, 0)
        with self.assertRaises(ip.Refused) as refused:
            ip.pins_at(absent, ip.PINS)
        self.assertIn("is no commit here", str(refused.exception))

    def test_pinning_refuses_a_map_it_cannot_prove_is_this_trees(self):
        self.assertIn("records no tree", ip.fresh(FIXTURE_MAP, ip.TOOL))
        with self.assertRaises(ip.Refused) as refused:
            ip.every_build(self.the_map, [])
        self.assertIn("fixture is not indexed here", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
