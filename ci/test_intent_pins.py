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
        for column, value in (("status", "Violated"), ("row", self.pins[key]["pin"]), ("tested_at", "another")):
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
        self.assertIsNone(ip.judge_repin(key, now, {**now, "production": "CHANGED", "tests": "CHANGED"}, []))
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
        # test, and a board log of that test's binary as cargo writes it.
        facts = next(r for r in ic._rows(ic.MANIFEST, ic.COLUMNS)
                     if r["evidence"] == "dsm::route_chain::tests::an_unread_leader_is_missing_and_no_other_seat_stands_in")
        name = facts["evidence"]
        self.assertIn(name, index)
        cargo_path = index[name][1]

        def failures(body):
            log = os.path.join(self.work, "board.log")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write("     Running unittests src/lib.rs (target/release/deps/dsm-0123456789abcdef)\n\n" + body)
            return ip.evidence_failures([facts], [log])

        self.assertEqual(failures(f"test {cargo_path} ... ok\n\ntest result: ok. 1 passed\n"), [])
        self.assertIn("failed", failures(f"test {cargo_path} ... FAILED\n\nfailures:\n    {cargo_path}\n\n"
                                         f"test result: FAILED. 0 passed; 1 failed\n")[0])
        self.assertIn("crashed", failures(f"test {cargo_path} ... ")[0])
        self.assertIn("did not run", failures("test result: ok. 0 passed\n")[0])
        self.assertIn("is no test", ip.evidence_failures([{**facts, "evidence": "dsm::no::such_test"}], [])[0])

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
        self.assertEqual(closure("dsm::no_such_file::no_such_test"), "absent:dsm::no_such_file::no_such_test")
        self.assertEqual(ip.unresolved([{**self.pins[next(iter(self.pins))], "tests": "absent:dsm::x::y"}])[0].split(": ", 1)[1],
                         "the map holds no definition of dsm::x::y")

    def test_pinning_refuses_a_map_it_cannot_prove_is_this_trees(self):
        self.assertIn("records no tree", ip.fresh(FIXTURE_MAP, ip.TOOL))
        with self.assertRaises(ip.Refused) as refused:
            ip.every_build(self.the_map, [])
        self.assertIn("fixture is not indexed here", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
