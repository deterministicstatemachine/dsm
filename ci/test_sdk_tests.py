#!/usr/bin/env python3
"""ci/sdk_tests.py proves itself before it may narrow or split anything.

Every rule that makes a run do LESS has a case here: what a pull request may
skip, and that a split loses no test and runs none twice. Every doubt must
resolve to running every test.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import sdk_tests as st  # noqa: E402

SDK = "dsm_client/deterministic_state_machine/dsm_sdk"
DSM = "dsm_client/deterministic_state_machine/dsm"
NODE_E2E = f"{SDK}/src/handlers/node_e2e_tests.rs"
BLE = f"{SDK}/src/bluetooth/offline_step.rs"
CORE_HASH = f"{DSM}/src/crypto/blake3.rs"
UNRUN = f"{SDK}/src/handlers/unrun.rs"

# A map shaped like the one test-map.yml builds.
MAP = {
    "version": st.MAP_VERSION,
    "commit": "c0ffee",
    "complete": True,
    "failed_modules": [],
    "dep_roots": [SDK, DSM],
    "files": [BLE, CORE_HASH, NODE_E2E, UNRUN],
    "modules": {
        "handlers::node_e2e_tests": [1, 2],
        "bluetooth::offline_step_tests": [0, 1],
        "storage::client_db": [],
    },
}


def no_lines(_path):
    return ["    let x = y + 1;"]


def sel(files, test_map=MAP, full=False, lines=no_lines):
    return st.select_tests(test_map, files, full, lines)[0]


class Selection(unittest.TestCase):
    def test_full_runs_everything(self):
        self.assertEqual(sel([NODE_E2E], full=True), {"mode": "all"})

    def test_no_map_runs_everything(self):
        self.assertEqual(sel([NODE_E2E], test_map=None), {"mode": "all"})

    def test_incomplete_or_foreign_map_runs_everything(self):
        self.assertEqual(sel([NODE_E2E], test_map={**MAP, "complete": False}), {"mode": "all"})
        self.assertEqual(sel([NODE_E2E], test_map={**MAP, "version": 0}), {"mode": "all"})

    def test_a_file_selects_exactly_the_modules_that_execute_it(self):
        s = sel([NODE_E2E])
        self.assertEqual(s["mode"], "impact")
        self.assertEqual(s["modules"], ["handlers::node_e2e_tests"])
        s = sel([CORE_HASH])
        self.assertEqual(s["modules"], ["bluetooth::offline_step_tests", "handlers::node_e2e_tests"])

    def test_a_file_the_map_never_saw_runs_everything(self):
        self.assertEqual(sel([f"{SDK}/src/handlers/brand_new.rs"]), {"mode": "all"})
        # Non-Rust inputs of a linked crate (SQL, fixtures) are unknown too.
        self.assertEqual(sel([f"{DSM}/src/fixtures/vector.bin"]), {"mode": "all"})

    def test_a_linked_file_no_module_executes_runs_everything(self):
        self.assertEqual(sel([UNRUN]), {"mode": "all"})

    def test_lines_coverage_cannot_attribute_run_everything(self):
        for line in (
            "const LIMIT: u64 = 5;",
            "pub const LIMIT: u64 = 5;",
            "    pub(crate) static TABLE: [u8; 4] = [0; 4];",
            "macro_rules! check {",
            '    let v = include_bytes!("v.bin");',
            'const X: &str = include_str!("x");',
        ):
            with self.subTest(line=line):
                self.assertEqual(sel([NODE_E2E], lines=lambda _f, l=line: [l]), {"mode": "all"})

    def test_a_const_inside_an_expression_is_not_a_declaration(self):
        s = sel([NODE_E2E], lines=lambda _f: ["    let total = constant_of(x);"])
        self.assertEqual(s["mode"], "impact")

    def test_files_outside_the_linked_crates_select_nothing(self):
        s = sel(["dsm_client/frontend/src/App.tsx", "dsm_storage_node/src/main.rs"])
        self.assertEqual(s, {"mode": "impact", "modules": [], "known_modules": sorted(MAP["modules"])})

    def test_integration_tests_and_markdown_select_nothing(self):
        s = sel([f"{SDK}/tests/ble_smoke.rs", f"{DSM}/tests/x.rs", f"{SDK}/src/README.md"])
        self.assertEqual(s["modules"], [])

    def test_the_most_specific_crate_owns_a_file(self):
        self.assertEqual(st.owning_root(f"{SDK}/src/a.rs", [DSM, SDK]), SDK + "/")
        # A sibling directory that merely shares a prefix is not inside the crate.
        self.assertIsNone(st.owning_root(f"{DSM}_extra/src/a.rs", [DSM]))
        # A package at the repository root owns what no deeper crate owns.
        self.assertEqual(st.owning_root("src/a.rs", ["."]), "")
        self.assertEqual(st.owning_root(f"{SDK}/src/a.rs", [".", SDK]), SDK + "/")

    def test_a_root_package_still_skips_its_integration_tests(self):
        m = {**MAP, "dep_roots": ["."], "files": ["src/a.rs"], "modules": {"a::tests": [0]}}
        self.assertEqual(sel(["src/a.rs"], test_map=m)["modules"], ["a::tests"])
        self.assertEqual(sel(["tests/it.rs"], test_map=m)["modules"], [])


class Choosing(unittest.TestCase):
    NAMES = [
        "handlers::node_e2e_tests::a",
        "handlers::node_e2e_tests::b",
        "bluetooth::offline_step_tests::c",
        "handlers::added_after_the_map::d",
    ]

    def test_all_chooses_every_listed_test(self):
        self.assertEqual(st.chosen_tests(self.NAMES, {"mode": "all"}), self.NAMES)

    def test_impact_keeps_selected_modules_and_every_module_the_map_does_not_know(self):
        s = sel([NODE_E2E])
        self.assertEqual(
            st.chosen_tests(self.NAMES, s),
            ["handlers::node_e2e_tests::a", "handlers::node_e2e_tests::b", "handlers::added_after_the_map::d"],
        )

    def test_module_keys(self):
        self.assertEqual(st.module_key("handlers::node_e2e_tests::x"), "handlers::node_e2e_tests")
        self.assertEqual(st.module_key("handlers::bilateral_finality_tests::many::x"), "handlers::bilateral_finality_tests")
        self.assertEqual(st.module_key("tests::x"), "tests")
        self.assertEqual(st.module_key("x"), "<root>")


class Sharding(unittest.TestCase):
    def test_every_test_lands_in_exactly_one_shard(self):
        names = [f"m{i % 7}::t{i}" for i in range(500)]
        times = {n: float(i % 13) for i, n in enumerate(names[:300])}  # some unknown
        for shards in range(1, 10):
            parts = st.partition(names, times, shards)
            self.assertEqual(len(parts), shards)
            flat = [n for p in parts for n in p]
            self.assertEqual(sorted(flat), sorted(names))
            self.assertEqual(len(flat), len(set(flat)))

    def test_the_partition_is_deterministic_whatever_the_list_order(self):
        names = [f"m::t{i}" for i in range(100)]
        times = {n: float(i) for i, n in enumerate(names)}
        self.assertEqual(st.partition(names, times, 4), st.partition(list(reversed(names)), times, 4))

    def test_shards_balance_by_time(self):
        times = {"big": 100.0, **{f"s{i}": 10.0 for i in range(10)}}
        loads = sorted(sum(times[n] for n in p) for p in st.partition(list(times), times, 2))
        self.assertEqual(loads, [100.0, 100.0])

    def test_shard_count_bounds(self):
        self.assertEqual(st.shard_count(0), 1)
        self.assertEqual(st.shard_count(st.TARGET_SHARD_SECONDS), 1)
        self.assertEqual(st.shard_count(st.TARGET_SHARD_SECONDS + 1), 2)
        self.assertEqual(st.shard_count(10**9), st.MAX_SHARDS)

    def test_outputs_always_ask_for_at_least_one_shard(self):
        out = dict(l.split("=", 1) for l in st.selection_outputs(sel([]), "r", {}))
        self.assertEqual(json.loads(out["sdk_shards"]), [{"shard": 1, "of": 1}])

    def test_the_recorded_times_cover_a_real_suite(self):
        times = st.read_times(Path(__file__).with_name("sdk_test_times.tsv"))
        self.assertGreater(len(times), 1000)
        self.assertEqual(st.shard_count(sum(times.values())), st.MAX_SHARDS)


class Parsing(unittest.TestCase):
    def test_list(self):
        text = "a::b: test\nc::d: test\nbench_x: benchmark\n\n"
        self.assertEqual(st.parse_list(text), ["a::b", "c::d"])
        with self.assertRaises(SystemExit):
            st.parse_list("a: test\na: test\n")

    def test_ran_count_counts_passed_failed_and_ignored(self):
        log = (
            "test result: ok. 10 passed; 0 failed; 2 ignored; 0 measured; 900 filtered out; finished in 1s\n"
            "\x1b[32mtest result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\x1b[0m\n"
        )
        self.assertEqual(st.ran_count(log), 16)

    def test_learn_times_from_a_serial_job_log(self):
        log = "\n".join([
            "2026-11-09T06:14:07.6992799Z      Running unittests src/lib.rs (target/release/deps/dsm_sdk-x)",
            "2026-11-09T06:14:07.7000000Z running 3 tests",
            "2026-11-09T06:14:08.0000000Z test a::x ... ok",
            "2026-11-09T06:14:10.5000000Z test a::y ... ",
            "2026-11-09T06:14:11.0000000Z some captured output",
            "2026-11-09T06:14:13.5000000Z ok",
            "2026-11-09T06:14:14.0000000Z test b::z ... ok",
            "2026-11-09T06:14:15.0000000Z test result: ok. 3 passed; 0 failed; 0 ignored",
            "2026-11-09T06:14:16.0000000Z test other_binary::w ... ok",
        ])
        self.assertEqual(st.learn_times(log), {"a::x": 2.5, "a::y": 3.5, "b::z": 1.0})


class TheMap(unittest.TestCase):
    ROOT = Path("/work/dsm")

    def export(self, covered: dict) -> dict:
        files = [
            {
                "filename": f,
                "summary": {"lines": {"covered": c, "count": 10}, "regions": {"covered": c, "count": 10}},
            }
            for f, c in covered.items()
        ]
        return {"data": [{"files": files}]}

    def test_assemble_keeps_repository_files_and_what_each_module_executed(self):
        exports = {
            "m::a": self.export({"/work/dsm/x.rs": 3, "/work/dsm/y.rs": 0, "/home/r/.cargo/registry/z.rs": 9}),
            "m::b": self.export({"/work/dsm/y.rs": 1}),
        }
        m = st.assemble_map(exports, set(), ["x"], self.ROOT, "abc")
        self.assertTrue(m["complete"])
        self.assertEqual(m["files"], ["x.rs", "y.rs"])
        self.assertEqual(m["modules"], {"m::a": [0], "m::b": [1]})

    def test_a_failed_module_makes_the_map_incomplete(self):
        m = st.assemble_map({"m::a": self.export({})}, {"m::b"}, [], self.ROOT, "abc")
        self.assertFalse(m["complete"])
        self.assertEqual(sel([NODE_E2E], test_map=m), {"mode": "all"})

    def test_dep_roots_follow_every_dependency_kind_and_drop_registry_crates(self):
        def pkg(name, path, source=None):
            return {"id": name, "name": name, "source": source, "manifest_path": f"/work/dsm/{path}/Cargo.toml"}

        metadata = {
            "packages": [
                pkg("dsm_sdk", SDK), pkg("dsm", DSM), pkg("dev_only", "crates/dev_only"),
                pkg("unrelated", "crates/unrelated"), pkg("serde", "x", source="registry+https://x"),
            ],
            "resolve": {"nodes": [
                {"id": "dsm_sdk", "deps": [{"pkg": "dsm"}, {"pkg": "dev_only"}, {"pkg": "serde"}]},
                {"id": "dsm", "deps": []},
                {"id": "dev_only", "deps": []},
                {"id": "unrelated", "deps": []},
                {"id": "serde", "deps": []},
            ]},
        }
        self.assertEqual(st.dep_roots(metadata, self.ROOT), sorted(["crates/dev_only", DSM, SDK]))


if __name__ == "__main__":
    unittest.main(verbosity=1)
