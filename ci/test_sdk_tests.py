#!/usr/bin/env python3
"""ci/sdk_tests.py proves itself before it may split anything: a split loses
no test and runs none twice, and a shard that ran other than its share fails.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import sdk_tests as st  # noqa: E402


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

    def test_outputs_ask_for_at_least_one_shard(self):
        out = dict(l.split("=", 1) for l in st.shard_outputs({}))
        self.assertEqual(json.loads(out["sdk_shards"]), [{"shard": 1, "of": 1}])

    def test_the_recorded_times_cover_a_real_suite_and_balance_to_the_longest_test(self):
        times = st.read_times(Path(__file__).with_name("sdk_test_times.tsv"))
        self.assertGreater(len(times), 1000)
        n = st.shard_count(sum(times.values()))
        self.assertEqual(n, st.MAX_SHARDS)
        floor = max(max(times.values()), sum(times.values()) / n)
        loads = [sum(times[t] for t in p) for p in st.partition(list(times), times, n)]
        # Within two minutes of the floor no split can go under.
        self.assertLessEqual(max(loads), floor + 120)


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

    def test_learn_times_charges_each_test_up_to_the_line_that_ends_it(self):
        # GitHub stamps a line when it ends: a silent test's whole line when
        # it finishes, a printing test's `ok` line when it finishes.
        log = "\n".join([
            "2026-11-09T06:14:07.6992799Z      Running unittests src/lib.rs (target/release/deps/dsm_sdk-x)",
            "2026-11-09T06:14:07.7000000Z running 4 tests",
            "2026-11-09T06:14:08.0000000Z test a::x ... ok",
            "2026-11-09T06:14:08.5000000Z test a::y ... some captured output",
            "2026-11-09T06:14:11.0000000Z more output",
            "2026-11-09T06:14:13.5000000Z ok",
            "2026-11-09T06:14:34.0000000Z test b::slow ... ok",
            "2026-11-09T06:14:34.5000000Z test b::skip ... ignored, needs a device",
            "2026-11-09T06:14:35.0000000Z test result: ok. 3 passed; 0 failed; 1 ignored",
            "2026-11-09T06:14:36.0000000Z test other_binary::w ... ok",
        ])
        self.assertEqual(
            st.learn_times(log),
            {"a::x": 0.3, "a::y": 5.5, "b::slow": 20.5, "b::skip": 0.5},
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
