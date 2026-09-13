#!/usr/bin/env python3
"""The selector proves itself before it is allowed to narrow anything.

Every case here is a rule the owner required (2026-09-13): a core change can
never select core alone; the SDK's jni module is SDK *and* JNI_ANDROID with
their escalations; STORAGE reaches its node-protocol SDK coverage; a
frontend-only change compiles no Rust; Cargo.lock, workflow files, shared
fixtures, build.rs and unknown paths yield FULL; two surfaces produce the
union; workflow_dispatch FULL turns everything on; push and schedule ignore
narrowing.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import select_layers as sl  # noqa: E402

CFG = sl.load_map(Path(__file__).with_name("layers.toml"))
ALL = set(sl.ALL_LAYERS)
DSM = "dsm_client/deterministic_state_machine/dsm/src/"
SDK = "dsm_client/deterministic_state_machine/dsm_sdk/src/"


def sel(files, event="pull_request", preset=None):
    layers, full, _ = sl.select(CFG, files, event, preset)
    return layers, full


def groups(layers):
    return {g["group"] for g in sl.rust_matrix(CFG, layers)}


class Selector(unittest.TestCase):
    def test_core_never_yields_core_alone(self):
        layers, full = sel([DSM + "types/device_state.rs"])
        self.assertFalse(full)
        self.assertEqual(layers, {"CORE", "SDK", "JNI_ANDROID", "STORAGE", "FORMAL", "SDK_NODE_PROTOCOL"})
        self.assertNotIn("FRONTEND", layers)
        self.assertEqual(groups(layers), {"dsm", "dsm_sdk", "workspace-rest"})

    def test_sdk_only_change(self):
        layers, full = sel([SDK + "handlers/dlv_routes.rs"])
        self.assertFalse(full)
        self.assertEqual(layers, {"SDK", "JNI_ANDROID", "FORMAL"})
        self.assertEqual(groups(layers), {"dsm_sdk", "workspace-rest"})

    def test_sdk_jni_module_is_sdk_and_jni_android(self):
        layers, full = sel([SDK + "jni/event_dispatch.rs"])
        self.assertFalse(full)
        self.assertTrue({"SDK", "JNI_ANDROID", "FORMAL"} <= layers)
        self.assertNotIn("CORE", layers)

    def test_android_change_escalates_to_sdk(self):
        layers, _ = sel(["dsm_client/android/app/src/main/java/com/dsm/wallet/Bridge.kt"])
        self.assertTrue({"JNI_ANDROID", "SDK"} <= layers)

    def test_storage_reaches_its_node_protocol_sdk_coverage(self):
        layers, full = sel(["dsm_storage_node/src/main.rs"])
        self.assertFalse(full)
        self.assertEqual(layers, {"STORAGE", "SDK_NODE_PROTOCOL"})
        self.assertEqual(groups(layers), {"sdk-node-protocol", "workspace-rest"})
        run = next(g["run"] for g in sl.rust_matrix(CFG, layers) if g["group"] == "sdk-node-protocol")
        self.assertIn("handlers::storage_routes", run)
        self.assertIn("--test b0x_integration", run)

    def test_storage_plus_sdk_runs_full_sdk_not_the_narrow_group(self):
        layers, _ = sel(["dsm_storage_node/src/main.rs", SDK + "sdk/token_sdk.rs"])
        self.assertEqual(groups(layers), {"dsm_sdk", "workspace-rest"})

    def test_frontend_alone_compiles_no_rust(self):
        layers, full = sel(["dsm_client/frontend/src/components/screens/SwapTab.tsx"])
        self.assertFalse(full)
        self.assertEqual(layers, {"FRONTEND"})
        self.assertFalse(layers & sl.RUST_LAYERS)
        self.assertEqual(groups(layers), set())

    def test_formal_only(self):
        layers, full = sel(["tla/DSM_Abstract.tla", "lean4/Core.lean"])
        self.assertFalse(full)
        self.assertEqual(layers, {"FORMAL"})
        self.assertEqual(groups(layers), {"workspace-rest"})

    def test_full_triggers(self):
        for f in [
            "Cargo.lock",
            "dsm_client/deterministic_state_machine/dsm_sdk/Cargo.toml",
            ".github/workflows/ci.yml",
            "ci/layers.toml",
            SDK + "test_support/two_device.rs",
            SDK + "economic_fixtures.rs",
            "dsm_client/deterministic_state_machine/dsm/build.rs",
            "proto/dsm_app.proto",
            DSM + "crypto/blake3.rs",
        ]:
            layers, full = sel([f, "dsm_client/frontend/src/index.tsx"])
            self.assertTrue(full, f)
            self.assertEqual(layers, ALL, f)

    def test_unknown_path_is_full(self):
        layers, full = sel(["docs/whitepaper.tex"])
        self.assertTrue(full)
        self.assertEqual(layers, ALL)
        layers, full = sel(["some/new/tree/file.rs", "dsm_client/frontend/src/a.ts"])
        self.assertTrue(full)

    def test_markdown_only_is_full_not_nothing(self):
        layers, full = sel(["README.md", "docs/plans/x.md"])
        self.assertTrue(full)

    def test_two_surfaces_produce_the_union(self):
        layers, full = sel(["dsm_client/frontend/src/a.tsx", "dsm_storage_node/src/lib.rs"])
        self.assertFalse(full)
        self.assertEqual(layers, {"FRONTEND", "STORAGE", "SDK_NODE_PROTOCOL"})

    def test_dispatch_full_turns_everything_on(self):
        layers, full = sel([], event="workflow_dispatch", preset="FULL")
        self.assertTrue(full)
        self.assertEqual(layers, ALL)

    def test_preset_uses_the_same_escalation_graph(self):
        layers, full = sel([], event="workflow_dispatch", preset="CORE")
        self.assertFalse(full)
        self.assertEqual(layers, {"CORE", "SDK", "JNI_ANDROID", "STORAGE", "FORMAL", "SDK_NODE_PROTOCOL"})
        layers, _ = sel([], event="workflow_dispatch", preset="STORAGE")
        self.assertEqual(layers, {"STORAGE", "SDK_NODE_PROTOCOL"})
        layers, full = sel([], event="workflow_dispatch", preset="bogus")
        self.assertTrue(full)

    def test_push_and_schedule_ignore_narrowing(self):
        for ev in ("push", "schedule"):
            layers, full = sel(["dsm_client/frontend/src/a.tsx"], event=ev)
            self.assertTrue(full, ev)
            self.assertEqual(layers, ALL, ev)

    def test_globs(self):
        self.assertTrue(sl.matches_any("a/b/Cargo.toml", ["**/Cargo.toml"]))
        self.assertTrue(sl.matches_any("Cargo.toml", ["**/Cargo.toml"]))
        self.assertFalse(sl.matches_any("crates/x/src/lib.rs", ["dsm_client/**"]))
        self.assertTrue(sl.matches_any("rust-toolchain.toml", ["rust-toolchain*"]))


if __name__ == "__main__":
    unittest.main(verbosity=1)
