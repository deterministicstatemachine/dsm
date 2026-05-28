// SPDX-License-Identifier: Apache-2.0
//
// Phase B.7 (issue #278) — DeviceTreeViewer WebView bridge wrapper.
//
// Pure-rendering React components call `fetchDeviceTreeSnapshot()` to
// hand a genesis hash to the Rust SDK, which:
//   1. Fetches the persisted DeviceTreeStateV1 from any storage node.
//   2. Re-canonicalises the leaf list and recomputes R_G.
//   3. Derives a fresh DeviceInclusionProofV1 for every leaf.
//   4. Verifies every proof locally with DevTreeProof::verify.
//   5. Returns a DeviceTreeSnapshotResponse with per-leaf
//      `inclusion_verified` + a tree-level
//      `claimed_root_matches_recomputed` gate.
//
// The frontend renders the returned booleans verbatim. No JS hashing,
// no @noble/hashes dependency — per the project rule
// `feedback_no_business_logic_in_frontend.md`.

import type { DeviceTreeSnapshotResponse } from "../../proto/dsm_app_pb";
import { invokeRouterEnvelope, toBytes } from "./transportCore";

/**
 * Fetch + verify the published Device Tree for `genesisHash` from any
 * configured storage node. Returns the decoded DeviceTreeSnapshotResponse
 * with all verification booleans populated by the Rust SDK.
 *
 * @throws on network failure, missing tree (no storage node returned
 *   a published DeviceTreeStateV1), or proto decode error from the
 *   bridge.
 */
export async function fetchDeviceTreeSnapshot(
  genesisHash: Uint8Array,
): Promise<DeviceTreeSnapshotResponse> {
  if (genesisHash.length !== 32) {
    throw new Error(
      `fetchDeviceTreeSnapshot: genesisHash must be 32 bytes, got ${genesisHash.length}`,
    );
  }
  // Dynamic import keeps the proto module shape loose enough for the
  // bufbuild-generated `Uint8Array` field type (which TS narrows to
  // `Uint8Array<ArrayBuffer>` in strict mode) to accept a plain
  // `new Uint8Array(input)` without a fresh-ArrayBuffer copy. Mirrors
  // the established `addSecondaryDeviceBin` pattern in genesis.ts.
  const pb = await import("../../proto/dsm_app_pb");
  // `toBytes()` widens / re-types the bufbuild-generated
  // `Uint8Array<ArrayBufferLike>` produced by `.toBinary()` to the
  // `Uint8Array<ArrayBuffer>` shape the generated proto field types
  // expect under TS 5.x strict mode. Mirrors the `addSecondaryDeviceBin`
  // pattern in genesis.ts.
  const req = new pb.DeviceTreeSnapshotRequest({
    genesisHash: toBytes(new Uint8Array(genesisHash)),
  });
  const arg = new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: toBytes(req.toBinary()),
  });
  const { envelope: env } = await invokeRouterEnvelope(
    "identity.devtree.snapshot",
    arg.toBinary(),
  );
  if (env.payload.case === "error") {
    const errMsg =
      env.payload.value.message ?? `Error code ${env.payload.value.code}`;
    throw new Error(`fetchDeviceTreeSnapshot failed: ${errMsg}`);
  }
  if (env.payload.case !== "deviceTreeSnapshotResponse") {
    throw new Error(
      `fetchDeviceTreeSnapshot: unexpected payload case ${env.payload.case}`,
    );
  }
  return env.payload.value;
}
