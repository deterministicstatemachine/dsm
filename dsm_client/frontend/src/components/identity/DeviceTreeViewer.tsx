// SPDX-License-Identifier: Apache-2.0
//
// Phase B.7 (issue #278) — DeviceTreeViewer.
//
// Pure-rendering React component. No hashing, no Merkle math, no
// `@noble/hashes` dependency. The Rust SDK (via the
// `identity.devtree.snapshot` query route) fetches the persisted
// `DeviceTreeStateV1` from any storage node, recomputes R_G from the
// canonical leaf list, derives + verifies an inclusion proof for every
// leaf, and hands us a `DeviceTreeSnapshotResponse` with:
//
//   - `tree`                              — claimed `DeviceTreeV1` summary
//   - `recomputedRoot`                    — R_G the SDK recomputed
//   - `claimedRootMatchesRecomputed`      — trust-but-verify gate
//   - `leaves[i].inclusionVerified`       — per-leaf verification result
//
// This component just renders those booleans. The verification
// pipeline is the same Rust code path the rest of the workspace
// exercises (DevTreeProof::verify in `dsm/src/common/device_tree.rs`),
// so there's no JS/Rust drift to worry about.

import * as React from "react";

import type { DeviceTreeSnapshotResponse } from "../../proto/dsm_app_pb";
import { fetchDeviceTreeSnapshot } from "../../dsm/WebViewBridge";
import { encodeBase32Crockford } from "../../utils/textId";

/**
 * Hook: fetches a `DeviceTreeSnapshotResponse` for the given genesis
 * hash, exposing explicit `loading` / `error` / `snapshot` states.
 * Re-fetches when `genesisHash` changes.
 */
export function useDeviceTreeSnapshot(genesisHash: Uint8Array | null): {
  loading: boolean;
  error: string | null;
  snapshot: DeviceTreeSnapshotResponse | null;
} {
  const [loading, setLoading] = React.useState<boolean>(false);
  const [error, setError] = React.useState<string | null>(null);
  const [snapshot, setSnapshot] =
    React.useState<DeviceTreeSnapshotResponse | null>(null);

  React.useEffect(() => {
    if (!genesisHash || genesisHash.length !== 32) {
      setSnapshot(null);
      setError(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetchDeviceTreeSnapshot(genesisHash)
      .then((s) => {
        if (cancelled) return;
        setSnapshot(s);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [genesisHash]);

  return { loading, error, snapshot };
}

interface DeviceTreeViewerProps {
  /** 32-byte genesis hash. Pass `null` to skip the fetch. */
  genesisHash: Uint8Array | null;
}

/**
 * Renders the current Device Tree for `genesisHash`. Tree-level
 * "✓ R_G verified" or "✗ Tampered" badge is wired off
 * `snapshot.claimedRootMatchesRecomputed`. Per-leaf badges are wired
 * off `snapshot.leaves[i].inclusionVerified`. All verification
 * booleans come from Rust.
 */
export function DeviceTreeViewer(props: DeviceTreeViewerProps): JSX.Element {
  const { loading, error, snapshot } = useDeviceTreeSnapshot(props.genesisHash);

  if (props.genesisHash === null) {
    return (
      <section className="device-tree-viewer device-tree-viewer--empty">
        <h3>Device Tree</h3>
        <p>No genesis hash provided.</p>
      </section>
    );
  }
  if (loading) {
    return (
      <section className="device-tree-viewer device-tree-viewer--loading">
        <h3>Device Tree</h3>
        <p>Loading…</p>
      </section>
    );
  }
  if (error !== null) {
    return (
      <section className="device-tree-viewer device-tree-viewer--error">
        <h3>Device Tree</h3>
        <p>Failed to load: {error}</p>
      </section>
    );
  }
  if (snapshot === null) {
    return (
      <section className="device-tree-viewer device-tree-viewer--empty">
        <h3>Device Tree</h3>
        <p>No tree published yet.</p>
      </section>
    );
  }

  const tree = snapshot.tree;
  const recomputedRoot = snapshot.recomputedRoot;
  const matches = snapshot.claimedRootMatchesRecomputed;
  const leaves = snapshot.leaves;

  return (
    <section className="device-tree-viewer">
      <h3>Device Tree</h3>

      <dl className="device-tree-viewer__summary">
        <dt>Root (R_G)</dt>
        <dd>
          <code>{shortBase32(recomputedRoot, 16)}</code>{" "}
          {matches ? (
            <span
              role="status"
              className="device-tree-viewer__badge device-tree-viewer__badge--ok"
            >
              ✓ Verified
            </span>
          ) : (
            <span
              role="status"
              className="device-tree-viewer__badge device-tree-viewer__badge--bad"
            >
              ✗ Tampered (claimed root differs from recomputed)
            </span>
          )}
        </dd>
        <dt>Devices</dt>
        <dd>{tree?.deviceCount ?? 0}</dd>
        <dt>Version</dt>
        <dd>{tree ? String(tree.versionNumber) : "0"}</dd>
      </dl>

      {leaves.length === 0 ? (
        <p>(no leaves)</p>
      ) : (
        <ul className="device-tree-viewer__leaves">
          {leaves.map((leaf, i) => (
            <li
              key={`leaf-${i}-${shortBase32(leaf.deviceId, 12)}`}
              className="device-tree-viewer__leaf"
            >
              <code>{shortBase32(leaf.deviceId, 12)}</code>{" "}
              {leaf.inclusionVerified ? (
                <span
                  role="status"
                  className="device-tree-viewer__badge device-tree-viewer__badge--ok"
                >
                  ✓ Included
                </span>
              ) : (
                <span
                  role="status"
                  className="device-tree-viewer__badge device-tree-viewer__badge--bad"
                >
                  ✗ Not included
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * Render the first `n` Base32 Crockford characters of `bytes` for
 * display. Used for tree root + device id truncation. No security
 * implication — purely a UI affordance to keep rows scannable.
 */
function shortBase32(bytes: Uint8Array, n: number): string {
  if (!bytes || bytes.length === 0) {
    return "";
  }
  const full = encodeBase32Crockford(bytes);
  return full.length > n ? `${full.slice(0, n)}…` : full;
}
