// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Phase B.7 (issue #278) — DeviceTreeViewer tests.
//
// The component is pure rendering: every verification boolean comes
// from the Rust SDK via `fetchDeviceTreeSnapshot`. These tests mock
// the bridge wrapper at the module boundary and assert the rendered
// badges follow the booleans.

import React, { act } from 'react';
import { render, screen, waitFor } from '@testing-library/react';

import { DeviceTreeViewer } from '../DeviceTreeViewer';

// Lightweight fakes that mirror the shape of
// `DeviceTreeSnapshotResponse` / `DeviceTreeV1` / `DeviceTreeLeafView`
// — only the fields the component reads. Using plain objects so the
// mock can hand them back without depending on protobuf classes.
type FakeTree = {
  schemaVersion: number;
  rootHash: Uint8Array;
  deviceCount: number;
  versionNumber: bigint;
};
type FakeLeaf = {
  deviceId: Uint8Array;
  proofBytes: Uint8Array;
  inclusionVerified: boolean;
};
type FakeSnapshot = {
  tree?: FakeTree;
  recomputedRoot: Uint8Array;
  claimedRootMatchesRecomputed: boolean;
  leaves: FakeLeaf[];
};

const mockFetchDeviceTreeSnapshot = jest.fn();

jest.mock('../../../dsm/WebViewBridge', () => ({
  fetchDeviceTreeSnapshot: (genesisHash: Uint8Array) =>
    mockFetchDeviceTreeSnapshot(genesisHash),
}));

function makeSnapshot(opts: {
  claimedRootMatchesRecomputed: boolean;
  leafVerifiedFlags: boolean[];
}): FakeSnapshot {
  const root = new Uint8Array(32).fill(0xab);
  const leaves: FakeLeaf[] = opts.leafVerifiedFlags.map((verified, i) => ({
    deviceId: new Uint8Array(32).fill(0x10 + i),
    proofBytes: new Uint8Array([0xfe, 0xed]),
    inclusionVerified: verified,
  }));
  return {
    tree: {
      schemaVersion: 1,
      rootHash: root,
      deviceCount: leaves.length,
      versionNumber: BigInt(7),
    },
    recomputedRoot: root,
    claimedRootMatchesRecomputed: opts.claimedRootMatchesRecomputed,
    leaves,
  };
}

describe('DeviceTreeViewer', () => {
  beforeEach(() => {
    mockFetchDeviceTreeSnapshot.mockReset();
  });

  it('shows the empty placeholder when no genesisHash is provided', () => {
    render(<DeviceTreeViewer genesisHash={null} />);
    expect(screen.getByText('No genesis hash provided.')).toBeTruthy();
    expect(mockFetchDeviceTreeSnapshot).not.toHaveBeenCalled();
  });

  it('shows loading then verified state for an honest snapshot', async () => {
    mockFetchDeviceTreeSnapshot.mockResolvedValueOnce(
      makeSnapshot({
        claimedRootMatchesRecomputed: true,
        leafVerifiedFlags: [true, true],
      }),
    );
    const genesisHash = new Uint8Array(32).fill(0x42);

    await act(async () => {
      render(<DeviceTreeViewer genesisHash={genesisHash} />);
    });

    await waitFor(() => {
      expect(screen.getByText('✓ Verified')).toBeTruthy();
    });
    // Two leaves both rendered as "✓ Included".
    expect(screen.getAllByText('✓ Included').length).toBe(2);
    expect(screen.queryByText(/Tampered/i)).toBeNull();
    expect(screen.queryByText('✗ Not included')).toBeNull();
  });

  it('shows the tampered badge when claimedRootMatchesRecomputed is false', async () => {
    mockFetchDeviceTreeSnapshot.mockResolvedValueOnce(
      makeSnapshot({
        claimedRootMatchesRecomputed: false,
        leafVerifiedFlags: [true],
      }),
    );
    const genesisHash = new Uint8Array(32).fill(0x42);

    await act(async () => {
      render(<DeviceTreeViewer genesisHash={genesisHash} />);
    });

    await waitFor(() => {
      // The tree-level tampered text contains "Tampered" — assert the
      // word, not the exact wording, so cosmetic copy changes don't
      // break the test.
      expect(screen.getByText(/Tampered/i)).toBeTruthy();
    });
    expect(screen.queryByText('✓ Verified')).toBeNull();
  });

  it('shows the error state when the bridge throws', async () => {
    mockFetchDeviceTreeSnapshot.mockRejectedValueOnce(
      new Error('no storage node returned a published Device Tree'),
    );
    const genesisHash = new Uint8Array(32).fill(0x42);

    await act(async () => {
      render(<DeviceTreeViewer genesisHash={genesisHash} />);
    });

    await waitFor(() => {
      expect(
        screen.getByText(/Failed to load:.*no storage node/i),
      ).toBeTruthy();
    });
  });

  it('flags a per-leaf "✗ Not included" when the SDK reports verification failure', async () => {
    mockFetchDeviceTreeSnapshot.mockResolvedValueOnce(
      makeSnapshot({
        claimedRootMatchesRecomputed: true,
        leafVerifiedFlags: [true, false, true],
      }),
    );
    const genesisHash = new Uint8Array(32).fill(0x42);

    await act(async () => {
      render(<DeviceTreeViewer genesisHash={genesisHash} />);
    });

    await waitFor(() => {
      expect(screen.getAllByText('✓ Included').length).toBe(2);
    });
    expect(screen.getAllByText('✗ Not included').length).toBe(1);
  });
});
