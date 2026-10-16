// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, item 9: the rig's read-only query hook is installed in a
// debug build alone. The build is the one the phone names; a release build,
// or a phone that names none, gets no hook.

import React from 'react';
import { act, render } from '@testing-library/react';
import { BridgeProvider } from '../BridgeProvider';
import { getBridgeInstance } from '../BridgeRegistry';
import { installScriptedPhone, removeScriptedPhone, settle } from '../../tests/helpers/scriptedPhone';
import type { AndroidBridgeV3 } from '../../dsm/bridgeTypes';

function installedBridge(): AndroidBridgeV3 {
  const bridge = getBridgeInstance();
  if (bridge === undefined) throw new Error('no bridge is installed');
  return bridge;
}

afterEach(() => {
  delete window.__dsmRigQuery;
  removeScriptedPhone();
});

describe('the rig query hook', () => {
  it('is installed when the phone names a debug build', async () => {
    installScriptedPhone({}, { buildType: new TextEncoder().encode('debug') });
    const { unmount } = render(<BridgeProvider bridge={installedBridge()}><span /></BridgeProvider>);
    await act(settle);
    expect(typeof window.__dsmRigQuery).toBe('function');
    unmount();
  });

  it('is not installed in a release build', async () => {
    installScriptedPhone({}, { buildType: new TextEncoder().encode('release') });
    const { unmount } = render(<BridgeProvider bridge={installedBridge()}><span /></BridgeProvider>);
    await act(settle);
    expect(window.__dsmRigQuery).toBeUndefined();
    unmount();
  });

  it('is not installed when the phone does not name the build', async () => {
    installScriptedPhone({});
    const { unmount } = render(<BridgeProvider bridge={installedBridge()}><span /></BridgeProvider>);
    await act(settle);
    expect(window.__dsmRigQuery).toBeUndefined();
    unmount();
  });
});
