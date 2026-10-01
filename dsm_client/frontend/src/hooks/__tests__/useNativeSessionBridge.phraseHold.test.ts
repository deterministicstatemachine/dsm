// SPDX-License-Identifier: Apache-2.0
// The recovery phrase stays on the screen while the native session reports
// that no wallet exists yet; the real stores and the real event bus.

import { act, renderHook } from '@testing-library/react';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { appRuntimeStore } from '../../runtime/appRuntimeStore';
import { DEFAULT_NATIVE_SESSION, type NativeSessionSnapshot } from '../../runtime/nativeSessionTypes';
import { useNativeSessionBridge } from '../useNativeSessionBridge';

function publish(overrides: Partial<NativeSessionSnapshot>): void {
  act(() => {
    bridgeEvents.emit('session.state', { ...DEFAULT_NATIVE_SESSION, ...overrides });
  });
}

function mountBridge(): void {
  renderHook(() => useNativeSessionBridge({ themes: ['stateboy'], setThemeIndex: () => {} }));
}

describe('useNativeSessionBridge while the recovery phrase is on the screen', () => {
  beforeEach(() => {
    mountBridge();
    publish({ phase: 'needs_genesis', identity_status: 'missing' });
    act(() => {
      appRuntimeStore.setAppState('backup_phrase');
    });
  });

  it('keeps the phrase on the screen while the session still reports no wallet', () => {
    publish({ phase: 'needs_genesis', identity_status: 'missing' });
    expect(appRuntimeStore.getSnapshot().appState).toBe('backup_phrase');

    publish({ phase: 'runtime_loading', identity_status: 'missing' });
    expect(appRuntimeStore.getSnapshot().appState).toBe('backup_phrase');
  });

  it('follows the session once genesis moves it on', () => {
    publish({ phase: 'securing_device', identity_status: 'missing' });
    expect(appRuntimeStore.getSnapshot().appState).toBe('securing_device');
  });

  it('shows a fatal session error over the phrase', () => {
    publish({ phase: 'error', identity_status: 'missing', fatal_error: 'storage unavailable' });
    expect(appRuntimeStore.getSnapshot().appState).toBe('error');
    expect(appRuntimeStore.getSnapshot().error).toBe('storage unavailable');
  });
});

describe('useNativeSessionBridge outside the recovery phrase', () => {
  it('follows the session to setup', () => {
    mountBridge();
    act(() => {
      appRuntimeStore.setAppState('wallet_ready');
    });
    publish({ phase: 'needs_genesis', identity_status: 'missing' });
    expect(appRuntimeStore.getSnapshot().appState).toBe('needs_genesis');
  });
});
