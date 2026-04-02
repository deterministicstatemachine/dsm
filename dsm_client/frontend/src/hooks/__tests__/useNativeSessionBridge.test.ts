/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook, act } from '@testing-library/react';

const mockGetPreference = jest.fn();
jest.mock('../../services/dsmClient', () => ({
  dsmClient: {
    getPreference: (...args: any[]) => mockGetPreference(...args),
  },
}));

jest.mock('../../utils/audio', () => ({
  AudioManager: { enabled: false },
}));

const mockApplyTheme = jest.fn();
jest.mock('../../utils/theme', () => ({
  applyTheme: (...args: any[]) => mockApplyTheme(...args),
}));

const mockAppRuntimeStore = {
  setAppState: jest.fn(),
  setError: jest.fn(),
  setTheme: jest.fn(),
  setSoundEnabled: jest.fn(),
};
jest.mock('../../runtime/appRuntimeStore', () => ({
  appRuntimeStore: mockAppRuntimeStore,
}));

const mockUseNativeSessionStore = jest.fn();
jest.mock('../../runtime/nativeSessionStore', () => ({
  useNativeSessionStore: () => mockUseNativeSessionStore(),
}));

import { AudioManager } from '../../utils/audio';
import { useNativeSessionBridge } from '../useNativeSessionBridge';
import type { NativeSessionSnapshot } from '../../runtime/nativeSessionTypes';
import { DEFAULT_NATIVE_SESSION } from '../../runtime/nativeSessionTypes';

function makeSession(overrides: Partial<NativeSessionSnapshot> = {}): NativeSessionSnapshot {
  return { ...DEFAULT_NATIVE_SESSION, ...overrides };
}

beforeEach(() => {
  mockGetPreference.mockReset();
  mockApplyTheme.mockReset();
  mockAppRuntimeStore.setAppState.mockReset();
  mockAppRuntimeStore.setError.mockReset();
  mockAppRuntimeStore.setTheme.mockReset();
  mockAppRuntimeStore.setSoundEnabled.mockReset();
  mockGetPreference.mockResolvedValue(null);
  (AudioManager as any).enabled = false;
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('useNativeSessionBridge', () => {
  it('returns current session snapshot', () => {
    const session = makeSession({ received: true, phase: 'wallet_ready' });
    mockUseNativeSessionStore.mockReturnValue(session);

    const { result } = renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy', 'pocket'], setThemeIndex: jest.fn() })
    );

    expect(result.current).toEqual(session);
  });

  it('maps session.phase to appState when received', () => {
    const session = makeSession({ received: true, phase: 'wallet_ready' });
    mockUseNativeSessionStore.mockReturnValue(session);

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy'], setThemeIndex: jest.fn() })
    );

    expect(mockAppRuntimeStore.setAppState).toHaveBeenCalledWith('wallet_ready');
  });

  it('maps appState to "loading" when session not received', () => {
    const session = makeSession({ received: false });
    mockUseNativeSessionStore.mockReturnValue(session);

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy'], setThemeIndex: jest.fn() })
    );

    expect(mockAppRuntimeStore.setAppState).toHaveBeenCalledWith('loading');
  });

  it('sets fatal_error from session', () => {
    const session = makeSession({ received: true, phase: 'error', fatal_error: 'crash' });
    mockUseNativeSessionStore.mockReturnValue(session);

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy'], setThemeIndex: jest.fn() })
    );

    expect(mockAppRuntimeStore.setError).toHaveBeenCalledWith('crash');
  });

  it('applies default theme when identity not ready', async () => {
    const session = makeSession({ received: true, identity_status: 'missing' });
    mockUseNativeSessionStore.mockReturnValue(session);
    const setThemeIndex = jest.fn();

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy', 'pocket'], setThemeIndex })
    );

    await act(async () => {});

    expect(mockApplyTheme).toHaveBeenCalledWith('stateboy');
    expect(mockAppRuntimeStore.setTheme).toHaveBeenCalledWith('stateboy');
    expect(setThemeIndex).toHaveBeenCalledWith(0);
    expect((AudioManager as any).enabled).toBe(true);
  });

  it('loads saved theme when identity is ready', async () => {
    mockGetPreference.mockImplementation(async (key: string) => {
      if (key === 'ui_theme') return 'pocket';
      if (key === 'sfx_enabled') return 'true';
      return null;
    });
    const session = makeSession({ received: true, identity_status: 'ready' });
    mockUseNativeSessionStore.mockReturnValue(session);
    const setThemeIndex = jest.fn();

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy', 'pocket'], setThemeIndex })
    );

    await act(async () => {});

    expect(mockApplyTheme).toHaveBeenCalledWith('pocket');
    expect(mockAppRuntimeStore.setTheme).toHaveBeenCalledWith('pocket');
    expect(setThemeIndex).toHaveBeenCalledWith(1);
  });

  it('disables sound when sfx_enabled is "false"', async () => {
    mockGetPreference.mockImplementation(async (key: string) => {
      if (key === 'sfx_enabled') return 'false';
      return null;
    });
    const session = makeSession({ received: true, identity_status: 'ready' });
    mockUseNativeSessionStore.mockReturnValue(session);

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy'], setThemeIndex: jest.fn() })
    );

    await act(async () => {});

    expect(mockAppRuntimeStore.setSoundEnabled).toHaveBeenCalledWith(false);
    expect((AudioManager as any).enabled).toBe(false);
  });

  it('falls back to stateboy when saved theme is not in themes list', async () => {
    mockGetPreference.mockImplementation(async (key: string) => {
      if (key === 'ui_theme') return 'nonexistent_theme';
      return null;
    });
    const session = makeSession({ received: true, identity_status: 'ready' });
    mockUseNativeSessionStore.mockReturnValue(session);

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy', 'pocket'], setThemeIndex: jest.fn() })
    );

    await act(async () => {});

    expect(mockApplyTheme).toHaveBeenCalledWith('stateboy');
  });

  it('does not apply UI prefs when session.received is false', async () => {
    const session = makeSession({ received: false });
    mockUseNativeSessionStore.mockReturnValue(session);

    renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy'], setThemeIndex: jest.fn() })
    );

    await act(async () => {});

    expect(mockApplyTheme).not.toHaveBeenCalled();
  });

  it('cancels stale async pref loads on re-render', async () => {
    const session1 = makeSession({ received: true, identity_status: 'ready' });
    mockUseNativeSessionStore.mockReturnValue(session1);

    let resolvePref!: (v: string) => void;
    mockGetPreference.mockReturnValue(new Promise<string>(r => { resolvePref = r; }));

    const setThemeIndex = jest.fn();
    const { unmount } = renderHook(() =>
      useNativeSessionBridge({ themes: ['stateboy', 'pocket'], setThemeIndex })
    );

    unmount();
    resolvePref('pocket');
    await act(async () => {});

    // After unmount, setThemeIndex should not be called with the resolved value
    expect(setThemeIndex).not.toHaveBeenCalledWith(1);
  });
});
