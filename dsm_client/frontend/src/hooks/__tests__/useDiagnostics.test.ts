/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook, act } from '@testing-library/react';

const mockGetPreference = jest.fn();
const mockSetPreference = jest.fn();
const mockGetIdentity = jest.fn();
jest.mock('../../services/dsmClient', () => ({
  dsmClient: {
    getPreference: (...args: any[]) => mockGetPreference(...args),
    setPreference: (...args: any[]) => mockSetPreference(...args),
    getIdentity: (...args: any[]) => mockGetIdentity(...args),
  },
}));

const bridgeHandlers = new Map<string, Set<Function>>();
jest.mock('../../bridge/bridgeEvents', () => ({
  bridgeEvents: {
    on: jest.fn((event: string, handler: Function) => {
      const set = bridgeHandlers.get(event) ?? new Set();
      set.add(handler);
      bridgeHandlers.set(event, set);
      return () => { set.delete(handler); };
    }),
    emit: jest.fn((event: string, payload: any) => {
      const set = bridgeHandlers.get(event);
      if (set) set.forEach(fn => fn(payload));
    }),
  },
}));

jest.mock('../../utils/githubIssue', () => ({
  BETA_BUG_TEMPLATE: 'bug-report-beta.yml',
  BETA_FEEDBACK_TEMPLATE: 'general-feedback-beta.yml',
  buildGitHubIssueUrl: jest.fn(() => 'https://github.com/test/issues/new'),
}));

jest.mock('../../runtime/nativeSessionStore', () => ({
  nativeSessionStore: {
    getSnapshot: jest.fn(() => ({ received: true, phase: 'wallet_ready' })),
  },
}));

const mockGetArchitectureInfo = jest.fn();
const mockGetDiagnosticsLog = jest.fn();
jest.mock('../../dsm/WebViewBridge', () => ({
  getArchitectureInfo: (...args: any[]) => mockGetArchitectureInfo(...args),
  getDiagnosticsLog: (...args: any[]) => mockGetDiagnosticsLog(...args),
}));

jest.mock('../../services/telemetry', () => ({
  sendDiagnostics: jest.fn(async () => {}),
}));

import { bridgeEvents } from '../../bridge/bridgeEvents';
import { useDiagnostics } from '../useDiagnostics';

const mockedBridgeEvents = bridgeEvents as any;

function emitBridge(event: string, payload: any) {
  const set = bridgeHandlers.get(event);
  if (set) set.forEach(fn => fn(payload));
}

beforeEach(() => {
  bridgeHandlers.clear();
  mockGetPreference.mockReset();
  mockSetPreference.mockReset();
  mockGetPreference.mockResolvedValue(null);
  mockSetPreference.mockResolvedValue(undefined);
  mockGetIdentity.mockReset();
  mockGetIdentity.mockResolvedValue({ deviceId: 'DEV', genesisHash: 'GEN' });
  mockGetArchitectureInfo.mockReset();
  mockGetArchitectureInfo.mockResolvedValue({
    status: 'COMPATIBLE',
    deviceArch: 'arm64',
    supportedAbis: 'arm64-v8a',
    message: 'OK',
    recommendation: '',
  });
  mockGetDiagnosticsLog.mockReset();
  mockGetDiagnosticsLog.mockResolvedValue(new Uint8Array(0));
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('useDiagnostics', () => {
  it('returns initial state', async () => {
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    expect(result.current.envConfigError).toBeNull();
    expect(result.current.showDiagnostics).toBe(false);
    expect(result.current.diagLoading).toBe(false);
    expect(result.current.diagnostics).toBeNull();
    expect(result.current.telemetryConsent).toBe(false);
    expect(result.current.lastBridgeError).toBeNull();
  });

  it('loads telemetry consent from preferences on mount', async () => {
    mockGetPreference.mockResolvedValueOnce('1');
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    expect(mockGetPreference).toHaveBeenCalledWith('diagnostics_consent');
    expect(result.current.telemetryConsent).toBe(true);
  });

  it('treats "true" as consent enabled', async () => {
    mockGetPreference.mockResolvedValueOnce('true');
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    expect(result.current.telemetryConsent).toBe(true);
  });

  it('defaults consent to false on preference error', async () => {
    mockGetPreference.mockRejectedValueOnce(new Error('fail'));
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    expect(result.current.telemetryConsent).toBe(false);
  });

  it('handles env.config.error events', async () => {
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    act(() => {
      emitBridge('env.config.error', { message: 'Missing config', type: 'MISSING_FILE', help: 'reinstall' });
    });

    expect(result.current.envConfigError).toBe('Missing config');
  });

  it('handles env.config.error with missing message', async () => {
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    act(() => {
      emitBridge('env.config.error', {});
    });

    expect(result.current.envConfigError).toBe('Environment configuration error');
  });

  it('handles bridge.error events', async () => {
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    act(() => {
      emitBridge('bridge.error', { code: 42, message: 'decode fail', debugB32: 'ABC123' });
    });

    expect(result.current.lastBridgeError).toEqual({
      code: 42,
      message: 'decode fail',
      debugB32: 'ABC123',
    });
  });

  it('updates telemetry consent and persists preference', async () => {
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      await result.current.setTelemetryConsent(true);
    });

    expect(result.current.telemetryConsent).toBe(true);
    expect(mockSetPreference).toHaveBeenCalledWith('diagnostics_consent', '1');
  });

  it('notifies error when consent save fails', async () => {
    mockSetPreference.mockRejectedValueOnce(new Error('save fail'));
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      await result.current.setTelemetryConsent(false);
    });

    expect(notifyToast).toHaveBeenCalledWith('error', 'Failed to save diagnostics consent');
  });

  it('gatherDiagnostics populates diagnostics string', async () => {
    const notifyToast = jest.fn();
    mockGetPreference.mockResolvedValue('');
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      await result.current.gatherDiagnostics();
    });

    expect(result.current.diagLoading).toBe(false);
    expect(result.current.showDiagnostics).toBe(true);
    expect(result.current.diagnostics).toContain('DSM diagnostics');
    expect(result.current.diagnostics).toContain('session=wallet_ready');
    expect(result.current.diagnostics).toContain('identity=device DEV genesis GEN');
    expect(result.current.diagnostics).toContain('arch=COMPATIBLE device=arm64 abis=arm64-v8a message=OK');
  });

  // The identity lines come from Rust's transport headers, never from the
  // preference copies Kotlin keeps for its own startup.
  it('reads the identity from Rust, not from preferences', async () => {
    const { result } = renderHook(() => useDiagnostics(jest.fn()));
    await act(async () => {});
    await act(async () => { await result.current.gatherDiagnostics(); });

    expect(mockGetIdentity).toHaveBeenCalled();
    for (const call of mockGetPreference.mock.calls) {
      expect(['device_id_bytes', 'genesis_hash_bytes', 'DSM_ENV_CONFIG_PATH']).not.toContain(call[0]);
    }
  });

  // A failed check is reported as its failure; it used to read archStatus=UNKNOWN.
  it('reports a failed architecture check as its failure, not as a status', async () => {
    mockGetArchitectureInfo.mockRejectedValueOnce(new Error('getArchitectureInfo answered no bytes'));
    const { result } = renderHook(() => useDiagnostics(jest.fn()));
    await act(async () => {});
    await act(async () => { await result.current.gatherDiagnostics(); });

    expect(result.current.diagnostics).toContain('arch=not measured: getArchitectureInfo answered no bytes');
    expect(result.current.diagnostics).not.toContain('UNKNOWN');
  });

  it('a missing identity is reported as missing, not as empty fields', async () => {
    mockGetIdentity.mockResolvedValueOnce(null);
    const { result } = renderHook(() => useDiagnostics(jest.fn()));
    await act(async () => {});
    await act(async () => { await result.current.gatherDiagnostics(); });

    expect(result.current.diagnostics).toContain('identity=none (getIdentity answered null)');
  });

  // The bundle says why the native log was not read; it used to say "No
  // native bridge log captured" for a failure and for an empty log alike.
  it('the bundle names why the bridge log was not read', async () => {
    mockGetDiagnosticsLog.mockRejectedValueOnce(new Error('Bridge not initialized'));
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true, writable: true });
    const { result } = renderHook(() => useDiagnostics(jest.fn()));
    await act(async () => {});
    await act(async () => { await result.current.gatherDiagnostics(); });
    await act(async () => { await result.current.copyDiagnostics(); });

    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText.mock.calls[0][0]).toContain('--- Native Bridge Log ---\nnot read: Bridge not initialized');
  });

  it('sendDiagnosticsTelemetry calls telemetry service', async () => {
    const telemetryMod = await import('../../services/telemetry');
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    // First gather so diagnostics is not null
    await act(async () => {
      await result.current.gatherDiagnostics();
    });

    await act(async () => {
      await result.current.sendDiagnosticsTelemetry();
    });

    expect(telemetryMod.sendDiagnostics).toHaveBeenCalled();
    expect(notifyToast).toHaveBeenCalledWith('success', 'Diagnostics saved to local log');
  });

  it('sendDiagnosticsTelemetry does nothing when diagnostics is null', async () => {
    const telemetryMod = await import('../../services/telemetry');
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      await result.current.sendDiagnosticsTelemetry();
    });

    expect(telemetryMod.sendDiagnostics).not.toHaveBeenCalled();
  });

  it('copyDiagnostics writes to clipboard', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      await result.current.gatherDiagnostics();
    });

    await act(async () => {
      await result.current.copyDiagnostics();
    });

    expect(writeText).toHaveBeenCalled();
    expect(notifyToast).toHaveBeenCalledWith('success', 'Diagnostics copied to clipboard');
  });

  it('copyDiagnostics does nothing when diagnostics is null', async () => {
    const writeText = jest.fn();
    Object.assign(navigator, { clipboard: { writeText } });

    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      await result.current.copyDiagnostics();
    });

    expect(writeText).not.toHaveBeenCalled();
  });

  it('downloadDiagnostics creates and clicks a link', async () => {
    const notifyToast = jest.fn();
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      await result.current.gatherDiagnostics();
    });

    const mockClick = jest.fn();
    const mockRemove = jest.fn();
    const mockCreateElement = jest.spyOn(document, 'createElement').mockReturnValue({
      href: '',
      download: '',
      click: mockClick,
      remove: mockRemove,
    } as any);
    jest.spyOn(document.body, 'appendChild').mockImplementation((n) => n);
    const mockCreateObjectURL = jest.fn(() => 'blob:test');
    const mockRevokeObjectURL = jest.fn();
    global.URL.createObjectURL = mockCreateObjectURL;
    global.URL.revokeObjectURL = mockRevokeObjectURL;

    await act(async () => {
      result.current.downloadDiagnostics();
      await new Promise(r => setTimeout(r, 10));
    });

    expect(mockClick).toHaveBeenCalled();
    expect(mockRemove).toHaveBeenCalled();
    expect(mockRevokeObjectURL).toHaveBeenCalled();

    mockCreateElement.mockRestore();
  });

  it('responds to dsm-open-diagnostics custom event', async () => {
    const notifyToast = jest.fn();
    mockGetPreference.mockResolvedValue('');
    const { result } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    await act(async () => {
      window.dispatchEvent(new CustomEvent('dsm-open-diagnostics', { detail: { autoGather: true } }));
      await new Promise(r => setTimeout(r, 10));
    });

    expect(result.current.showDiagnostics).toBe(true);
  });

  it('unsubscribes bridge events on unmount', async () => {
    const notifyToast = jest.fn();
    const { unmount } = renderHook(() => useDiagnostics(notifyToast));

    await act(async () => {});

    const envHandlers = bridgeHandlers.get('env.config.error');
    const bridgeErrHandlers = bridgeHandlers.get('bridge.error');

    unmount();

    expect(envHandlers?.size ?? 0).toBe(0);
    expect(bridgeErrHandlers?.size ?? 0).toBe(0);
  });

  it('cancelled flag prevents stale consent updates', async () => {
    let resolvePreference!: (v: string) => void;
    mockGetPreference.mockReturnValueOnce(new Promise<string>(r => { resolvePreference = r; }));

    const notifyToast = jest.fn();
    const { result, unmount } = renderHook(() => useDiagnostics(notifyToast));

    unmount();
    resolvePreference('1');
    await act(async () => {});

    // After unmount, consent should remain false (cancelled=true prevents setState)
    expect(result.current.telemetryConsent).toBe(false);
  });
});
