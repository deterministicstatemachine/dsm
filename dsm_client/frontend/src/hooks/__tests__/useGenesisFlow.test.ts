/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook, act } from '@testing-library/react';

jest.mock('../../utils/logger', () => ({
  __esModule: true,
  default: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock('../../dsm/decoding', () => ({
  decodeFramedEnvelopeV3: jest.fn(),
}));

type DsmEventHandler = (evt: { topic: string; payload: Uint8Array }) => void;
let dsmEventListeners: DsmEventHandler[] = [];
const mockCreateGenesisViaRouter = jest.fn();

jest.mock('../../dsm/WebViewBridge', () => ({
  addDsmEventListener: jest.fn((handler: DsmEventHandler) => {
    dsmEventListeners.push(handler);
    return () => {
      dsmEventListeners = dsmEventListeners.filter(h => h !== handler);
    };
  }),
  createGenesisViaRouter: (...args: any[]) => mockCreateGenesisViaRouter(...args),
}));

import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';
import { useGenesisFlow } from '../useGenesisFlow';

const mockedDecode = decodeFramedEnvelopeV3 as jest.Mock;

function emitDsmEvent(topic: string, payload: Uint8Array = new Uint8Array(0)) {
  dsmEventListeners.forEach(h => h({ topic, payload }));
}

beforeEach(() => {
  dsmEventListeners = [];
  mockCreateGenesisViaRouter.mockReset();
  mockedDecode.mockReset();
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});

  // Provide crypto.getRandomValues for genesis entropy
  if (!globalThis.crypto) {
    (globalThis as any).crypto = {};
  }
  (globalThis.crypto as any).getRandomValues = (buf: Uint8Array) => {
    for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
    return buf;
  };
});

afterEach(() => {
  jest.restoreAllMocks();
});

function makeHookArgs() {
  return {
    appState: 'needs_genesis' as any,
    setAppState: jest.fn(),
    setError: jest.fn(),
    setSecuringProgress: jest.fn(),
  };
}

describe('useGenesisFlow', () => {
  it('returns handleGenerateGenesis callback', () => {
    const args = makeHookArgs();
    const { result } = renderHook(() => useGenesisFlow(args));
    expect(typeof result.current.handleGenerateGenesis).toBe('function');
  });

  it('successful genesis flow decodes envelope and completes', async () => {
    const args = makeHookArgs();
    const fakeEnvelope = new Uint8Array(64).fill(1);
    mockCreateGenesisViaRouter.mockResolvedValue(fakeEnvelope);
    mockedDecode.mockReturnValue({
      payload: {
        case: 'genesisCreatedResponse',
        value: { ok: true },
      },
    });

    const { result } = renderHook(() => useGenesisFlow(args));

    await act(async () => {
      await result.current.handleGenerateGenesis();
    });

    expect(mockCreateGenesisViaRouter).toHaveBeenCalledWith(
      expect.any(String),
      'mainnet',
      expect.any(Uint8Array),
    );
    expect(mockedDecode).toHaveBeenCalledWith(fakeEnvelope);
    // No error set on success
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('prevents concurrent genesis calls', async () => {
    const args = makeHookArgs();
    let resolveGenesis!: (v: Uint8Array) => void;
    mockCreateGenesisViaRouter.mockReturnValue(new Promise<Uint8Array>(r => { resolveGenesis = r; }));

    const { result } = renderHook(() => useGenesisFlow(args));

    // Start first call
    let firstPromise: Promise<void>;
    act(() => {
      firstPromise = result.current.handleGenerateGenesis();
    });

    // Second call while first is in flight — should be a no-op
    await act(async () => {
      await result.current.handleGenerateGenesis();
    });

    expect(mockCreateGenesisViaRouter).toHaveBeenCalledTimes(1);

    // Clean up
    const fakeEnvelope = new Uint8Array(64).fill(1);
    mockedDecode.mockReturnValue({ payload: { case: 'genesisCreatedResponse', value: {} } });
    resolveGenesis(fakeEnvelope);
    await act(async () => { await firstPromise!; });
  });

  it('handles error envelope case', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockResolvedValue(new Uint8Array(64).fill(1));
    mockedDecode.mockReturnValue({
      payload: { case: 'error', value: { message: 'Entropy invalid' } },
    });

    const { result } = renderHook(() => useGenesisFlow(args));

    await act(async () => {
      await result.current.handleGenerateGenesis();
    });

    expect(args.setError).toHaveBeenCalledWith('Genesis creation failed: Entropy invalid');
    expect(args.setAppState).toHaveBeenCalledWith('error');
  });

  it('handles empty/too-small envelope', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockResolvedValue(new Uint8Array(5));

    const { result } = renderHook(() => useGenesisFlow(args));

    await act(async () => {
      await result.current.handleGenerateGenesis();
    });

    expect(args.setError).toHaveBeenCalledWith('Genesis envelope is empty or too small');
    expect(args.setAppState).toHaveBeenCalledWith('error');
  });

  it('handles invalid envelope case', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockResolvedValue(new Uint8Array(64).fill(1));
    mockedDecode.mockReturnValue({
      payload: { case: 'somethingElse', value: {} },
    });

    const { result } = renderHook(() => useGenesisFlow(args));

    await act(async () => {
      await result.current.handleGenerateGenesis();
    });

    expect(args.setError).toHaveBeenCalledWith(expect.stringContaining('Invalid GenesisCreated envelope'));
    expect(args.setAppState).toHaveBeenCalledWith('error');
  });

  it('aborts on visibility change during securing_device', () => {
    const args = { ...makeHookArgs(), appState: 'securing_device' as any };
    renderHook(() => useGenesisFlow(args));

    // Simulate tab hidden
    Object.defineProperty(document, 'visibilityState', { value: 'hidden', writable: true });
    document.dispatchEvent(new Event('visibilitychange'));

    expect(args.setError).toHaveBeenCalledWith(expect.stringContaining('Do not leave the screen'));
    expect(args.setAppState).toHaveBeenCalledWith('needs_genesis');
    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);

    // Restore
    Object.defineProperty(document, 'visibilityState', { value: 'visible', writable: true });
  });

  it('does not listen for visibility change when not securing_device', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    Object.defineProperty(document, 'visibilityState', { value: 'hidden', writable: true });
    document.dispatchEvent(new Event('visibilitychange'));

    expect(args.setError).not.toHaveBeenCalled();
    Object.defineProperty(document, 'visibilityState', { value: 'visible', writable: true });
  });

  it('responds to genesis.securing-device DSM event', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    expect(args.setAppState).toHaveBeenCalledWith('securing_device');
  });

  it('responds to genesis.securing-device-progress DSM event', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device-progress', new Uint8Array([75]));
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(75);
  });

  it('responds to genesis.securing-device-complete DSM event', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device-complete');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(100);
  });

  it('responds to genesis.securing-device-aborted DSM event', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device-aborted');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    expect(args.setError).toHaveBeenCalledWith(expect.stringContaining('Do not leave the screen'));
    expect(args.setAppState).toHaveBeenCalledWith('needs_genesis');
  });

  it('cleans up DSM event listeners on unmount', () => {
    const args = makeHookArgs();
    const { unmount } = renderHook(() => useGenesisFlow(args));

    expect(dsmEventListeners.length).toBeGreaterThan(0);
    unmount();
    expect(dsmEventListeners.length).toBe(0);
  });

  it('error with "Do not leave the screen" resets to needs_genesis', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockRejectedValue(
      new Error('Do not leave the screen until finished')
    );

    const { result } = renderHook(() => useGenesisFlow(args));

    await act(async () => {
      await result.current.handleGenerateGenesis();
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    expect(args.setAppState).toHaveBeenCalledWith('needs_genesis');
  });
});
