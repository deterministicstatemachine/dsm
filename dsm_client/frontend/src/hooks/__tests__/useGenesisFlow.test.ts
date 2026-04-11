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
    setError: jest.fn(),
    setSecuringProgress: jest.fn(),
  };
}

describe('useGenesisFlow (UI-only)', () => {
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

  it('error envelope case surfaces message via setError (no phase writes)', async () => {
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
    // Phase transitions are owned by Rust now — the hook must not touch appState.
    // The new Args type doesn't expose setAppState, so we can't assert "not called";
    // we instead assert the surface: only setError + setSecuringProgress are used.
  });

  it('empty/too-small envelope surfaces message via setError', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockResolvedValue(new Uint8Array(5));

    const { result } = renderHook(() => useGenesisFlow(args));

    await act(async () => {
      await result.current.handleGenerateGenesis();
    });

    expect(args.setError).toHaveBeenCalledWith('Genesis envelope is empty or too small');
  });

  it('invalid envelope case surfaces message via setError', async () => {
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
  });

  it('genesis.securing-device event only resets progress (no phase write)', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    // Phase transition is driven by Rust via session.state. The hook must NOT
    // emit a setError for the 'securing-device' lifecycle event.
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('genesis.securing-device-progress event updates progress bar', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device-progress', new Uint8Array([75]));
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(75);
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('genesis.securing-device-complete event sets progress to 100', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device-complete');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(100);
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('genesis.securing-device-aborted event only resets progress, does not call setError', () => {
    // REGRESSION GUARD: pre-Task-7 the hook called setError + setAppState on
    // this event. Now Rust owns the phase transition via markGenesisSecuring
    // (ABORTED) which triggers a publishCurrentSessionState on the Kotlin side.
    // The TS hook must stay out of the phase transition path.
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device-aborted');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('does not register a visibilitychange listener (Rust owns abort on backgrounding)', () => {
    // REGRESSION GUARD: the pre-Task-7 hook attached a document-level
    // visibilitychange listener that unilaterally flipped appState.
    // NativeBoundaryBridge + handleHostPauseDuringGenesis now own this path
    // via the ABORTED ingress marker. The TS hook must not touch document.
    const addSpy = jest.spyOn(document, 'addEventListener');
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    const visibilityCalls = addSpy.mock.calls.filter(
      (call) => call[0] === 'visibilitychange',
    );
    expect(visibilityCalls).toHaveLength(0);

    addSpy.mockRestore();
  });

  it('cleans up DSM event listeners on unmount', () => {
    const args = makeHookArgs();
    const { unmount } = renderHook(() => useGenesisFlow(args));

    expect(dsmEventListeners.length).toBeGreaterThan(0);
    unmount();
    expect(dsmEventListeners.length).toBe(0);
  });
});
