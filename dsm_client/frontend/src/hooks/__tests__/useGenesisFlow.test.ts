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
const mockGenerateMnemonic = jest.fn();
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

jest.mock('../../dsm/WebViewBridge', () => ({
  addDsmEventListener: jest.fn((handler: DsmEventHandler) => {
    dsmEventListeners.push(handler);
    return () => {
      dsmEventListeners = dsmEventListeners.filter(h => h !== handler);
    };
  }),
  createGenesisViaRouter: (...args: any[]) => mockCreateGenesisViaRouter(...args),
  generateMnemonic: (...args: any[]) => mockGenerateMnemonic(...args),
}));

import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';
import { useGenesisFlow } from '../useGenesisFlow';
import { recoveryPhraseStore } from '../../runtime/recoveryPhraseStore';
import { cryptoDraw, phraseWords } from '../../onboarding/recoveryPhrase';

const mockedDecode = decodeFramedEnvelopeV3 as jest.Mock;

function emitDsmEvent(topic: string, payload: Uint8Array = new Uint8Array(0)) {
  dsmEventListeners.forEach(h => h({ topic, payload }));
}

beforeEach(() => {
  dsmEventListeners = [];
  recoveryPhraseStore.clear();
  mockCreateGenesisViaRouter.mockReset();
  mockGenerateMnemonic.mockReset();
  mockGenerateMnemonic.mockResolvedValue(TEST_MNEMONIC);
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

function makePendingGenesis() {
  return new Promise<Uint8Array>(() => {});
}

type Flow = { current: ReturnType<typeof useGenesisFlow> };

/** INITIALIZE: the phrase is generated and put on the screen. */
async function initialize(result: Flow) {
  await act(async () => {
    await result.current.handleGenerateGenesis();
  });
}

/**
 * INITIALIZE, the phrase written down, and every checked word picked back
 * out. The last pick starts the wallet's creation; it is returned unawaited,
 * so a test can hold genesis open.
 */
async function initializeAndCheck(result: Flow) {
  await initialize(result);
  act(() => {
    recoveryPhraseStore.startChecks(cryptoDraw);
  });
  const checks = recoveryPhraseStore.getSnapshot().checks;
  for (const check of checks.slice(0, -1)) {
    await act(async () => {
      await result.current.answerPhraseCheck(check.answer);
    });
  }
  let creation: Promise<void> = Promise.resolve();
  act(() => {
    creation = result.current.answerPhraseCheck(checks[checks.length - 1].answer);
  });
  return { creation };
}

describe('useGenesisFlow', () => {
  it('returns the genesis and phrase callbacks', () => {
    const args = makeHookArgs();
    const { result } = renderHook(() => useGenesisFlow(args));
    expect(typeof result.current.handleGenerateGenesis).toBe('function');
    expect(typeof result.current.cancelPhraseBackup).toBe('function');
    expect(typeof result.current.answerPhraseCheck).toBe('function');
  });

  it('INITIALIZE puts the recovery phrase on the screen and creates no wallet', async () => {
    const args = makeHookArgs();
    const { result } = renderHook(() => useGenesisFlow(args));

    await initialize(result);

    expect(args.setAppState).toHaveBeenCalledTimes(1);
    expect(args.setAppState).toHaveBeenCalledWith('backup_phrase');
    // Creation forgets the phrase whatever its outcome: it is still held, unchecked.
    expect(recoveryPhraseStore.getSnapshot().words).toEqual(phraseWords(TEST_MNEMONIC));
    expect(recoveryPhraseStore.getSnapshot().status).toBe('reading');
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('creates the wallet from the phrase once every checked word matches', async () => {
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
    const { creation } = await initializeAndCheck(result);
    await act(async () => {
      await creation;
    });

    // The network is the SDK's to choose; the frontend names none, and no locale.
    expect(mockCreateGenesisViaRouter).toHaveBeenCalledWith(TEST_MNEMONIC);
    expect(mockedDecode).toHaveBeenCalledWith(fakeEnvelope);
    // No error set on success
    expect(args.setError).not.toHaveBeenCalled();
    // The phrase is forgotten once the wallet is created from it.
    expect(recoveryPhraseStore.getSnapshot().words).toEqual([]);
  });

  it('creates nothing until the last checked word is picked', async () => {
    const args = makeHookArgs();
    const { result } = renderHook(() => useGenesisFlow(args));

    await initialize(result);
    act(() => {
      recoveryPhraseStore.startChecks(cryptoDraw);
    });
    const checks = recoveryPhraseStore.getSnapshot().checks;
    for (const check of checks.slice(0, -1)) {
      await act(async () => {
        await result.current.answerPhraseCheck(check.answer);
      });
    }

    expect(recoveryPhraseStore.getSnapshot().status).toBe('checking');
    expect(recoveryPhraseStore.getSnapshot().words).toEqual(phraseWords(TEST_MNEMONIC));
    expect(args.setAppState).toHaveBeenCalledTimes(1);
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('a word that does not match creates no wallet', async () => {
    const args = makeHookArgs();
    const { result } = renderHook(() => useGenesisFlow(args));

    await initialize(result);
    act(() => {
      recoveryPhraseStore.startChecks(cryptoDraw);
    });
    const [first] = recoveryPhraseStore.getSnapshot().checks;
    const wrong = first.choices.find((word) => word !== first.answer);
    expect(wrong).toBeDefined();

    await act(async () => {
      await result.current.answerPhraseCheck(wrong as string);
    });
    expect(recoveryPhraseStore.getSnapshot().status).toBe('missed');

    // A miss is not a pass: picking every right word after it does not create the wallet.
    for (const check of recoveryPhraseStore.getSnapshot().checks) {
      await act(async () => {
        await result.current.answerPhraseCheck(check.answer);
      });
    }
    expect(recoveryPhraseStore.getSnapshot().status).toBe('missed');
    expect(recoveryPhraseStore.getSnapshot().words).toEqual(phraseWords(TEST_MNEMONIC));
    expect(args.setAppState).toHaveBeenCalledTimes(1);
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('cancel forgets the phrase and returns to setup', async () => {
    const args = makeHookArgs();
    const { result } = renderHook(() => useGenesisFlow(args));

    await initialize(result);
    act(() => {
      result.current.cancelPhraseBackup();
    });

    expect(args.setAppState).toHaveBeenLastCalledWith('needs_genesis');
    expect(recoveryPhraseStore.getSnapshot().words).toEqual([]);
    expect(args.setError).not.toHaveBeenCalled();
  });

  it('generates one phrase for concurrent INITIALIZE presses', async () => {
    const args = makeHookArgs();
    const { result } = renderHook(() => useGenesisFlow(args));

    await act(async () => {
      await Promise.all([result.current.handleGenerateGenesis(), result.current.handleGenerateGenesis()]);
    });

    expect(args.setAppState).toHaveBeenCalledTimes(1);
    expect(args.setAppState).toHaveBeenCalledWith('backup_phrase');
  });

  it('prevents concurrent genesis calls', async () => {
    const args = makeHookArgs();
    let resolveGenesis!: (v: Uint8Array) => void;
    mockCreateGenesisViaRouter.mockReturnValue(new Promise<Uint8Array>(r => { resolveGenesis = r; }));

    const { result } = renderHook(() => useGenesisFlow(args));
    const { creation } = await initializeAndCheck(result);

    // INITIALIZE while the wallet is being created — should be a no-op
    await initialize(result);

    expect(mockCreateGenesisViaRouter).toHaveBeenCalledTimes(1);
    // No second phrase was begun over the one being created from.
    expect(recoveryPhraseStore.getSnapshot().status).toBe('complete');

    // Clean up
    const fakeEnvelope = new Uint8Array(64).fill(1);
    mockedDecode.mockReturnValue({ payload: { case: 'genesisCreatedResponse', value: {} } });
    resolveGenesis(fakeEnvelope);
    await act(async () => { await creation; });
  });

  it('handles error envelope case', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockResolvedValue(new Uint8Array(64).fill(1));
    mockedDecode.mockReturnValue({
      payload: { case: 'error', value: { message: 'Entropy invalid' } },
    });

    const { result } = renderHook(() => useGenesisFlow(args));
    const { creation } = await initializeAndCheck(result);
    await act(async () => {
      await creation;
    });

    expect(args.setError).toHaveBeenCalledWith('Genesis creation failed: Entropy invalid');
    expect(args.setAppState).toHaveBeenCalledWith('error');
    expect(recoveryPhraseStore.getSnapshot().words).toEqual([]);
  });

  it('handles empty/too-small envelope', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockResolvedValue(new Uint8Array(5));

    const { result } = renderHook(() => useGenesisFlow(args));
    const { creation } = await initializeAndCheck(result);
    await act(async () => {
      await creation;
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
    const { creation } = await initializeAndCheck(result);
    await act(async () => {
      await creation;
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

  it('responds to genesis.securing-device DSM event', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockReturnValue(makePendingGenesis());
    const { result } = renderHook(() => useGenesisFlow(args));
    await initializeAndCheck(result);

    act(() => {
      emitDsmEvent('genesis.securing-device');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    expect(args.setAppState).toHaveBeenCalledWith('securing_device');
  });

  it('responds to genesis.securing-device-progress DSM event', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockReturnValue(makePendingGenesis());
    const { result } = renderHook(() => useGenesisFlow(args));
    await initializeAndCheck(result);

    act(() => {
      emitDsmEvent('genesis.securing-device-progress', new Uint8Array([75]));
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(75);
  });

  it('responds to genesis.securing-device-complete DSM event', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockReturnValue(makePendingGenesis());
    const { result } = renderHook(() => useGenesisFlow(args));
    await initializeAndCheck(result);

    act(() => {
      emitDsmEvent('genesis.securing-device-complete');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(100);
  });

  it('responds to genesis.securing-device-aborted DSM event', async () => {
    const args = makeHookArgs();
    mockCreateGenesisViaRouter.mockReturnValue(makePendingGenesis());
    const { result } = renderHook(() => useGenesisFlow(args));
    await initializeAndCheck(result);

    act(() => {
      emitDsmEvent('genesis.securing-device-aborted');
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    expect(args.setError).toHaveBeenCalledWith(expect.stringContaining('Do not leave the screen'));
    expect(args.setAppState).toHaveBeenCalledWith('needs_genesis');
  });

  it('ignores stale genesis lifecycle events when no genesis is running', () => {
    const args = makeHookArgs();
    renderHook(() => useGenesisFlow(args));

    act(() => {
      emitDsmEvent('genesis.securing-device');
      emitDsmEvent('genesis.securing-device-progress', new Uint8Array([75]));
      emitDsmEvent('genesis.securing-device-complete');
      emitDsmEvent('genesis.securing-device-aborted');
    });

    expect(args.setSecuringProgress).not.toHaveBeenCalled();
    expect(args.setError).not.toHaveBeenCalled();
    expect(args.setAppState).not.toHaveBeenCalled();
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
    const { creation } = await initializeAndCheck(result);
    await act(async () => {
      await creation;
    });

    expect(args.setSecuringProgress).toHaveBeenCalledWith(0);
    expect(args.setAppState).toHaveBeenCalledWith('needs_genesis');
  });
});
