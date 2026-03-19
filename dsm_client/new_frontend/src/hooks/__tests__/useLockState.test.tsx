import React from 'react';
import { render, act } from '@testing-library/react';
import { useLockState } from '../useLockState';
import { LOCK_SETUP_COMPLETE_EVENT } from '../../services/lock/lockService';
import { lockSessionViaRouter, unlockSessionViaRouter } from '../../dsm/WebViewBridge';

jest.mock('../../dsm/WebViewBridge', () => ({
  lockSessionViaRouter: jest.fn().mockResolvedValue(undefined),
  unlockSessionViaRouter: jest.fn().mockResolvedValue(undefined),
}));

let hookResult: { lock: () => void; unlock: () => Promise<void> };

function Harness(props: { appState: string; setAppState: (s: string) => void }) {
  hookResult = useLockState(props);
  return null;
}

const mockedLockSessionViaRouter = lockSessionViaRouter as jest.MockedFunction<typeof lockSessionViaRouter>;
const mockedUnlockSessionViaRouter = unlockSessionViaRouter as jest.MockedFunction<typeof unlockSessionViaRouter>;

describe('useLockState', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  it('lock() calls lockSessionViaRouter when wallet_ready', () => {
    const setAppState = jest.fn();
    render(<Harness appState="wallet_ready" setAppState={setAppState} />);

    act(() => { hookResult.lock(); });

    expect(mockedLockSessionViaRouter).toHaveBeenCalledTimes(1);
  });

  it('lock() is a no-op when not wallet_ready', () => {
    const setAppState = jest.fn();
    render(<Harness appState="needs_genesis" setAppState={setAppState} />);

    act(() => { hookResult.lock(); });

    expect(mockedLockSessionViaRouter).not.toHaveBeenCalled();
  });

  it('unlock() calls unlockSessionViaRouter', async () => {
    const setAppState = jest.fn();
    render(<Harness appState="locked" setAppState={setAppState} />);

    await act(async () => { await hookResult.unlock(); });

    expect(mockedUnlockSessionViaRouter).toHaveBeenCalledTimes(1);
  });

  it('locks after LOCK_SETUP_COMPLETE_EVENT with delay', () => {
    jest.useFakeTimers();
    const setAppState = jest.fn();
    render(<Harness appState="wallet_ready" setAppState={setAppState} />);

    act(() => {
      window.dispatchEvent(new CustomEvent(LOCK_SETUP_COMPLETE_EVENT));
    });

    expect(mockedLockSessionViaRouter).not.toHaveBeenCalled();

    act(() => { jest.advanceTimersByTime(1300); });

    expect(mockedLockSessionViaRouter).toHaveBeenCalledTimes(1);
  });
});
