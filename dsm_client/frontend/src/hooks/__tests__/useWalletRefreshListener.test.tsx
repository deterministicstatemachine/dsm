/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, act } from '@testing-library/react';

jest.mock('../../bridge/bridgeEvents', () => {
  const handlers = new Map<string, Set<Function>>();
  return {
    bridgeEvents: {
      on: jest.fn((event: string, handler: Function) => {
        const set = handlers.get(event) ?? new Set();
        set.add(handler);
        handlers.set(event, set);
        return () => { set.delete(handler); };
      }),
      emit: jest.fn((event: string, payload: any) => {
        const set = handlers.get(event);
        if (set) set.forEach(fn => fn(payload));
      }),
      _handlers: handlers,
    },
  };
});

import { bridgeEvents } from '../../bridge/bridgeEvents';
import { useWalletRefreshListener } from '../useWalletRefreshListener';

const mockedBridgeEvents = bridgeEvents as any;

let rafCallbacks: Array<(ts: number) => void> = [];
let rafId = 0;

beforeEach(() => {
  rafCallbacks = [];
  rafId = 0;
  (globalThis as any).requestAnimationFrame = (cb: (ts: number) => void) => {
    rafId++;
    rafCallbacks.push(cb);
    return rafId;
  };
  (globalThis as any).cancelAnimationFrame = jest.fn();
  mockedBridgeEvents._handlers.clear();
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
});

function flushRaf() {
  const batch = rafCallbacks.slice();
  rafCallbacks = [];
  batch.forEach(cb => cb(performance.now()));
}

function Harness({ refresh, deps }: { refresh: () => Promise<void> | void; deps?: unknown[] }) {
  useWalletRefreshListener(refresh, deps);
  return null;
}

describe('useWalletRefreshListener', () => {
  it('subscribes to wallet.refresh on mount', () => {
    const refresh = jest.fn().mockResolvedValue(undefined);
    render(<Harness refresh={refresh} />);
    expect(mockedBridgeEvents.on).toHaveBeenCalledWith('wallet.refresh', expect.any(Function));
  });

  it('unsubscribes on unmount', () => {
    const refresh = jest.fn().mockResolvedValue(undefined);
    const { unmount } = render(<Harness refresh={refresh} />);
    unmount();
    // After unmount, emitting should not schedule new refreshes
    mockedBridgeEvents.emit('wallet.refresh', { source: 'test' });
    flushRaf();
    expect(refresh).not.toHaveBeenCalled();
  });

  it('calls refresh on wallet.refresh event after RAF', async () => {
    const refresh = jest.fn().mockResolvedValue(undefined);
    render(<Harness refresh={refresh} />);

    act(() => { mockedBridgeEvents.emit('wallet.refresh', { source: 'test' }); });
    expect(refresh).not.toHaveBeenCalled();

    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('coalesces rapid events into a single RAF callback', async () => {
    const refresh = jest.fn().mockResolvedValue(undefined);
    render(<Harness refresh={refresh} />);

    act(() => {
      mockedBridgeEvents.emit('wallet.refresh', { source: 'ble1' });
      mockedBridgeEvents.emit('wallet.refresh', { source: 'ble2' });
      mockedBridgeEvents.emit('wallet.refresh', { source: 'ble3' });
    });

    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  // The old "cooldown" counted dropped events, not frames: after a reload the
  // next 119 events from a low-priority source were discarded. Every event is
  // followed by a reload that started after it, whatever its source.
  it('an event after a completed refresh runs another: nothing is dropped', async () => {
    const refresh = jest.fn().mockResolvedValue(undefined);
    render(<Harness refresh={refresh} />);

    for (const source of ['inbox.sync', 'storage.sync', 'sofi']) {
      act(() => { mockedBridgeEvents.emit('wallet.refresh', { source }); });
      await act(async () => { flushRaf(); });
    }
    expect(refresh).toHaveBeenCalledTimes(3);
  });

  it('events during a running refresh owe exactly one more after it', async () => {
    let resolveRefresh!: () => void;
    const refresh = jest.fn().mockReturnValue(new Promise<void>(r => { resolveRefresh = r; }));
    render(<Harness refresh={refresh} />);

    act(() => { mockedBridgeEvents.emit('wallet.refresh', { source: 'a' }); });
    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(1);

    // Three events while the first refresh is still running.
    act(() => {
      mockedBridgeEvents.emit('wallet.refresh', { source: 'b' });
      mockedBridgeEvents.emit('wallet.refresh', { source: 'c' });
      mockedBridgeEvents.emit('wallet.refresh', { source: 'd' });
    });
    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(1);

    refresh.mockResolvedValue(undefined);
    await act(async () => { resolveRefresh(); });
    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(2);

    // Nothing further is owed.
    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it('an owed refresh is not run after unmount', async () => {
    let resolveRefresh!: () => void;
    const refresh = jest.fn().mockReturnValue(new Promise<void>(r => { resolveRefresh = r; }));
    const { unmount } = render(<Harness refresh={refresh} />);

    act(() => { mockedBridgeEvents.emit('wallet.refresh', { source: 'a' }); });
    await act(async () => { flushRaf(); });
    act(() => { mockedBridgeEvents.emit('wallet.refresh', { source: 'b' }); });
    await act(async () => { flushRaf(); });
    unmount();

    await act(async () => { resolveRefresh(); });
    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('handles refresh errors without crashing', async () => {
    const refresh = jest.fn().mockRejectedValue(new Error('boom'));
    render(<Harness refresh={refresh} />);

    act(() => { mockedBridgeEvents.emit('wallet.refresh', { source: 'test' }); });
    await act(async () => { flushRaf(); });
    expect(refresh).toHaveBeenCalledTimes(1);
    // Should not throw — error is caught
  });

  it('cancels pending RAF on unmount', () => {
    const refresh = jest.fn().mockResolvedValue(undefined);
    const { unmount } = render(<Harness refresh={refresh} />);

    act(() => { mockedBridgeEvents.emit('wallet.refresh', { source: 'test' }); });
    unmount();

    expect((globalThis as any).cancelAnimationFrame).toHaveBeenCalled();
  });
});
