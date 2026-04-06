/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { renderHook, act } from '@testing-library/react';

const bridgeHandlers = new Map<string, Set<Function>>();
jest.mock('../../bridge/bridgeEvents', () => ({
  bridgeEvents: {
    on: jest.fn((event: string, handler: Function) => {
      const set = bridgeHandlers.get(event) ?? new Set();
      set.add(handler);
      bridgeHandlers.set(event, set);
      return () => { set.delete(handler); };
    }),
  },
}));

import { useBridgeEvent } from '../useBridgeEvents';

function emitBridge(event: string, payload?: any) {
  const set = bridgeHandlers.get(event);
  if (set) set.forEach(fn => fn(payload));
}

beforeEach(() => {
  bridgeHandlers.clear();
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('useBridgeEvent', () => {
  it('subscribes to the named event and invokes handler', () => {
    const handler = jest.fn();
    renderHook(() => useBridgeEvent('wallet.refresh', handler));

    act(() => { emitBridge('wallet.refresh', { source: 'test' }); });

    expect(handler).toHaveBeenCalledWith({ source: 'test' });
  });

  it('unsubscribes on unmount', () => {
    const handler = jest.fn();
    const { unmount } = renderHook(() => useBridgeEvent('wallet.refresh', handler));

    unmount();

    act(() => { emitBridge('wallet.refresh', { source: 'test' }); });

    expect(handler).not.toHaveBeenCalled();
  });

  it('uses latest handler via ref (no re-subscribe on handler change)', () => {
    const handler1 = jest.fn();
    const handler2 = jest.fn();

    const { rerender } = renderHook(
      ({ handler }) => useBridgeEvent('wallet.refresh', handler),
      { initialProps: { handler: handler1 } },
    );

    rerender({ handler: handler2 });

    act(() => { emitBridge('wallet.refresh', { source: 'test' }); });

    expect(handler1).not.toHaveBeenCalled();
    expect(handler2).toHaveBeenCalledWith({ source: 'test' });
  });

  it('re-subscribes when eventName changes', () => {
    const handler = jest.fn();

    const { rerender } = renderHook(
      ({ eventName }) => useBridgeEvent(eventName, handler),
      { initialProps: { eventName: 'wallet.refresh' } },
    );

    rerender({ eventName: 'identity.ready' });

    // Old event should no longer trigger
    act(() => { emitBridge('wallet.refresh', { source: 'test' }); });
    expect(handler).not.toHaveBeenCalled();

    // New event should work
    act(() => { emitBridge('identity.ready'); });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('handles event with no payload', () => {
    const handler = jest.fn();
    renderHook(() => useBridgeEvent('identity.ready', handler));

    act(() => { emitBridge('identity.ready'); });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(undefined);
  });

  it('supports typed payloads', () => {
    const handler = jest.fn();
    renderHook(() => useBridgeEvent<{ address: string }>('ble.deviceConnected', handler));

    act(() => { emitBridge('ble.deviceConnected', { address: 'AA:BB:CC' }); });

    expect(handler).toHaveBeenCalledWith({ address: 'AA:BB:CC' });
  });
});
