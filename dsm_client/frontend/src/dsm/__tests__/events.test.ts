// SPDX-License-Identifier: MIT OR Apache-2.0

jest.mock('../../bridge/bridgeEvents', () => {
  const handlers = new Map<string, Set<(payload: any) => void>>();
  return {
    bridgeEvents: {
      emit: jest.fn((event: string, payload: any) => {
        const set = handlers.get(event);
        if (set) {
          for (const handler of Array.from(set)) {
            handler(payload);
          }
        }
      }),
      on: jest.fn((event: string, handler: (payload: any) => void) => {
        const set = handlers.get(event) ?? new Set();
        set.add(handler);
        handlers.set(event, set);
        return () => set.delete(handler);
      }),
    },
  };
});

import { emitWalletRefresh, emitBilateralAccepted } from '../events';
import { bridgeEvents } from '../../bridge/bridgeEvents';

describe('events.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('emitWalletRefresh', () => {
    test('emits wallet.refresh event with detail', () => {
      const detail = { source: 'storage.sync' };
      emitWalletRefresh(detail);
      expect(bridgeEvents.emit).toHaveBeenCalledWith('wallet.refresh', detail);
    });

    test('passes extra fields through', () => {
      const detail = { source: 'wallet.send', transactionHash: new Uint8Array(32) };
      emitWalletRefresh(detail);
      expect(bridgeEvents.emit).toHaveBeenCalledWith('wallet.refresh', detail);
    });
  });

  describe('emitBilateralAccepted', () => {
    test('emits wallet.bilateralAccepted with the transfer it names', () => {
      const detail = {
        commitmentHash: new Uint8Array(32).fill(0xAA),
        counterpartyDeviceId: new Uint8Array(32).fill(0xBB),
      };
      emitBilateralAccepted(detail);
      expect(bridgeEvents.emit).toHaveBeenCalledWith('wallet.bilateralAccepted', detail);
    });
  });

  describe('event integration with bridgeEvents listeners', () => {
    test('wallet.refresh event is received by listeners', () => {
      const listener = jest.fn();
      bridgeEvents.on('wallet.refresh', listener);

      emitWalletRefresh({ source: 'test' });
      expect(listener).toHaveBeenCalledWith({ source: 'test' });
    });

    test('wallet.bilateralAccepted event is received by listeners', () => {
      const listener = jest.fn();
      bridgeEvents.on('wallet.bilateralAccepted', listener);

      const detail = {
        commitmentHash: new Uint8Array(32).fill(1),
        counterpartyDeviceId: new Uint8Array(32).fill(2),
      };
      emitBilateralAccepted(detail);
      expect(listener).toHaveBeenCalledWith(detail);
    });
  });
});
