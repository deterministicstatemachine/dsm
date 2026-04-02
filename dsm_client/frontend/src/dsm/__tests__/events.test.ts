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

import { emitWalletRefresh, emitBilateralCommitted, DSM_WALLET_REFRESH_EVENT } from '../events';
import { bridgeEvents } from '../../bridge/bridgeEvents';

describe('events.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('DSM_WALLET_REFRESH_EVENT', () => {
    test('has the canonical event name', () => {
      expect(DSM_WALLET_REFRESH_EVENT).toBe('dsm-wallet-refresh');
    });
  });

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

  describe('emitBilateralCommitted', () => {
    test('emits wallet.bilateralCommitted with detail', () => {
      const detail = {
        commitmentHash: new Uint8Array(32).fill(0xAA),
        counterpartyDeviceId: new Uint8Array(32).fill(0xBB),
        accepted: true,
        committed: true,
        rejected: false,
      };
      emitBilateralCommitted(detail);
      expect(bridgeEvents.emit).toHaveBeenCalledWith('wallet.bilateralCommitted', detail);
    });

    test('emits empty object when no detail provided', () => {
      emitBilateralCommitted();
      expect(bridgeEvents.emit).toHaveBeenCalledWith('wallet.bilateralCommitted', {});
    });

    test('emits empty object when undefined is passed', () => {
      emitBilateralCommitted(undefined);
      expect(bridgeEvents.emit).toHaveBeenCalledWith('wallet.bilateralCommitted', {});
    });
  });

  describe('event integration with bridgeEvents listeners', () => {
    test('wallet.refresh event is received by listeners', () => {
      const listener = jest.fn();
      bridgeEvents.on('wallet.refresh', listener);

      emitWalletRefresh({ source: 'test' });
      expect(listener).toHaveBeenCalledWith({ source: 'test' });
    });

    test('wallet.bilateralCommitted event is received by listeners', () => {
      const listener = jest.fn();
      bridgeEvents.on('wallet.bilateralCommitted', listener);

      const detail = { accepted: true, committed: true };
      emitBilateralCommitted(detail);
      expect(listener).toHaveBeenCalledWith(detail);
    });
  });
});
