/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { render } from '@testing-library/react';
import { emit } from '../../dsm/EventBridge';
import { BilateralTransferDialog } from '../BilateralTransferDialog';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { BilateralEventType, encodeBilateralEventNotification } from '../../services/bilateral/bilateralEventService';

jest.mock('../../contexts/UXContext', () => ({
  useUX: () => ({
    hideComplexity: true,
    setHideComplexity: jest.fn(),
  }),
  useWallet: () => ({
    refreshAll: jest.fn(),
  }),
}));

describe('BilateralTransferDialog TRANSFER_COMPLETE event handling', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  test('dispatches dsm-wallet-refresh', async () => {
    const refreshSpy = jest.fn();

    const unsubscribe = bridgeEvents.on('wallet.refresh', refreshSpy as any);

    // Render dialog (safe to render without WalletProvider; default context is no-op)
    render(<BilateralTransferDialog />);

    // Build a TRANSFER_COMPLETE event payload
    const payload = encodeBilateralEventNotification({
      eventType: BilateralEventType.TRANSFER_COMPLETE,
      status: 'complete',
      message: 'transfer complete test',
      amount: 100n,
      tokenId: 'ERA',
    });

    // Emit via EventBridge
    emit('bilateral.event', payload);

    // Handlers are dispatched synchronously by the component; assert spies called
    expect(refreshSpy).toHaveBeenCalled();

    unsubscribe();
  });
});
