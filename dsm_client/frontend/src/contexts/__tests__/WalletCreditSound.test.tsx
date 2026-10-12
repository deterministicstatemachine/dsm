// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import { WalletProvider } from '../WalletContext';
import { UXProvider } from '../UXContext';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { dsmClient } from '../../services/dsmClient';
import { walletStore } from '../../stores/walletStore';
import { playCoinSound } from '../../utils/coinSound';
import { initializeEventBridge } from '../../dsm/EventBridge';
import * as pb from '../../proto/dsm_app_pb';

jest.mock('../../utils/coinSound', () => ({
  playCoinSound: jest.fn(),
}));

/** A native event as Kotlin posts it: the topic and the raw payload bytes. */
function announce(topic: string, payload: Uint8Array) {
  window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic, payload } }));
}

describe('wallet credit sound routing', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    jest.clearAllMocks();
    (walletStore as any).snapshot = {
      genesisHash: null,
      deviceId: null,
      balances: [],
      transactions: [],
      isInitialized: false,
      isLoading: false,
      error: null,
    };
    (walletStore as any).loadingCount = 0;
  });

  // What the event bridge announces for one change reloads the projection
  // once: a completed bilateral transfer (`bilateral.event`) and an inbox sync
  // with new items (`inbox.updated`) each become one `wallet.refresh`, and the
  // provider reloads on that alone. The coin sound follows what Rust reports
  // landed (the inbox items it processed), never a higher number on a reload:
  // a balance that grew between two reads used to be announced as a payment,
  // and at launch the first read is empty, so every launch was greeted as one.
  it('reloads once per announced change and plays the coin sound only for items Rust reports', async () => {
    initializeEventBridge();
    jest.spyOn(dsmClient, 'getIdentity' as any).mockResolvedValue({
      genesisHash: 'G'.repeat(32),
      deviceId: 'D'.repeat(32),
    });
    jest.spyOn(dsmClient, 'getWalletHistory' as any).mockResolvedValue({ transactions: [] });
    jest.spyOn(dsmClient, 'getAllBalances' as any)
      .mockResolvedValueOnce([
        { tokenId: 'dBTC', tokenName: 'dBTC', baseUnits: 5n, decimals: 8, symbol: 'dBTC' },
      ])
      .mockResolvedValueOnce([
        { tokenId: 'dBTC', tokenName: 'dBTC', baseUnits: 6n, decimals: 8, symbol: 'dBTC' },
      ])
      .mockResolvedValueOnce([
        { tokenId: 'dBTC', tokenName: 'dBTC', baseUnits: 6n, decimals: 8, symbol: 'dBTC' },
      ]);

    await act(async () => {
      render(
        <UXProvider>
          <WalletProvider>
            <div data-testid="wallet-credit-sound" />
          </WalletProvider>
        </UXProvider>
      );
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(dsmClient.getIdentity as any).toHaveBeenCalled();
    });

    expect(playCoinSound).not.toHaveBeenCalled();

    act(() => {
      announce(
        'bilateral.event',
        new pb.BilateralEventNotification({
          eventType: pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE,
          message: 'test',
        } as any).toBinary(),
      );
    });

    await waitFor(() => {
      expect((dsmClient.getAllBalances as any)).toHaveBeenCalledTimes(2);
    });
    // The balance rose from 5 to 6 on that reload; that is not a credit.
    expect(playCoinSound).not.toHaveBeenCalled();

    act(() => {
      announce('inbox.updated', new pb.StorageSyncResponse({ processed: 1 } as any).toBinary());
    });

    await waitFor(() => {
      expect((dsmClient.getAllBalances as any)).toHaveBeenCalledTimes(3);
    });
    // A second reload of either change would follow within a frame or two;
    // none does.
    await act(async () => {
      await new Promise((r) => setTimeout(r, 80));
    });
    expect((dsmClient.getAllBalances as any)).toHaveBeenCalledTimes(3);
    expect(playCoinSound).toHaveBeenCalledTimes(1);
  });

  it('plays the coin sound for explicit bridge completion credit events', async () => {
    await act(async () => {
      render(
        <UXProvider>
          <div data-testid="wallet-credit-event" />
        </UXProvider>
      );
      await Promise.resolve();
    });

    act(() => {
      bridgeEvents.emit('wallet.creditReceived', {
        source: 'bitcoin.exit_completed',
        tokenId: 'BTC_CHAIN',
        amount: '100000',
        creditCount: 1,
      });
    });

    await waitFor(() => {
      expect(playCoinSound).toHaveBeenCalledTimes(1);
    });
  });
});
