import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import { WalletProvider } from '../WalletContext';
import { UXProvider } from '../UXContext';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { dsmClient } from '../../services/dsmClient';
import { walletStore } from '../../stores/walletStore';
import { playCoinSound } from '../../utils/coinSound';

jest.mock('../../utils/coinSound', () => ({
  playCoinSound: jest.fn(),
}));

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
    (walletStore as any).hasObservedBalances = false;
  });

  it('plays the coin sound only after a positive balance delta on receiver-side refreshes', async () => {
    jest.spyOn(dsmClient, 'getIdentity' as any).mockResolvedValue({
      genesisHash: 'G'.repeat(32),
      deviceId: 'D'.repeat(32),
    });
    jest.spyOn(dsmClient, 'getWalletHistory' as any).mockResolvedValue({ transactions: [] });
    jest.spyOn(dsmClient, 'getAllBalances' as any)
      .mockResolvedValueOnce([
        { tokenId: 'dBTC', tokenName: 'dBTC', balance: 5n, decimals: 8, symbol: 'dBTC' },
      ])
      .mockResolvedValueOnce([
        { tokenId: 'dBTC', tokenName: 'dBTC', balance: 6n, decimals: 8, symbol: 'dBTC' },
      ])
      .mockResolvedValueOnce([
        { tokenId: 'dBTC', tokenName: 'dBTC', balance: 6n, decimals: 8, symbol: 'dBTC' },
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
      bridgeEvents.emit('bilateral.transferComplete', undefined as any);
    });

    await waitFor(() => {
      expect(playCoinSound).toHaveBeenCalledTimes(1);
    });

    act(() => {
      bridgeEvents.emit('inbox.updated', { unreadCount: 1, newItems: 1, source: 'poll' });
    });

    await waitFor(() => {
      expect((dsmClient.getAllBalances as any)).toHaveBeenCalledTimes(3);
    });

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
