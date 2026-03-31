import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { WalletProvider } from '../WalletContext';
import { UXProvider } from '../UXContext';
import { dsmClient } from '../../services/dsmClient';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import GlobalToast from '../../components/GlobalToast';

describe('WalletContext bilateral committed event', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    jest.useFakeTimers();
  });

  const renderWalletProvider = async (children?: React.ReactNode) => {
    await act(async () => {
      render(
        <UXProvider>
          <WalletProvider>
            <GlobalToast />
            {children}
          </WalletProvider>
        </UXProvider>
      );
      jest.runOnlyPendingTimers();
      await Promise.resolve();
      await Promise.resolve();
    });
  };

  afterEach(async () => {
    await act(async () => {
      jest.runOnlyPendingTimers();
      await Promise.resolve();
      await Promise.resolve();
    });
    jest.useRealTimers();
  });

  it('refreshes balances and history when wallet.bilateralCommitted fires', async () => {
    const mockBalances = jest.spyOn(dsmClient, 'getAllBalances' as any).mockResolvedValue([]);
    const mockHistory = jest.spyOn(dsmClient, 'getWalletHistory' as any).mockResolvedValue({ transactions: [] });
    const mockIdentity = jest
      .spyOn(dsmClient, 'getIdentity' as any)
      .mockResolvedValue({
        genesisHash: 'G'.repeat(32),
        deviceId: 'D'.repeat(32),
      });
    jest.spyOn(dsmClient, 'isReady' as any).mockResolvedValue(true);

    // Render provider so initialization happens and initial fetch may occur
    await renderWalletProvider(<div data-testid="inside-provider" />);

    // Wait for init to attempt identity + first refresh.
    await waitFor(() => expect(mockIdentity).toHaveBeenCalled());

    // Reset call counts to observe the event-triggered refresh
    mockBalances.mockClear();
    mockHistory.mockClear();

    // Dispatch event that should trigger refreshAll()
    await act(async () => {
      bridgeEvents.emit('wallet.bilateralCommitted', {} as any);
      await Promise.resolve();
    });

    // useSyncExternalStore triggers a synchronous snapshot update; timers not required.

    // Expect the underlying refresh calls to be called
    await waitFor(() => expect(mockBalances).toHaveBeenCalled());
    await waitFor(() => expect(mockHistory).toHaveBeenCalled());

    await act(async () => {
      jest.runOnlyPendingTimers();
      await Promise.resolve();
      await Promise.resolve();
    });
  });

  it('does not reopen the transfer accepted toast when the user dismisses it', async () => {
    jest.spyOn(dsmClient, 'getAllBalances' as any).mockResolvedValue([]);
    jest.spyOn(dsmClient, 'getWalletHistory' as any).mockResolvedValue({ transactions: [] });
    jest.spyOn(dsmClient, 'getIdentity' as any).mockResolvedValue({
      genesisHash: 'G'.repeat(32),
      deviceId: 'D'.repeat(32),
    });
    jest.spyOn(dsmClient, 'isReady' as any).mockResolvedValue(true);

    await renderWalletProvider();

    await act(async () => {
      bridgeEvents.emit('wallet.bilateralCommitted', { accepted: true } as any);
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(screen.getByText('Transfer accepted')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByLabelText('Dismiss'));

    await waitFor(() => {
      expect(screen.queryByText('Transfer accepted')).not.toBeInTheDocument();
    });

    await act(async () => {
      jest.runOnlyPendingTimers();
      await Promise.resolve();
    });

    expect(screen.queryByText('Transfer accepted')).not.toBeInTheDocument();
  });
});
