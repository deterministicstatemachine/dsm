// SPDX-License-Identifier: MIT OR Apache-2.0

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

  // An accepted transfer reaches the provider as two events from the accept
  // path: `wallet.bilateralCommitted` (the signal) and `wallet.refresh` (the
  // reload). The provider reloads once, on the second; it used to reload on
  // both.
  it('reloads once for an accepted transfer, on the accept path’s wallet.refresh', async () => {
    const mockBalances = jest.spyOn(dsmClient, 'getAllBalances' as any).mockResolvedValue([]);
    const mockHistory = jest.spyOn(dsmClient, 'getWalletHistory' as any).mockResolvedValue({ transactions: [] });
    const mockIdentity = jest
      .spyOn(dsmClient, 'getIdentity' as any)
      .mockResolvedValue({
        genesisHash: 'G'.repeat(32),
        deviceId: 'D'.repeat(32),
      });
    // The listener reloads on an animation frame; fake timers do not drive
    // jsdom's, so run the frame callback at once.
    jest.spyOn(window, 'requestAnimationFrame').mockImplementation((cb) => {
      cb(0);
      return 0;
    });

    // Render provider so initialization happens and initial fetch may occur
    await renderWalletProvider(<div data-testid="inside-provider" />);

    // Wait for init to attempt identity + first refresh.
    await waitFor(() => expect(mockIdentity).toHaveBeenCalled());

    // Reset call counts to observe the event-triggered refresh
    mockBalances.mockClear();
    mockHistory.mockClear();

    // The signal alone reloads nothing.
    await act(async () => {
      bridgeEvents.emit('wallet.bilateralCommitted', {} as any);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(mockBalances).not.toHaveBeenCalled();
    expect(mockHistory).not.toHaveBeenCalled();

    // The accept path's own refresh reloads, once.
    await act(async () => {
      bridgeEvents.emit('wallet.refresh', { source: 'bilateral.accept_followup' });
      await Promise.resolve();
      await Promise.resolve();
    });
    await waitFor(() => expect(mockBalances).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockHistory).toHaveBeenCalledTimes(1));

    await act(async () => {
      jest.runOnlyPendingTimers();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(mockBalances).toHaveBeenCalledTimes(1);
  });

  it('does not reopen the transfer accepted toast when the user dismisses it', async () => {
    jest.spyOn(dsmClient, 'getAllBalances' as any).mockResolvedValue([]);
    jest.spyOn(dsmClient, 'getWalletHistory' as any).mockResolvedValue({ transactions: [] });
    jest.spyOn(dsmClient, 'getIdentity' as any).mockResolvedValue({
      genesisHash: 'G'.repeat(32),
      deviceId: 'D'.repeat(32),
    });

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
