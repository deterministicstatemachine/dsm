// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { render, act } from '@testing-library/react';
import { UXProvider } from '../UXContext';
import { WalletProvider } from '../WalletContext';
import GlobalToast from '../../components/GlobalToast';
import { dsmClient } from '@/dsm/index';
import { emitBilateralCommitted } from '@/dsm/events';

describe('WalletContext bilateral event throttle & toast', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  // The committed signal is the toast's trigger and nothing else: the accept
  // path emits its own `wallet.refresh`, and the provider used to reload on
  // the signal as well, a second reload of the same accept.
  test('a burst of committed signals shows one toast and reloads nothing', async () => {
    const getBalancesSpy = jest.spyOn(dsmClient, 'getAllBalances').mockResolvedValue([] as any);
    const getHistorySpy = jest.spyOn(dsmClient, 'getWalletHistory').mockResolvedValue({ transactions: [] } as any);
    const getContactsSpy = jest.spyOn(dsmClient, 'getContacts').mockResolvedValue({ contacts: [] } as any);
    // Do NOT provide identity so the initial refresh won't fire (we'll exercise refresh via events)
    jest.spyOn(dsmClient, 'getIdentity').mockResolvedValue(null as any);

    const notifySpy = jest.fn();

    const SpyHarness = () => {
      const ux = (require('../UXContext') as any).useUX();
      React.useEffect(() => {
        // Replace notifyToast with spy (mutates provider value)
        ux.notifyToast = (...args: any[]) => notifySpy(...args);
      }, []);
      return null;
    };

    // Render providers
    render(
      <UXProvider>
        <WalletProvider>
          <SpyHarness />
          <GlobalToast />
        </WalletProvider>
      </UXProvider>
    );

    // Clear initial refresh calls triggered by provider initialization
    getBalancesSpy.mockClear();
    getHistorySpy.mockClear();
    getContactsSpy.mockClear();
    notifySpy.mockClear();

    // Rapidly dispatch 3 events at t=0
    act(() => {
      emitBilateralCommitted();
      emitBilateralCommitted();
      emitBilateralCommitted();
    });

    // Deterministic coalescing uses a microtask gate. Flush microtasks to allow it to run.
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(getBalancesSpy).not.toHaveBeenCalled();
    expect(getHistorySpy).not.toHaveBeenCalled();
    expect(notifySpy).toHaveBeenCalledTimes(1);

    // A second burst: one more toast, still no reload from the signal.
    act(() => {
      emitBilateralCommitted();
      emitBilateralCommitted();
    });

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(getBalancesSpy).not.toHaveBeenCalled();
    expect(notifySpy).toHaveBeenCalledTimes(2);
  });
});
