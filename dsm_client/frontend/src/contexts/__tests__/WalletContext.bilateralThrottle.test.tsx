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

  test('refreshAll is throttled and toast not spammed on rapid events', async () => {
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
    expect(getBalancesSpy).toHaveBeenCalledTimes(1);
    expect(notifySpy).toHaveBeenCalledTimes(1);

    // Dispatch a couple more events inside throttle window (should not cause extra immediate refreshes)
    act(() => {
      emitBilateralCommitted();
      emitBilateralCommitted();
    });

    // Flushing microtasks again should schedule exactly one more refresh.
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(getBalancesSpy).toHaveBeenCalledTimes(2);
    expect(notifySpy).toHaveBeenCalledTimes(2);
  });
});
