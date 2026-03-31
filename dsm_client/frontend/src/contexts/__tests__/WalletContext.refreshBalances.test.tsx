import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import { UXProvider } from '../UXContext';
import { WalletProvider, useWallet } from '../WalletContext';
import { dsmClient } from '../../services/dsmClient';
import * as bitcoinTap from '../../services/bitcoinTap';

describe('WalletContext balance refresh', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
  });

  it('clears prior non-dBTC balances when the authoritative refresh is empty', async () => {
    let latest: ReturnType<typeof useWallet> | null = null;

    jest.spyOn(dsmClient, 'getIdentity' as any).mockResolvedValue({
      genesisHash: 'G'.repeat(32),
      deviceId: 'D'.repeat(32),
    });
    jest.spyOn(dsmClient, 'getWalletHistory' as any).mockResolvedValue({ transactions: [] });
    jest.spyOn(dsmClient, 'getAllBalances' as any)
      .mockResolvedValueOnce([
        { tokenId: 'ERA', tokenName: 'ERA Token', balance: 5n, decimals: 0, symbol: 'ERA' },
      ])
      .mockResolvedValueOnce([]);
    jest.spyOn(bitcoinTap, 'getDbtcBalance').mockResolvedValue(null as any);

    function Harness() {
      latest = useWallet();
      return <div>{latest.balances.length}</div>;
    }

    render(
      <UXProvider>
        <WalletProvider>
          <Harness />
        </WalletProvider>
      </UXProvider>
    );

    await waitFor(() => expect(latest?.balances).toHaveLength(1));

    await act(async () => {
      await latest!.refreshBalances();
    });

    await waitFor(() => expect(latest?.balances).toHaveLength(0));
  });
});
