import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DevAmmMonitorScreen from '../DevAmmMonitorScreen';

jest.mock('../../../dsm/amm', () => ({
  listOwnedAmmVaults: jest.fn(),
}));

import { listOwnedAmmVaults } from '../../../dsm/amm';
import { encodeBase32Crockford } from '../../../utils/textId';

const v1 = encodeBase32Crockford(new Uint8Array(32).fill(0x11));
const v2 = encodeBase32Crockford(new Uint8Array(32).fill(0x22));

describe('DevAmmMonitorScreen', () => {
  beforeEach(() => jest.clearAllMocks());

  test('auto-refreshes on mount and renders empty state', async () => {
    (listOwnedAmmVaults as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [],
    });
    render(<DevAmmMonitorScreen />);
    await waitFor(() => expect(listOwnedAmmVaults).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(screen.getByText(/No AMM vaults owned by this wallet/i)).toBeInTheDocument(),
    );
  });

  test('renders vault rows with reserves + advertised state_number', async () => {
    (listOwnedAmmVaults as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [
        {
          vaultIdBase32: v1,
          tokenA: new TextEncoder().encode('DEMO_AAA'),
          tokenB: new TextEncoder().encode('DEMO_BBB'),
          reserveA: 1_000_000n,
          reserveB: 2_000_000n,
          feeBps: 30,
          advertisedStateNumber: 5n,
          routingAdvertised: true,
        },
      ],
    });
    render(<DevAmmMonitorScreen />);
    await waitFor(() =>
      expect(screen.getByText(/DEMO_AAA\/DEMO_BBB/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/reserves/)).toBeInTheDocument();
    expect(screen.getByText(/\(1000000, 2000000\)/)).toBeInTheDocument();
    expect(screen.getByText(/state_number=5/)).toBeInTheDocument();
    expect(screen.getByText(/✓ published/)).toBeInTheDocument();
  });

  test('shows "not published" hint for vaults without routing ad', async () => {
    (listOwnedAmmVaults as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [
        {
          vaultIdBase32: v2,
          tokenA: new TextEncoder().encode('AAA'),
          tokenB: new TextEncoder().encode('BBB'),
          reserveA: 1n,
          reserveB: 1n,
          feeBps: 5,
          advertisedStateNumber: 0n,
          routingAdvertised: false,
        },
      ],
    });
    render(<DevAmmMonitorScreen />);
    await waitFor(() =>
      expect(screen.getByText(/✗ not published/i)).toBeInTheDocument(),
    );
  });

  test('Refresh button triggers a re-fetch', async () => {
    (listOwnedAmmVaults as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [],
    });
    render(<DevAmmMonitorScreen />);
    await waitFor(() => expect(listOwnedAmmVaults).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByText(/^Refresh$/i));
    await waitFor(() => expect(listOwnedAmmVaults).toHaveBeenCalledTimes(2));
  });

  test('surfaces error envelopes verbatim', async () => {
    (listOwnedAmmVaults as jest.Mock).mockResolvedValue({
      success: false,
      error: 'wallet locked',
    });
    render(<DevAmmMonitorScreen />);
    await waitFor(() =>
      expect(screen.getByText(/Refresh failed: wallet locked/i)).toBeInTheDocument(),
    );
  });
});
