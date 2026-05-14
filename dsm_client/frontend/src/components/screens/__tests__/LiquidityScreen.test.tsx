// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import LiquidityScreen from '../LiquidityScreen';
import * as amm from '../../../dsm/amm';

jest.mock('../../../dsm/amm');

const mockedList = jest.mocked(amm.listOwnedAmmVaults);
const mockedCreate = jest.mocked(amm.createAmmVault);

describe('LiquidityScreen', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('renders empty state when no vaults are owned', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/No AMM vaults owned by this wallet/)).toBeInTheDocument());
    expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument();
  });

  it('renders owned vaults with reserves and routing-ad status', async () => {
    mockedList.mockResolvedValue({
      success: true,
      vaults: [
        {
          vaultIdBase32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
          tokenA: new TextEncoder().encode('AAA'),
          tokenB: new TextEncoder().encode('BBB'),
          reserveA: 1000n,
          reserveB: 2000n,
          feeBps: 30,
          advertisedStateNumber: 3n,
          routingAdvertised: true,
        },
      ],
    });
    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/AAA \/ BBB/)).toBeInTheDocument());
    expect(screen.getByText(/fee 30 bps/)).toBeInTheDocument();
    expect(screen.getByText(/reserves: 1000 \/ 2000/)).toBeInTheDocument();
    expect(screen.getByText(/ad: ✓ seq=3/)).toBeInTheDocument();
  });

  it('rejects a wrong-length policy anchor at create-time', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /\+ Create vault/ }));
    fireEvent.change(screen.getByLabelText(/Token A/), { target: { value: 'AAA' } });
    fireEvent.change(screen.getByLabelText(/Token B/), { target: { value: 'BBB' } });
    fireEvent.change(screen.getByLabelText(/^Reserve A$/), { target: { value: '1000' } });
    fireEvent.change(screen.getByLabelText(/^Reserve B$/), { target: { value: '2000' } });
    fireEvent.change(screen.getByLabelText(/Policy anchor/), { target: { value: 'TOOSHORT' } });
    fireEvent.click(screen.getByRole('button', { name: /^Create$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));

    await waitFor(() => expect(screen.getByText(/policy anchor must decode to 32 bytes/)).toBeInTheDocument());
    expect(mockedCreate).not.toHaveBeenCalled();
  });

  it('happy path: form submits, refreshes list, shows toast', async () => {
    mockedList
      .mockResolvedValueOnce({ success: true, vaults: [] })
      .mockResolvedValueOnce({
        success: true,
        vaults: [
          {
            vaultIdBase32: 'ABCDEFGHJKMNPQRSTVWXYZ0123456789',
            tokenA: new TextEncoder().encode('AAA'),
            tokenB: new TextEncoder().encode('BBB'),
            reserveA: 1000n,
            reserveB: 2000n,
            feeBps: 30,
            advertisedStateNumber: 1n,
            routingAdvertised: true,
          },
        ],
      });
    mockedCreate.mockResolvedValue({ success: true, vaultIdBase32: 'ABCDEFGHJKMNPQRSTVWXYZ0123456789' });

    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /\+ Create vault/ }));
    fireEvent.change(screen.getByLabelText(/Token A/), { target: { value: 'AAA' } });
    fireEvent.change(screen.getByLabelText(/Token B/), { target: { value: 'BBB' } });
    fireEvent.change(screen.getByLabelText(/^Reserve A$/), { target: { value: '1000' } });
    fireEvent.change(screen.getByLabelText(/^Reserve B$/), { target: { value: '2000' } });
    // 32 zero bytes Base32 Crockford = '0000000000000000000000000000000000000000000000000000'
    fireEvent.change(screen.getByLabelText(/Policy anchor/), {
      target: { value: '0000000000000000000000000000000000000000000000000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Create$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));

    await waitFor(() => expect(mockedCreate).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText(/Vault created/)).toBeInTheDocument());
  });

  it('back button calls onNavigate with home', () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    const onNavigate = jest.fn();
    render(<LiquidityScreen onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('button', { name: /Back/ }));
    expect(onNavigate).toHaveBeenCalledWith('home');
  });
});
