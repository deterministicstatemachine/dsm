// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import SwapTab from '../SwapTab';
import * as routeCommit from '../../../../dsm/route_commit';

jest.mock('../../../../dsm/route_commit');

const mockedSync = jest.mocked(routeCommit.syncVaultsForPair);
const mockedList = jest.mocked(routeCommit.listAdvertisementsForPair);
const mockedFindBind = jest.mocked(routeCommit.findAndBindBestPath);

function makeProps(overrides: Partial<React.ComponentProps<typeof SwapTab>> = {}) {
  return {
    balances: [
      { tokenId: 'ERA', symbol: 'ERA', balance: '100' },
      { tokenId: 'DEMO_AAA', symbol: 'AAA', balance: '5000' },
    ],
    deviceB32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
    onCancel: jest.fn(),
    onSwapComplete: jest.fn(),
    loadWalletData: jest.fn().mockResolvedValue(undefined),
    setError: jest.fn(),
    ...overrides,
  };
}

function fillForm({ from, to, amount }: { from: string; to: string; amount: string }) {
  fireEvent.change(screen.getByLabelText(/Input token id/i), { target: { value: from } });
  fireEvent.change(screen.getByLabelText(/Output token id/i), { target: { value: to } });
  fireEvent.change(screen.getByLabelText(/Input amount/i), { target: { value: amount } });
}

describe('SwapTab', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('renders symmetric From / To text inputs with Quote disabled until both filled', () => {
    render(<SwapTab {...makeProps()} />);
    const quote = screen.getByRole('button', { name: /Quote/ });
    expect(quote).toBeDisabled();

    fillForm({ from: 'DEMO_AAA', to: 'DEMO_BBB', amount: '10000' });
    expect(quote).not.toBeDisabled();
  });

  it('disables Quote when from === to (would be a no-op pair)', () => {
    render(<SwapTab {...makeProps()} />);
    fillForm({ from: 'ERA', to: 'ERA', amount: '10' });
    expect(screen.getByRole('button', { name: /Quote/ })).toBeDisabled();
  });

  it('exposes a slippage tolerance input defaulted at 0.5%', () => {
    render(<SwapTab {...makeProps()} />);
    const slip = screen.getByLabelText(/Slippage tolerance percent/i) as HTMLInputElement;
    expect(slip.value).toBe('0.5');
    expect(slip).toHaveAttribute('max', '50');
  });

  it('discovers a route and shows expected output + slippage-adjusted min-out', async () => {
    mockedSync.mockResolvedValue({ success: true, newlyMirroredBase32: [] });
    mockedList.mockResolvedValue({
      success: true,
      advertisements: [
        {
          vaultIdBase32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
          tokenA: new TextEncoder().encode('DEMO_AAA'),
          tokenB: new TextEncoder().encode('DEMO_BBB'),
          reserveA: 1_000_000n,
          reserveB: 1_000_000n,
          feeBps: 30,
          stateNumber: 1n,
          ownerPublicKey: new Uint8Array([0x01]),
        },
      ],
    });
    // expectedFinalOutput and floorFinalOutput are stamped by the Rust
    // binder; the frontend just displays what came back.  Mock both
    // values directly here — the underlying AMM math (x=10000, y=1M,
    // fee=30 → ~9871, with 0.5% floor → 9821) is exercised by
    // `route_commit_sdk::tests` in Rust.
    mockedFindBind.mockResolvedValue({
      success: true,
      unsignedRouteCommitBytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      quote: {
        expectedFinalOutput: 9871n,
        floorFinalOutput: 9821n,
        hops: [],
        fallbackGroupCount: 0,
      },
    });

    render(<SwapTab {...makeProps()} />);
    fillForm({ from: 'DEMO_AAA', to: 'DEMO_BBB', amount: '10000' });
    fireEvent.click(screen.getByRole('button', { name: /Quote/ }));

    await waitFor(() => expect(screen.getByText(/1 vault discovered/)).toBeInTheDocument());
    expect(screen.getByText(/~9871 DEMO_BBB/)).toBeInTheDocument();
    expect(screen.getByText(/9821/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Swap$/ })).toBeInTheDocument();
  });

  it('surfaces an error if no vault is advertised for the pair', async () => {
    mockedSync.mockResolvedValue({ success: true, newlyMirroredBase32: [] });
    mockedList.mockResolvedValue({ success: true, advertisements: [] });
    const setError = jest.fn();

    render(<SwapTab {...makeProps({ setError })} />);
    fillForm({ from: 'A', to: 'NOPAIR', amount: '1' });
    fireEvent.click(screen.getByRole('button', { name: /Quote/ }));

    await waitFor(() => expect(setError).toHaveBeenCalledWith(expect.stringMatching(/No liquidity advertised/)));
    expect(screen.queryByRole('button', { name: /^Swap$/ })).not.toBeInTheDocument();
  });

  it('surfaces a sync error verbatim', async () => {
    mockedSync.mockResolvedValue({ success: false, error: 'storage node unreachable' });
    const setError = jest.fn();

    render(<SwapTab {...makeProps({ setError })} />);
    fillForm({ from: 'A', to: 'X', amount: '1' });
    fireEvent.click(screen.getByRole('button', { name: /Quote/ }));

    await waitFor(() => expect(setError).toHaveBeenCalledWith('storage node unreachable'));
  });

  it('cancels back to the overview tab', () => {
    const onCancel = jest.fn();
    render(<SwapTab {...makeProps({ onCancel })} />);
    fireEvent.click(screen.getByRole('button', { name: /Cancel/ }));
    expect(onCancel).toHaveBeenCalled();
  });
});
