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

// Real 52-char Base32 Crockford CPTA anchors. The fields take a 32-byte policy
// commit, not a ticker: a ticker is not an identity, and typing one used to be
// encoded as UTF-8 and sent as the pair, which no vault could ever match.
const ANCHOR_A = 'BRFKTA6X2BHFWBBWBFE1CK9TMD8DDYS64HQGMBP3MBHZXEK61JP0';
const ANCHOR_B = 'NW9MKEFNZ6GTD8209QN3DQ6996DWP9E9NQ0H5DYCKA9WNS0Z69H0';
const ANCHOR_C = '0EJ2PSRS2YQR8BR77P3WZ92SV12VJT7XP6NWP0SH5P8MWD81C8H0';

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

    fillForm({ from: ANCHOR_A, to: ANCHOR_B, amount: '10000' });
    expect(quote).not.toBeDisabled();
  });

  it('disables Quote when from === to (would be a no-op pair)', () => {
    render(<SwapTab {...makeProps()} />);
    fillForm({ from: ANCHOR_A, to: ANCHOR_A, amount: '10' });
    expect(screen.getByRole('button', { name: /Quote/ })).toBeDisabled();
  });

  it('discovers a route and shows the exact expected output', async () => {
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
    // expectedFinalOutput is the exact output the Rust binder bound to
    // the anchored vault state; the frontend just displays it. The AMM
    // math (x=10000, y=1M, fee=30 → 9871) is exercised by
    // `route_commit_sdk::tests` in Rust.
    mockedFindBind.mockResolvedValue({
      success: true,
      unsignedRouteCommitBytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      quote: {
        expectedFinalOutput: 9871n,
        hops: [],
      },
    });

    render(<SwapTab {...makeProps()} />);
    fillForm({ from: ANCHOR_A, to: ANCHOR_B, amount: '10000' });
    fireEvent.click(screen.getByRole('button', { name: /Quote/ }));

    await waitFor(() => expect(screen.getByText(/1 vault discovered/)).toBeInTheDocument());
    // The exact output Rust computed, against the asset named by its
    // anchor. The frontend never recomputes this number.
    expect(screen.getByText(new RegExp(`9871 ${ANCHOR_B}`))).toBeInTheDocument();
    expect(screen.getByText(/exact output/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Swap$/ })).toBeInTheDocument();
  });

  it('surfaces an error if no vault is advertised for the pair', async () => {
    mockedSync.mockResolvedValue({ success: true, newlyMirroredBase32: [] });
    mockedList.mockResolvedValue({ success: true, advertisements: [] });
    const setError = jest.fn();

    render(<SwapTab {...makeProps({ setError })} />);
    fillForm({ from: ANCHOR_A, to: ANCHOR_C, amount: '1' });
    fireEvent.click(screen.getByRole('button', { name: /Quote/ }));

    await waitFor(() => expect(setError).toHaveBeenCalledWith(expect.stringMatching(/No liquidity advertised/)));
    expect(screen.queryByRole('button', { name: /^Swap$/ })).not.toBeInTheDocument();
  });

  it('surfaces a sync error verbatim', async () => {
    mockedSync.mockResolvedValue({ success: false, error: 'storage node unreachable' });
    const setError = jest.fn();

    render(<SwapTab {...makeProps({ setError })} />);
    fillForm({ from: ANCHOR_A, to: ANCHOR_C, amount: '1' });
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
