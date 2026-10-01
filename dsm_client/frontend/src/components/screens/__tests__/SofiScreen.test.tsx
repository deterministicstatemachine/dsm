// SPDX-License-Identifier: Apache-2.0
// The SoFi screen sends intent only: the anchors the balances carry, decoded
// to the 32 bytes SoFi names a token by, and the amounts as typed, in token
// units, for Rust to parse. It shows the amounts Rust renders.

import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { encodeBase32Crockford } from '../../../utils/textId';
import type { TokenBalanceView } from '../../../dsm/types';

const findRoute = jest.fn();
const trade = jest.fn();
const route = jest.fn();
const createVault = jest.fn();
const close = jest.fn();
const resolve = jest.fn();
const relay = jest.fn();
jest.mock('../../../dsm/sofi', () => ({
  findRoute: (...a: unknown[]) => findRoute(...a),
  trade: (...a: unknown[]) => trade(...a),
  route: (...a: unknown[]) => route(...a),
  createVault: (...a: unknown[]) => createVault(...a),
  close: (...a: unknown[]) => close(...a),
  resolve: (...a: unknown[]) => resolve(...a),
  relay: (...a: unknown[]) => relay(...a),
}));

const play = jest.fn();
jest.mock('../../fx/FxProvider', () => ({
  useFx: () => ({ play }),
}));

const refreshBalances = jest.fn().mockResolvedValue(undefined);
let balances: TokenBalanceView[] = [];
jest.mock('../../../contexts/WalletContext', () => ({
  useWallet: () => ({ balances, refreshBalances }),
}));

import SofiScreen from '../SofiScreen';

const ERA_BYTES = new Uint8Array(32).fill(0x11);
const PLAY_BYTES = new Uint8Array(32).fill(0x22);
const ERA = encodeBase32Crockford(ERA_BYTES);
const PLAY = encodeBase32Crockford(PLAY_BYTES);
const VAULT_1 = new Uint8Array(32).fill(0xa1);
const VAULT_2 = new Uint8Array(32).fill(0xa2);

function balance(symbol: string, anchor: string | undefined): TokenBalanceView {
  return {
    tokenId: symbol,
    symbol,
    tokenName: symbol,
    baseUnits: 1000n,
    decimals: 0,
    displayAmount: '1000',
    policyAnchorB32: anchor,
    anchorFingerprint: anchor?.slice(0, 8),
    protocolDefined: symbol === 'ERA',
  };
}

async function pickToken(control: string, ticker: string) {
  fireEvent.click(screen.getByRole('button', { name: control }));
  const list = await screen.findByRole('listbox', { name: control });
  fireEvent.click(within(list).getByRole('option', { name: new RegExp(ticker) }));
}

beforeEach(() => {
  jest.clearAllMocks();
  // A hostile row: a token with no anchor is held, and must not be offered.
  balances = [balance('ERA', ERA), balance('PLAY', PLAY), balance('NOANCHOR', undefined)];
});

describe('SofiScreen', () => {
  it('is a framed screen with Swap and Liquidity, and offers only anchored tokens', async () => {
    render(<SofiScreen />);
    expect(screen.getByRole('heading', { name: 'SoFi' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Swap' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Liquidity' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Token in' }));
    const list = await screen.findByRole('listbox', { name: 'Token in' });
    expect(within(list).getAllByRole('option')).toHaveLength(2);
    expect(within(list).queryByText('NOANCHOR')).toBeNull();
  });

  it("tells two tokens with one ticker apart by their anchor's fingerprint", async () => {
    const LOOKALIKE = encodeBase32Crockford(new Uint8Array(32).fill(0x33));
    balances = [balance('PLAY', PLAY), balance('PLAY', LOOKALIKE)];
    render(<SofiScreen />);
    fireEvent.click(screen.getByRole('button', { name: 'Liquidity' }));

    fireEvent.click(screen.getByRole('button', { name: 'Token A' }));
    const list = await screen.findByRole('listbox', { name: 'Token A' });
    const rows = within(list).getAllByRole('option');
    expect(rows.map((row) => row.textContent)).toEqual([
      `PLAY${PLAY.slice(0, 8)}`,
      `PLAY${LOOKALIKE.slice(0, 8)}`,
    ]);
  });

  it('sends an amount in token units as entered, for Rust to parse', async () => {
    render(<SofiScreen />);
    fireEvent.change(screen.getByLabelText('You pay'), { target: { value: ' 2.5 ' } });
    await pickToken('Token in', 'ERA');
    await pickToken('Token out', 'PLAY');
    fireEvent.click(screen.getByRole('button', { name: 'Quote' }));
    await waitFor(() => expect(findRoute).toHaveBeenCalledTimes(1));
    expect(findRoute).toHaveBeenCalledWith({ tokenIn: ERA_BYTES, tokenOut: PLAY_BYTES, amountIn: '2.5' });
  });

  it('creates liquidity with the pair ordered bytewise and the reserves following their tokens', async () => {
    createVault.mockResolvedValueOnce({ vaultId: VAULT_1, position: 3n });
    render(<SofiScreen />);
    fireEvent.click(screen.getByRole('button', { name: 'Liquidity' }));

    // PLAY (0x22…) is picked as A, ERA (0x11…) as B: ERA sorts first.
    fireEvent.change(screen.getByLabelText('Token A and its reserve'), { target: { value: '500' } });
    await pickToken('Token A', 'PLAY');
    fireEvent.change(screen.getByLabelText('Token B and its reserve'), { target: { value: '100' } });
    await pickToken('Token B', 'ERA');
    fireEvent.change(screen.getByLabelText('Fee, in basis points'), { target: { value: '25' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Liquidity Vault' }));

    await waitFor(() => expect(createVault).toHaveBeenCalledTimes(1));
    expect(createVault).toHaveBeenCalledWith({ tokenA: ERA_BYTES, tokenB: PLAY_BYTES, reserveA: '100', reserveB: '500', feeBps: 25 });
    const created = await screen.findByRole('status', { name: 'Liquidity vault created' });
    expect(within(created).getByText(encodeBase32Crockford(VAULT_1))).toBeInTheDocument();
    expect(screen.getByLabelText('Vault id')).toHaveValue(encodeBase32Crockford(VAULT_1));
    expect(play).toHaveBeenCalledWith(expect.objectContaining({ anim: 'vault', title: 'Liquidity vault created' }));
  });

  it('closes liquidity by its id, with no setup of its own to press; resolve is on the header', async () => {
    close.mockResolvedValueOnce({ position: 5n, state: 'realized' });
    resolve.mockResolvedValueOnce({ position: 6n, state: 'retriesExhausted' });
    render(<SofiScreen />);
    fireEvent.click(screen.getByRole('button', { name: 'Liquidity' }));

    fireEvent.change(screen.getByLabelText('Vault id'), { target: { value: encodeBase32Crockford(VAULT_2) } });
    // The first trade, or the owner's first close, sets up on its own (SoFi Amendment S16).
    expect(screen.queryByRole('button', { name: 'Set up' })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(close).toHaveBeenCalledWith(VAULT_2));
    expect(await screen.findByText('Realized at position 5')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Resolve' }));
    await waitFor(() => expect(resolve).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Network retries ran out/)).toBeInTheDocument();
    expect(play).toHaveBeenLastCalledWith(expect.objectContaining({ anim: 'fail', title: 'Resolve not realized' }));
  });
});
