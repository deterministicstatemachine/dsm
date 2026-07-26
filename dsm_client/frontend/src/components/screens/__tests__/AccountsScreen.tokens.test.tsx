// SPDX-License-Identifier: Apache-2.0
//! The screen the TOKENS menu opens must be able to manage tokens.
//!
//! The predecessor of this file tested `TokenManagementScreen` by rendering it
//! directly. It passed six times over while that component was **unreachable**:
//! the home menu's TOKENS entry called `navigate('accounts')`, which routes to
//! this screen, and nothing anywhere navigated to `'tokens'`. Create, mint and
//! burn were shipped as dead code and only found by opening the app on a
//! handset.
//!
//! So the first test here asserts the WIRING, not just the rendering. A test
//! that mounts a component in isolation can never catch a component nobody
//! mounts.

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

const balances = [
  { tokenId: 'ERA', symbol: 'ERA', balance: '264' },
  { tokenId: 'MYTOK', symbol: 'MYTOK', balance: '500' },
];

jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    getAllBalances: jest.fn().mockResolvedValue(balances),
    claimFaucet: jest.fn(),
  },
}));

jest.mock('../../../dsm/policies', () => ({
  mintToken: jest.fn(),
  burnToken: jest.fn(),
  addTokenByAnchor: jest.fn(),
}));

jest.mock('../../../hooks/useWalletRefreshListener', () => ({
  useWalletRefreshListener: () => {},
}));

jest.mock('../../../contexts/WalletContext', () => ({
  useWallet: () => ({ refreshAll: jest.fn(), isInitialized: true }),
}));

jest.mock('../../../hooks/useDpadNav', () => ({
  useDpadNav: () => ({ focusedIndex: -1 }),
}));

jest.mock('../../TokenCreationDialog', () => ({
  TokenCreationDialog: () => <div data-testid="create-dialog" />,
}));

import AccountsScreen from '../AccountsScreen';
import { mintToken, burnToken, addTokenByAnchor } from '../../../dsm/policies';

describe('AccountsScreen — the screen TOKENS actually opens', () => {
  beforeEach(() => jest.clearAllMocks());

  /// THE REGRESSION GUARD. The menu entry must resolve to a screen that offers
  /// token creation. This is the assertion whose absence let create/mint/burn
  /// ship unreachable.
  it('is the screen the TOKENS menu routes to, and it offers creation', async () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../../AppContent.tsx'),
      'utf8',
    );
    const match = src.match(/TOKENS:\s*\(\)\s*=>\s*navigate\('([a-z]+)'\)/);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('accounts'); // this file's screen

    render(<AccountsScreen />);
    expect(
      await screen.findByRole('button', { name: /create token/i }),
    ).toBeInTheDocument();
  });

  it('opens the creation wizard when create is pressed', async () => {
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByRole('button', { name: /create token/i }));
    expect(await screen.findByTestId('create-dialog')).toBeInTheDocument();
  });

  it('exposes MINT and BURN on a token this device created', async () => {
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    expect(await screen.findByRole('button', { name: /^MINT$/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^BURN$/ })).toBeInTheDocument();
  });

  /// Protocol-defined assets are not user-mintable, so they must not offer the
  /// controls at all.
  it('offers no supply actions on protocol tokens', async () => {
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('ERA'));
    expect(screen.queryByRole('button', { name: /^MINT$/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /^BURN$/ })).toBeNull();
  });

  /// The typed amount reaches Rust unchanged — no client-side rescaling.
  it('sends the entered amount verbatim to mint', async () => {
    (mintToken as jest.Mock).mockResolvedValue({ success: true });
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    fireEvent.click(await screen.findByRole('button', { name: /^MINT$/ }));
    fireEvent.change(screen.getByPlaceholderText('0'), { target: { value: '250' } });
    fireEvent.click(screen.getByRole('button', { name: /CONFIRM/i }));

    await waitFor(() =>
      expect(mintToken).toHaveBeenCalledWith(
        expect.objectContaining({ tokenId: 'MYTOK', amount: '250' }),
      ),
    );
  });

  it('sends the entered amount verbatim to burn', async () => {
    (burnToken as jest.Mock).mockResolvedValue({ success: true });
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    fireEvent.click(await screen.findByRole('button', { name: /^BURN$/ }));
    fireEvent.change(screen.getByPlaceholderText('0'), { target: { value: '40' } });
    fireEvent.click(screen.getByRole('button', { name: /CONFIRM/i }));

    await waitFor(() =>
      expect(burnToken).toHaveBeenCalledWith(
        expect.objectContaining({ tokenId: 'MYTOK', amount: '40' }),
      ),
    );
  });

  /// A policy refusal is the committed policy's decision and is shown as-is.
  it('surfaces a policy refusal verbatim', async () => {
    (mintToken as jest.Mock).mockResolvedValue({
      success: false,
      message: 'Mint would exceed the token’s maximum supply',
    });
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    fireEvent.click(await screen.findByRole('button', { name: /^MINT$/ }));
    fireEvent.change(screen.getByPlaceholderText('0'), { target: { value: '999999' } });
    fireEvent.click(screen.getByRole('button', { name: /CONFIRM/i }));

    expect(await screen.findByText(/maximum supply/i)).toBeInTheDocument();
  });

  /// (2) A successful adoption must appear in the list WITHOUT navigation or
  /// restart, and the list must come from the persisted registry rather than
  /// an optimistic row. On device the add succeeded in canonical state while
  /// the screen showed nothing, which is indistinguishable from failure.
  it('shows an adopted token immediately, reloaded from persisted state', async () => {
    const { dsmClient } = require('../../../services/dsmClient');
    (addTokenByAnchor as jest.Mock).mockImplementation(async () => {
      // Rust persisted it; the next registry read is what must reveal it.
      (dsmClient.getAllBalances as jest.Mock).mockResolvedValue([
        ...balances,
        { tokenId: 'RIGB', symbol: 'RIGB', balance: '0' },
      ]);
      return { success: true, ticker: 'RIGB', tokenId: 'Z68HWMYS' };
    });

    render(<AccountsScreen />);
    fireEvent.click(await screen.findByRole('button', { name: /add token/i }));
    fireEvent.change(screen.getByPlaceholderText('CPTA policy anchor'), {
      target: { value: '6PW31E7DEMNDVC11F88XTR9J9X90M90MF6M02JPV5BFRQE773BJ0' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^ADD$/ }));

    // Visible in the list, with no navigation in between.
    expect(await screen.findByText('RIGB')).toBeInTheDocument();
  });

  /// The acknowledgement must be durable and carry the identifiers a user needs
  /// to check against the creating device.
  it('shows a durable success panel with ticker, token id and anchor', async () => {
    const ANCHOR = '6PW31E7DEMNDVC11F88XTR9J9X90M90MF6M02JPV5BFRQE773BJ0';
    (addTokenByAnchor as jest.Mock).mockResolvedValue({
      success: true, ticker: 'RIGB', tokenId: 'Z68HWMYSPT9B',
    });
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByRole('button', { name: /add token/i }));
    fireEvent.change(screen.getByPlaceholderText('CPTA policy anchor'), {
      target: { value: ANCHOR },
    });
    fireEvent.click(screen.getByRole('button', { name: /^ADD$/ }));

    expect(await screen.findByText(/RIGB added/)).toBeInTheDocument();
    expect(screen.getByText('Z68HWMYSPT9B')).toBeInTheDocument();
    expect(screen.getByText(ANCHOR)).toBeInTheDocument();
  });

  /// Typed refusals reach the user as written by Rust.
  it('surfaces typed adoption errors verbatim', async () => {
    (addTokenByAnchor as jest.Mock).mockResolvedValue({
      success: false,
      error: 'TICKER_CONFLICT: RIGB is already held by a different token on this device',
    });
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByRole('button', { name: /add token/i }));
    fireEvent.change(screen.getByPlaceholderText('CPTA policy anchor'), {
      target: { value: 'ZZZZ' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^ADD$/ }));

    expect(await screen.findByText(/TICKER_CONFLICT/)).toBeInTheDocument();
  });
});
