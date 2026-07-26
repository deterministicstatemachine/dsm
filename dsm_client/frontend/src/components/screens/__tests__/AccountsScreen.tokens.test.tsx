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
import { mintToken, burnToken } from '../../../dsm/policies';

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
});
