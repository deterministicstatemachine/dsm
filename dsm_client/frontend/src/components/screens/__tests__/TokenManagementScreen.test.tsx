// SPDX-License-Identifier: Apache-2.0
//! The Tokens screen must actually let a user manage tokens.
//!
//! It previously showed a read-only list with tabs (My Tokens / Scan / Faucet)
//! and no way to create, mint or burn anything — creating a token was reachable
//! only through Settings → "Policy Tools", a developer screen named after the
//! mechanism rather than the goal. These tests pin the product flow so it
//! cannot silently regress into a read-only viewer again.

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

jest.mock('../../../dsm/policies', () => ({
  mintToken: jest.fn(),
  burnToken: jest.fn(),
  getTokenCreationFeeEra: jest.fn().mockResolvedValue(10n),
}));

jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    listPolicies: jest.fn().mockResolvedValue([]),
  },
}));

jest.mock('../../qr/QRCodeScannerPanel', () => ({
  __esModule: true,
  default: () => <div data-testid="scanner" />,
}));

jest.mock('../EraFaucetScreen', () => ({
  __esModule: true,
  default: () => <div data-testid="faucet" />,
}));

jest.mock('../../../services/policy/policyDisplayService', () => ({
  mapPoliciesToDisplayEntries: () => [
    {
      key: 'mine',
      label: 'MYTOK',
      ticker: 'MYTOK',
      alias: 'My Token',
      decimals: 0,
      maxSupply: '1000',
      cptaType: 'CPTA TOKEN',
      cptaAnchorId: 'ANCHOR1',
      cptaAnchorFull: 'ANCHORFULL',
      builtIn: false,
    },
  ],
}));

jest.mock('../../../services/policy/policyScanService', () => ({
  importTokenPolicyFromScanData: jest.fn(),
}));

import TokenManagementScreen from '../TokenManagementScreen';
import { mintToken, burnToken } from '../../../dsm/policies';

describe('TokenManagementScreen', () => {
  beforeEach(() => jest.clearAllMocks());

  /// Creating a token must be reachable from the screen a user opens to manage
  /// tokens — not only from a developer screen buried in Settings.
  it('offers token creation directly on the Tokens screen', async () => {
    render(<TokenManagementScreen />);
    expect(
      await screen.findByRole('button', { name: /CREATE TOKEN/i }),
    ).toBeInTheDocument();
  });

  /// Tokens the user created expose supply actions; the routes existed with no
  /// UI calling them at all until this.
  it('exposes MINT and BURN on a user-created token', async () => {
    render(<TokenManagementScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));

    expect(await screen.findByRole('button', { name: /^MINT$/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^BURN$/ })).toBeInTheDocument();
  });

  /// The amount the user types is what gets sent — no client-side re-scaling,
  /// and no pre-judging whether the policy will allow it.
  it('sends the entered amount to the mint route', async () => {
    (mintToken as jest.Mock).mockResolvedValue({ success: true, message: 'ok' });
    render(<TokenManagementScreen />);
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

  it('sends the entered amount to the burn route', async () => {
    (burnToken as jest.Mock).mockResolvedValue({ success: true, message: 'ok' });
    render(<TokenManagementScreen />);
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

  /// A refusal from the policy (authority, threshold, supply cap) must be shown
  /// to the user verbatim rather than swallowed.
  it('surfaces a policy refusal to the user', async () => {
    (mintToken as jest.Mock).mockResolvedValue({
      success: false,
      message: 'Mint would exceed the token’s maximum supply',
    });
    render(<TokenManagementScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    fireEvent.click(await screen.findByRole('button', { name: /^MINT$/ }));
    fireEvent.change(screen.getByPlaceholderText('0'), { target: { value: '999999' } });
    fireEvent.click(screen.getByRole('button', { name: /CONFIRM/i }));

    expect(await screen.findByText(/maximum supply/i)).toBeInTheDocument();
  });

  /// Builtin protocol tokens are not user-mintable, so they must not offer the
  /// controls at all.
  it('does not offer supply actions on builtin tokens', async () => {
    render(<TokenManagementScreen />);
    fireEvent.click(await screen.findByText('ERA'));
    expect(screen.queryByRole('button', { name: /^MINT$/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /^BURN$/ })).toBeNull();
  });
});
