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
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { dsmClient } from '../../../services/dsmClient';

const MYTOK_ANCHOR = 'KYGP1FMF3X0QV4DXYQ4E5NZ1JVT9C9CW549NNZPXGC4SDD3MDHDG';

const balances = [
  { tokenId: 'ERA', symbol: 'ERA', balance: '264', policyAnchorB32: 'ERAANCHOR0000', anchorFingerprint: 'ERAANCHO' },
  {
    tokenId: 'MYTOK',
    symbol: 'MYTOK',
    balance: '500',
    canonicalTokenId: 'QMK5SY91DSJDY8KHAP6CCTWW80X7GHTVKFZ0KXTHAGQSTMFGV3GG',
    policyAnchorB32: MYTOK_ANCHOR,
    anchorFingerprint: MYTOK_ANCHOR.slice(0, 8),
  },
];

jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    getAllBalances: jest.fn(() => Promise.resolve(balances)),
    claimFaucet: jest.fn(),
  },
}));

jest.mock('../../../dsm/policies', () => ({
  mintToken: jest.fn(),
  burnToken: jest.fn(),
  addTokenByAnchor: jest.fn(),
  forgetToken: jest.fn(),
  tokenAdoptionQr: jest.fn().mockResolvedValue({
    uri: 'dsm:token/v1:PAYLOAD',
    ticker: 'MYTOK',
    tokenId: 'MYTOK',
    policyAnchorB32: MYTOK_ANCHOR,
    anchorFingerprint: MYTOK_ANCHOR.slice(0, 8),
  }),
}));

jest.mock('qrcode', () => ({
  __esModule: true,
  default: { toDataURL: jest.fn().mockResolvedValue('data:image/png;base64,QR') },
}));

const mockCopyText = jest.fn().mockResolvedValue(true);
jest.mock('../../../utils/anchorDisplay', () => ({
  copyText: (...a: unknown[]) => mockCopyText(...a),
  shortId: () => '',
  prettyAnchor: () => '',
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
import { mintToken, burnToken, addTokenByAnchor, forgetToken, tokenAdoptionQr } from '../../../dsm/policies';

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

  /// THE GAP THIS CLOSES. A device that ADOPTS a token is shown its anchor on
  /// the confirmation card; the device that CREATED it was shown nothing,
  /// anywhere. Handing the token to a peer therefore meant reading the registry
  /// off-device and encoding the commit by hand — and a hand-rolled Base32 pads
  /// the wrong group, yielding an anchor that resolves to nothing.
  it('shows a created token\'s CPTA anchor, id and fingerprint', async () => {
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    const panel = await screen.findByTestId('token-identity');
    expect(within(panel).getByText(MYTOK_ANCHOR)).toBeInTheDocument();
    expect(within(panel).getByText(MYTOK_ANCHOR.slice(0, 8))).toBeInTheDocument();
    expect(within(panel).getByText('Token ID')).toBeInTheDocument();
    expect(within(panel).getByText('Policy Anchor (CPTA)')).toBeInTheDocument();
    // Scoped to the panel on purpose: the adoption success card renders the
    // same 'Token ID' label, so an unscoped query is ambiguous once both are
    // on screen.
    // The real token id, not the ticker: a ticker is not an identity, and two
    // different tokens can claim the same one.
    expect(
      within(panel).getByText('QMK5SY91DSJDY8KHAP6CCTWW80X7GHTVKFZ0KXTHAGQSTMFGV3GG'),
    ).toBeInTheDocument();
  });

  /// The anchor is 52 characters. Retyping it is how transcription errors get
  /// in, so it has to be copyable.
  it('copies the anchor rather than making the user retype it', async () => {
    mockCopyText.mockClear();
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    fireEvent.click(await screen.findByRole('button', { name: /copy anchor/i }));
    await waitFor(() => expect(mockCopyText).toHaveBeenCalledWith(MYTOK_ANCHOR));
  });

  /// Rust assembles the adoption URI; this screen renders whatever it returns
  /// and never builds a payload of its own.
  it('renders a scannable code built by Rust', async () => {
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    const img = await screen.findByAltText(/adoption code for MYTOK/i);
    expect(img).toHaveAttribute('src', 'data:image/png;base64,QR');
    expect(tokenAdoptionQr).toHaveBeenCalledWith('MYTOK');
  });

  /// A protocol asset already exists on every device, so there is nothing to
  /// hand over and no code to scan.
  it('offers no adoption code for a protocol token', async () => {
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('ERA'));
    expect(screen.queryByRole('button', { name: /copy anchor/i })).toBeNull();
    expect(screen.queryByAltText(/adoption code/i)).toBeNull();
  });

  /// A device that has adopted a token cannot adopt a different token with the
  /// same ticker, so a superseded token blocks its own ticker. The only way out
  /// is to drop the identity, and that has to be reachable from the screen the
  /// user is already looking at — a route with no control is a dead end.
  it('offers FORGET on a token this device holds, and calls it by token id', async () => {
    (forgetToken as jest.Mock).mockResolvedValue({ success: true, message: 'MYTOK forgotten' });
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    fireEvent.click(await screen.findByRole('button', { name: /^FORGET$/ }));
    await waitFor(() => expect(forgetToken).toHaveBeenCalledWith('MYTOK'));
    confirmSpy.mockRestore();
  });

  /// Forgetting removes a token from this device, so it must not happen on a
  /// stray tap.
  it('does not forget when the confirmation is declined', async () => {
    (forgetToken as jest.Mock).mockClear();
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('MYTOK'));
    fireEvent.click(await screen.findByRole('button', { name: /^FORGET$/ }));
    expect(forgetToken).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  /// Protocol-defined assets are not user-mintable, so they must not offer the
  /// controls at all.
  it('offers no supply actions on protocol tokens', async () => {
    render(<AccountsScreen />);
    fireEvent.click(await screen.findByText('ERA'));
    expect(screen.queryByRole('button', { name: /^MINT$/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /^BURN$/ })).toBeNull();
    // Nor FORGET: a protocol asset is not an adopted identity to drop.
    expect(screen.queryByRole('button', { name: /^FORGET$/ })).toBeNull();
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
  /// The card shows the anchor RUST holds, not the text the user supplied.
  ///
  /// A scanned payload is a `dsm:token/v1:` URI. Echoing that back under the
  /// label "Policy Anchor (CPTA)" teaches the reader that a URI is an anchor —
  /// and the next person they hand it to gets something that resolves to
  /// nothing. So the panel reads the value back off the reloaded registry row.
  it('shows a durable success panel with the anchor from the registry, not the input', async () => {
    const REAL_ANCHOR = '6PW31E7DEMNDVC11F88XTR9J9X90M90MF6M02JPV5BFRQE773BJ0';
    const PASTED_URI = 'dsm:token/v1:SOMEPAYLOADBYTES';
    (addTokenByAnchor as jest.Mock).mockResolvedValue({
      success: true, ticker: 'RIGB', tokenId: 'Z68HWMYSPT9B',
    });
    (dsmClient.getAllBalances as jest.Mock).mockResolvedValue([
      ...balances,
      {
        tokenId: 'RIGB',
        symbol: 'RIGB',
        balance: '0.00',
        canonicalTokenId: 'Z68HWMYSPT9B',
        policyAnchorB32: REAL_ANCHOR,
        anchorFingerprint: REAL_ANCHOR.slice(0, 8),
      },
    ]);

    render(<AccountsScreen />);
    fireEvent.click(await screen.findByRole('button', { name: /add token/i }));
    fireEvent.change(screen.getByPlaceholderText('CPTA policy anchor'), {
      target: { value: PASTED_URI },
    });
    fireEvent.click(screen.getByRole('button', { name: /^ADD$/ }));

    const panel = await screen.findByRole('status');
    expect(within(panel).getByText(/RIGB added/)).toBeInTheDocument();
    expect(within(panel).getByText('Z68HWMYSPT9B')).toBeInTheDocument();
    expect(within(panel).getByText(REAL_ANCHOR)).toBeInTheDocument();
    expect(within(panel).queryByText(PASTED_URI)).toBeNull();
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
