// SPDX-License-Identifier: Apache-2.0
//! A send form offers only what the wallet holds, as Rust reported it.
//!
//! With no balances the form used to offer ERA at a balance of 0 — a row Rust
//! never reported — and every label fell back to ERA when nothing was chosen.

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';

import SendTab from '../SendTab';

import type { DomainContact } from '../../../../domain/types';

/** A contact as contacts.list answers one: its genesis named, so verified, and the tokens it can be sent. */
function contact(deviceId: string, alias: string, sendableTokenIds: string[]): DomainContact {
  const genesisHash = `G-${alias}`;
  return { alias, deviceId, genesisHash, pairing: 'idle', relationship: 'established', genesisVerifiedOnline: genesisHash.length > 2, signingPublicKey: `K-${alias}`, sendableTokenIds };
}

const D3 = contact('NJ2C7P4CXGNY59', 'nj2c7p4c', ['ERA', 'RIGB']);
// A contact that has added no token of its own: it can be sent the protocol's assets only.
const PLAIN = contact('RXDC8XQMZ7JHAB', 'rxdc8xqm', ['ERA']);

const props = (balances: any[]) =>
  ({
    contacts: [D3, PLAIN],
    balances,
    onCancel: jest.fn(),
    onSendComplete: jest.fn(),
    loadWalletData: jest.fn(),
    setError: jest.fn(),
  }) as any;

describe('SendTab tokens', () => {
  it('with no balances offers no token and cannot send', () => {
    render(<SendTab {...props([])} />);
    fireEvent.change(screen.getByLabelText(/recipient/i), { target: { value: D3.deviceId } });

    expect(screen.getByText('No balances to send yet.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Amount')).toBeNull();
    expect(screen.queryByText(/ERA/)).toBeNull();
    expect(screen.getByRole('button', { name: /^send$/i })).toBeDisabled();
  });

  it('shows the selected token and its balance as Rust rendered them', () => {
    render(
      <SendTab
        {...props([{ tokenId: 'RIGB', symbol: 'RIGB', baseUnits: 100000n, displayAmount: '1000.00', decimals: 2 }])}
      />,
    );

    expect(screen.getByText('1000.00')).toBeInTheDocument();
    expect(screen.getByLabelText('Amount')).toHaveAttribute('step', '0.01');
    expect(screen.queryByText(/ERA/)).toBeNull();
  });
  // A contact credits only a token it has added, so the dropdown lists only
  // the tokens Rust says the chosen contact can be sent (owner, 2026-11-21).
  // Before a recipient is chosen it lists what the wallet holds.
  it('offers the chosen recipient only the tokens it can be sent', () => {
    const held = [
      { tokenId: 'ERA', symbol: 'ERA', baseUnits: 1000n, displayAmount: '10.00', decimals: 2 },
      { tokenId: 'RIGB', symbol: 'RIGB', baseUnits: 100000n, displayAmount: '1000.00', decimals: 2 },
    ];
    const offered = () => {
      fireEvent.click(screen.getByRole('button', { name: /token/i }));
      const tickers = screen.getAllByRole('option').map((o) => o.textContent?.trim());
      fireEvent.click(screen.getByRole('button', { name: /token/i }));
      return tickers.filter((t) => t === 'ERA' || t === 'RIGB');
    };
    render(<SendTab {...props(held)} />);
    expect(offered()).toEqual(['ERA', 'RIGB']);

    fireEvent.change(screen.getByLabelText(/recipient/i), { target: { value: PLAIN.deviceId } });
    expect(offered()).toEqual(['ERA']);

    fireEvent.change(screen.getByLabelText(/recipient/i), { target: { value: D3.deviceId } });
    expect(offered()).toEqual(['ERA', 'RIGB']);
  });

  // A token held at zero is not offered (owner, 2026-11-22): there is nothing
  // of it to send. An online send spends the balance. An offline send spends
  // the offline allocation, which is unknown, not zero, until the appliance
  // has stated it: a token whose allocation is not yet known stays on offer
  // offline, and one whose allocation is known to be zero does not.
  it('does not offer a token there is nothing of to send', () => {
    const held = [
      { tokenId: 'ERA', symbol: 'ERA', baseUnits: 1000n, displayAmount: '10.00', decimals: 2, offline: { baseUnits: 0n, displayAmount: '0.00' } },
      { tokenId: 'RIGB', symbol: 'RIGB', baseUnits: 0n, displayAmount: '0.00', decimals: 2, offline: { baseUnits: 500n, displayAmount: '5.00' } },
      { tokenId: 'NONE', symbol: 'NONE', baseUnits: 0n, displayAmount: '0.00', decimals: 2 },
    ];
    const offered = () => {
      const pick = screen.queryByRole('button', { name: /token/i });
      if (pick === null) return [];
      fireEvent.click(pick);
      const tickers = screen.getAllByRole('option').map((o) => o.textContent?.trim());
      fireEvent.click(pick);
      return tickers.filter((t) => t === 'ERA' || t === 'RIGB' || t === 'NONE');
    };
    render(<SendTab {...props(held)} />);
    expect(offered()).toEqual(['ERA']);

    fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    expect(offered()).toEqual(['RIGB', 'NONE']);
  });
});
