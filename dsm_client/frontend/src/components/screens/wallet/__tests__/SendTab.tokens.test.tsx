// SPDX-License-Identifier: Apache-2.0
//! A send form offers only what the wallet holds, as Rust reported it.
//!
//! With no balances the form used to offer ERA at a balance of 0 — a row Rust
//! never reported — and every label fell back to ERA when nothing was chosen.

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';

import SendTab from '../SendTab';

const D3 = { deviceId: 'NJ2C7P4CXGNY59', alias: 'nj2c7p4c' } as any;

const props = (balances: any[]) =>
  ({
    contacts: [D3],
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
        {...props([{ tokenId: 'RIGB', symbol: 'RIGB', displayAmount: '1000.00', decimals: 2 }])}
      />,
    );

    expect(screen.getByText('1000.00')).toBeInTheDocument();
    expect(screen.getByLabelText('Amount')).toHaveAttribute('step', '0.01');
    expect(screen.queryByText(/ERA/)).toBeNull();
  });
});
