// SPDX-License-Identifier: Apache-2.0
//! A money form must never choose the recipient for you.
//!
//! The send form defaulted to `contacts[0].deviceId`, and when the selected
//! contact was not found it SUBSTITUTED `contacts[0]` again. On the rig the
//! contact list reordered between renders, so a transfer aimed at D3 came back
//! aimed at 9FF with nothing on screen to say so. Silently retargeting a
//! transfer at a different device is the one failure a send form must not have.
//!
//! Selection is keyed by deviceId — reordering alone can never disturb it — and
//! there is no default and no substitute: a missing contact clears the choice
//! and disables Send.

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';

import SendTab from '../SendTab';

const D3 = { deviceId: 'NJ2C7P4CXGNY59', alias: 'nj2c7p4c' } as any;
const NFF = { deviceId: 'RXDC8XQMZ7JHAB', alias: 'rxdc8xqm' } as any;

const baseProps = (contacts: any[]) =>
  ({
    contacts,
    balances: [{ tokenId: 'RIGB', symbol: 'RIGB', balance: '1000' }],
    onSend: jest.fn(),
    setError: jest.fn(),
  }) as any;

describe('SendTab recipient selection', () => {
  /// A fresh form has NO recipient, and Send cannot be pressed.
  it('starts with no recipient and Send disabled', () => {
    render(<SendTab {...baseProps([D3, NFF])} />);
    expect(screen.getByTestId('send-recipient-confirm')).toHaveTextContent(
      /select a recipient/i,
    );
    expect(screen.getByRole('button', { name: /^send$/i })).toBeDisabled();
  });

  /// THE REGRESSION. Reordering [D3, 9FF] -> [9FF, D3] must not move the
  /// selection: it is keyed by device id, not position.
  it('keeps the selected device id when contacts reorder', () => {
    const { rerender } = render(<SendTab {...baseProps([D3, NFF])} />);

    const select = screen.getByLabelText(/recipient/i) as HTMLSelectElement;
    fireEvent.change(select, { target: { value: D3.deviceId } });
    expect(screen.getByTestId('send-recipient-confirm')).toHaveTextContent(
      D3.deviceId.slice(0, 8),
    );

    // Same contacts, opposite order — exactly what happened on the rig.
    rerender(<SendTab {...baseProps([NFF, D3])} />);

    expect(screen.getByTestId('send-recipient-confirm')).toHaveTextContent(
      D3.deviceId.slice(0, 8),
    );
    expect((screen.getByLabelText(/recipient/i) as HTMLSelectElement).value).toBe(
      D3.deviceId,
    );
  });

  /// If the chosen contact disappears, clear it — never fall through to
  /// whoever is now first.
  it('clears the selection when the chosen contact disappears', () => {
    const { rerender } = render(<SendTab {...baseProps([D3, NFF])} />);
    fireEvent.change(screen.getByLabelText(/recipient/i), {
      target: { value: D3.deviceId },
    });

    rerender(<SendTab {...baseProps([NFF])} />); // D3 gone

    expect(screen.getByTestId('send-recipient-confirm')).toHaveTextContent(
      /select a recipient/i,
    );
    expect(screen.getByRole('button', { name: /^send$/i })).toBeDisabled();
  });

  /// The recipient is shown, by device id, right above the action.
  it('shows the selected device id above Send', () => {
    render(<SendTab {...baseProps([D3, NFF])} />);
    fireEvent.change(screen.getByLabelText(/recipient/i), {
      target: { value: NFF.deviceId },
    });
    expect(screen.getByTestId('send-recipient-confirm')).toHaveTextContent(
      NFF.deviceId.slice(0, 8),
    );
    expect(screen.getByRole('button', { name: /^send$/i })).toBeEnabled();
  });
});
