// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { TokenCreationDialog } from '../TokenCreationDialog';

jest.mock('@/services/dsmClient', () => ({
  dsmClient: {
    createToken: jest.fn(),
  },
}));

describe('TokenCreationDialog token kind selector', () => {
  // Fungible is the only kind the protocol enforces. NFT and SBT are not
  // hidden behind a disabled control — they are deleted, because offering a
  // kind whose semantics nothing enforces is a promise the state machine
  // cannot keep.
  it('offers only the fungible token kind', () => {
    render(<TokenCreationDialog onClose={jest.fn()} />);

    const fungible = screen.getByRole('button', { name: /FUNGIBLE/i });
    expect(fungible).toHaveAttribute('aria-pressed', 'true');
    expect(fungible.className).toContain('tcd-kind-btn--active');

    expect(screen.queryByRole('button', { name: /^NFT$/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /^SBT$/i })).toBeNull();
  });

  it('does not show a transferable toggle on the rules step', () => {
    render(<TokenCreationDialog onClose={jest.fn()} />);

    fireEvent.change(screen.getByLabelText(/Ticker/i), { target: { value: 'ART' } });
    fireEvent.change(screen.getByLabelText(/Display Name/i), { target: { value: 'Artwork' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue/i }));

    expect(screen.queryByText(/^Transferable$/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/tcd-transferable/i)).not.toBeInTheDocument();
  });
});
