import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { TokenCreationDialog } from '../TokenCreationDialog';

jest.mock('@/services/dsmClient', () => ({
  dsmClient: {
    createToken: jest.fn(),
  },
}));

describe('TokenCreationDialog token kind selector', () => {
  it('keeps a single active token kind selection', () => {
    render(<TokenCreationDialog onClose={jest.fn()} />);

    const fungible = screen.getByRole('button', { name: /FUNGIBLE/i });
    const nft = screen.getByRole('button', { name: /NFT/i });
    const sbt = screen.getByRole('button', { name: /SBT/i });

    expect(fungible).toHaveAttribute('aria-pressed', 'true');
    expect(fungible.className).toContain('tcd-kind-btn--active');

    fireEvent.click(nft);
    expect(nft).toHaveAttribute('aria-pressed', 'true');
    expect(nft.className).toContain('tcd-kind-btn--active');
    expect(fungible).toHaveAttribute('aria-pressed', 'false');

    fireEvent.click(sbt);
    expect(sbt).toHaveAttribute('aria-pressed', 'true');
    expect(sbt.className).toContain('tcd-kind-btn--active');
    expect(nft).toHaveAttribute('aria-pressed', 'false');
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
