// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { TokenCreationDialog } from '../TokenCreationDialog';

jest.mock('@/services/dsmClient', () => ({
  dsmClient: {
    createToken: jest.fn(),
  },
}));

// The coin itself is covered by utils/__tests__/coinArtwork.test.ts; here it only has to be placed.
jest.mock('../TokenCoin', () => ({
  TokenCoin: ({ iconUrl }: { iconUrl?: string }) => <span data-testid="token-coin" data-icon={iconUrl ?? ''} />,
}));

jest.mock('../../utils/imageRgba', () => ({
  readImageRgba: jest.fn(),
}));

import { readImageRgba } from '../../utils/imageRgba';

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

describe('TokenCreationDialog coin artwork', () => {
  const logo = () => {
    const width = 40, height = 40;
    const rgba = new Uint8ClampedArray(width * height * 4);
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const inLogo = x >= 10 && x < 30 && y >= 10 && y < 30;
        rgba.set(inLogo ? [10, 10, 10, 255] : [245, 245, 245, 255], (y * width + x) * 4);
      }
    }
    return { rgba, width, height };
  };

  it('stores an uploaded logo as the canonical silhouette, and can go back to the ticker', async () => {
    (readImageRgba as jest.Mock).mockResolvedValue(logo());
    render(<TokenCreationDialog onClose={jest.fn()} />);

    // The free-form icon URL is gone: a policy's icon is the coin artwork now.
    expect(screen.queryByLabelText(/Icon URL/i)).toBeNull();
    expect(screen.getByTestId('token-coin')).toHaveAttribute('data-icon', '');

    const file = new File([new Uint8Array([1, 2, 3])], 'logo.png', { type: 'image/png' });
    fireEvent.change(screen.getByLabelText(/Coin artwork/i), { target: { files: [file] } });

    await waitFor(() => expect(screen.getByTestId('token-coin').getAttribute('data-icon')).toMatch(/^dsm:coin:v1:[0-9A-HJKMNP-TV-Z]+$/));
    expect(screen.getByLabelText(/Cut out the background instead/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Use the ticker instead/i }));
    expect(screen.getByTestId('token-coin')).toHaveAttribute('data-icon', '');
    expect(screen.queryByRole('button', { name: /Use the ticker instead/i })).toBeNull();
  });

  it('says why an image cannot be used and keeps the ticker coin', async () => {
    (readImageRgba as jest.Mock).mockRejectedValue(new Error('Choose a PNG, JPEG or WebP image.'));
    render(<TokenCreationDialog onClose={jest.fn()} />);

    const file = new File([new Uint8Array([1])], 'logo.gif', { type: 'image/gif' });
    fireEvent.change(screen.getByLabelText(/Coin artwork/i), { target: { files: [file] } });

    expect(await screen.findByRole('alert')).toHaveTextContent('Choose a PNG, JPEG or WebP image.');
    expect(screen.getByTestId('token-coin')).toHaveAttribute('data-icon', '');
  });
});

