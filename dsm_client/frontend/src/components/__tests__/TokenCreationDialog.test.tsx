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

jest.mock('@/dsm/policies', () => ({
  ...jest.requireActual('@/dsm/policies'),
  getTokenCreationFee: jest.fn(),
}));

import { readImageRgba } from '../../utils/imageRgba';
import { getTokenCreationFee } from '@/dsm/policies';

describe('TokenCreationDialog token kind selector', () => {
  // Fungible is the only kind the protocol enforces. NFT and SBT are not
  // hidden behind a disabled control — they are deleted, because offering a
  // kind whose semantics nothing enforces is a promise the state machine
  // cannot keep.
  it('offers only the fungible token kind', () => {
    render(<TokenCreationDialog onClose={jest.fn()} />);

    const fungible = screen.getByRole('button', { name: /FUNGIBLE/i });
    expect(fungible).toHaveAttribute('aria-pressed', 'true');

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


describe('TokenCreationDialog creation fee', () => {
  const standing = (eraHeld: bigint, feeCovered: boolean) => ({ feeEra: 10n, eraHeld, feeCovered });

  async function toReview() {
    fireEvent.change(screen.getByLabelText(/Ticker/i), { target: { value: 'ART' } });
    fireEvent.change(screen.getByLabelText(/Display Name/i), { target: { value: 'Artwork' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue/i }));
    fireEvent.click(screen.getByRole('button', { name: /Continue/i }));
    await screen.findByText('10 ERA (burned)');
  }

  beforeEach(() => {
    (getTokenCreationFee as jest.Mock).mockReset();
  });

  // A fresh wallet used to fill in every step and learn only at Publish that
  // it held no ERA for the fee.
  it("shows the ERA held beside the fee, and a claim from the faucet keeps what was entered", async () => {
    (getTokenCreationFee as jest.Mock)
      .mockResolvedValueOnce(standing(0n, false))
      .mockResolvedValueOnce(standing(100n, true));
    const claimEra = jest.fn().mockResolvedValue('Released 100 ERA from the reserve');
    render(<TokenCreationDialog onClose={jest.fn()} claimEra={claimEra} />);
    await toReview();

    expect(screen.getByText('0 ERA')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Publishing burns 10 ERA and you hold 0.');
    fireEvent.click(screen.getByRole('button', { name: 'Claim ERA' }));

    expect(await screen.findByText('Released 100 ERA from the reserve')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('100 ERA')).toBeInTheDocument());
    expect(claimEra).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Claim ERA' })).toBeNull();
    // Still the review of what was entered, ready to publish.
    expect(screen.getByText('ART')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Publish' })).toBeEnabled();
  });

  it('offers no claim when the ERA held pays the fee', async () => {
    (getTokenCreationFee as jest.Mock).mockResolvedValue(standing(100n, true));
    render(<TokenCreationDialog onClose={jest.fn()} claimEra={jest.fn()} />);
    await toReview();

    expect(screen.getByText('100 ERA')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Claim ERA' })).toBeNull();
    expect(screen.queryByText(/Publishing burns/)).toBeNull();
  });

  it('points at the Tokens screen where the wizard has no faucet of its own', async () => {
    (getTokenCreationFee as jest.Mock).mockResolvedValue(standing(3n, false));
    render(<TokenCreationDialog onClose={jest.fn()} />);
    await toReview();

    expect(screen.getByRole('status')).toHaveTextContent(
      'Publishing burns 10 ERA and you hold 3. Claim ERA from the faucet on the Tokens screen first.',
    );
    expect(screen.queryByRole('button', { name: 'Claim ERA' })).toBeNull();
  });

  it('shows a refused claim and leaves the review as it was', async () => {
    (getTokenCreationFee as jest.Mock).mockResolvedValue(standing(0n, false));
    const claimEra = jest.fn().mockRejectedValue(new Error('faucet.claim: the reserve is spent'));
    render(<TokenCreationDialog onClose={jest.fn()} claimEra={claimEra} />);
    await toReview();

    fireEvent.click(screen.getByRole('button', { name: 'Claim ERA' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('faucet.claim: the reserve is spent');
    expect(screen.getByText('0 ERA')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Claim ERA' })).toBeEnabled();
  });
});
