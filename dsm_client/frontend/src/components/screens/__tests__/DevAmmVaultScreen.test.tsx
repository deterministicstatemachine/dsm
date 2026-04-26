import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DevAmmVaultScreen from '../DevAmmVaultScreen';

jest.mock('../../../dsm/amm', () => ({
  createAmmVault: jest.fn(),
  encodeAmmConstantProductFulfillment: jest.fn(),
  encodeBase32Crockford: jest.fn(),
}));

jest.mock('../../../dsm/route_commit', () => ({
  publishRoutingAdvertisement: jest.fn(),
}));

import { createAmmVault } from '../../../dsm/amm';
import { publishRoutingAdvertisement } from '../../../dsm/route_commit';
import { encodeBase32Crockford } from '../../../utils/textId';

describe('DevAmmVaultScreen', () => {
  beforeEach(() => jest.clearAllMocks());

  test('renders default pair + reserves + fee inputs', () => {
    render(<DevAmmVaultScreen />);
    expect(screen.getByDisplayValue('DEMO_AAA')).toBeInTheDocument();
    expect(screen.getByDisplayValue('DEMO_BBB')).toBeInTheDocument();
    expect(screen.getAllByDisplayValue('1000000').length).toBeGreaterThan(0);
    expect(screen.getByDisplayValue('30')).toBeInTheDocument();
  });

  test('rejects create when policy anchor missing', async () => {
    render(<DevAmmVaultScreen />);
    const createBtn = screen.getByText(/Create AMM vault/i) as HTMLButtonElement;
    expect(createBtn.disabled).toBe(true);
  });

  test('rejects create when pair not lex-canonical', () => {
    render(<DevAmmVaultScreen />);
    const tokenAInput = screen.getByDisplayValue('DEMO_AAA') as HTMLInputElement;
    fireEvent.change(tokenAInput, { target: { value: 'ZZZZ' } });
    expect(
      screen.getByText(/lex-lower than tokenB/i),
    ).toBeInTheDocument();
  });

  test('calls createAmmVault with parsed inputs on Create click', async () => {
    (createAmmVault as jest.Mock).mockResolvedValue({
      success: true,
      vaultIdBase32: 'NEWVAULTBASE32',
    });
    render(<DevAmmVaultScreen />);
    // Provide a 32-byte Base32 anchor so the button enables.
    const anchor = encodeBase32Crockford(new Uint8Array(32).fill(0xAA));
    const anchorInput = screen.getByPlaceholderText(/Base32 Crockford/i) as HTMLInputElement;
    fireEvent.change(anchorInput, { target: { value: anchor } });

    const createBtn = await screen.findByText(/Create AMM vault/i);
    fireEvent.click(createBtn);
    await waitFor(() => expect(createAmmVault).toHaveBeenCalledTimes(1));
    const arg = (createAmmVault as jest.Mock).mock.calls[0][0];
    expect(arg.feeBps).toBe(30);
    expect(arg.reserveA).toBe(1000000n);
    expect(arg.reserveB).toBe(1000000n);
    expect(arg.policyDigest.length).toBe(32);
    // JSDOM Uint8Array instanceof is realm-flaky; check shape.
    expect(typeof arg.tokenA?.length).toBe('number');
    expect(typeof arg.tokenB?.length).toBe('number');
    await waitFor(() =>
      expect(screen.getByText(/Vault created/i)).toBeInTheDocument(),
    );
  });

  test('surfaces vault creation failure verbatim', async () => {
    (createAmmVault as jest.Mock).mockResolvedValue({
      success: false,
      error: 'wallet locked',
    });
    render(<DevAmmVaultScreen />);
    const anchor = encodeBase32Crockford(new Uint8Array(32).fill(0xBB));
    const anchorInput = screen.getByPlaceholderText(/Base32 Crockford/i) as HTMLInputElement;
    fireEvent.change(anchorInput, { target: { value: anchor } });
    const createBtn = await screen.findByText(/Create AMM vault/i);
    fireEvent.click(createBtn);
    await waitFor(() =>
      expect(screen.getByText(/wallet locked/i)).toBeInTheDocument(),
    );
  });

  test('Publish routing ad disabled until a vault has been created', () => {
    render(<DevAmmVaultScreen />);
    const pubBtn = screen.getByText(/Publish routing ad/i) as HTMLButtonElement;
    expect(pubBtn.disabled).toBe(true);
  });

  test('publishes routing ad after a vault is created', async () => {
    (createAmmVault as jest.Mock).mockResolvedValue({
      success: true,
      vaultIdBase32: encodeBase32Crockford(new Uint8Array(32).fill(0x77)),
    });
    (publishRoutingAdvertisement as jest.Mock).mockResolvedValue({
      success: true,
      vaultIdBase32: encodeBase32Crockford(new Uint8Array(32).fill(0x77)),
    });

    render(<DevAmmVaultScreen />);
    const anchor = encodeBase32Crockford(new Uint8Array(32).fill(0xCC));
    const anchorInput = screen.getByPlaceholderText(/Base32 Crockford/i) as HTMLInputElement;
    fireEvent.change(anchorInput, { target: { value: anchor } });

    fireEvent.click(await screen.findByText(/Create AMM vault/i));
    await waitFor(() => expect(createAmmVault).toHaveBeenCalled());

    const pubBtn = await screen.findByText(/Publish routing ad/i);
    await waitFor(() => expect((pubBtn as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(pubBtn);
    await waitFor(() => expect(publishRoutingAdvertisement).toHaveBeenCalledTimes(1));
  });
});
