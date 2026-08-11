// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import LiquidityScreen from '../LiquidityScreen';
import * as amm from '../../../dsm/amm';
import * as route_commit from '../../../dsm/route_commit';
import * as wallet from '../../../dsm/wallet';
import { encodeBase32Crockford } from '../../../utils/textId';

jest.mock('../../../dsm/amm');
jest.mock('../../../dsm/wallet');
jest.mock('../../../dsm/route_commit');

const mockedBalances = jest.mocked(wallet.getAllBalances);

// The pair is selected from HELD assets, and each option's value is the
// token's CPTA anchor — its identity. The ticker is only the visible label,
// which is why both of these can be called RIGB without colliding.
const ANCHOR_A = encodeBase32Crockford(new Uint8Array(32).fill(0x11));
const ANCHOR_B = encodeBase32Crockford(new Uint8Array(32).fill(0x22));

const HELD = [
  {
    tokenId: 'RIGB',
    ticker: 'RIGB',
    balance: '10',
    baseUnits: 1000n,
    decimals: 2,
    symbol: 'RIGB',
    policyAnchorB32: ANCHOR_A,
    anchorFingerprint: ANCHOR_A.slice(0, 8),
  },
  {
    tokenId: 'RIGB',
    ticker: 'RIGB',
    balance: '20',
    baseUnits: 2000n,
    decimals: 2,
    symbol: 'RIGB',
    policyAnchorB32: ANCHOR_B,
    anchorFingerprint: ANCHOR_B.slice(0, 8),
  },
] as unknown as Awaited<ReturnType<typeof wallet.getAllBalances>>;

const mockedList = jest.mocked(amm.listOwnedAmmVaults);
const mockedCreate = jest.mocked(amm.createAmmVault);
const mockedPublishAd = jest.mocked(route_commit.publishRoutingAdvertisement);

// 32 zero bytes Base32-Crockford-encoded — 52 chars per ceil(256/5).
const ZERO_VAULT_ID_B32 = '0'.repeat(52);

describe('LiquidityScreen', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    mockedBalances.mockResolvedValue(HELD);
  });

  it('renders empty state when no vaults are owned', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/No AMM vaults owned by this wallet/)).toBeInTheDocument());
    expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument();
  });

  it('renders owned vaults with reserves and routing-ad status', async () => {
    mockedList.mockResolvedValue({
      success: true,
      vaults: [
        {
          vaultIdBase32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
          // 32-byte CPTA policy commits — what the wire actually carries. The old
          // fixture used TextEncoder('AAA'), which baked in the very assumption that
          // produced mojibake labels in the real screen.
          tokenA: new Uint8Array(32).fill(0xa1),
          tokenB: new Uint8Array(32).fill(0xb2),
          tokenATicker: 'AAA',
          tokenBTicker: 'BBB',
          reserveA: 1000n,
          reserveB: 2000n,
          feeBps: 30,
          advertisedStateNumber: 3n,
          routingAdvertised: true,
          anchorSequence: 0n,
          anchorEnforcement: 'required' as const,
        },
      ],
    });
    render(<LiquidityScreen />);
    // The label comes from the Rust-resolved ticker fields, NOT from decoding the
    // commit bytes. This assertion used to pass for the wrong reason: the fixture
    // supplied TextEncoder('AAA') as `tokenA` and the screen UTF-8-decoded it, so a
    // green test coexisted with mojibake on real data, where `tokenA` is a 32-byte
    // digest. The fixture now carries a real commit, so only the ticker field can
    // produce this text.
    await waitFor(() => expect(screen.getByText(/AAA \/ BBB/)).toBeInTheDocument());
    // And the commit bytes must never reach the DOM as text.
    expect(screen.queryByText(/\uFFFD/)).toBeNull();
    expect(screen.getByText(/fee 30 bps/)).toBeInTheDocument();
    expect(screen.getByText(/reserves: 1000 \/ 2000/)).toBeInTheDocument();
    expect(screen.getByText(/ad: ✓ seq=3/)).toBeInTheDocument();
  });

  it('rejects a wrong-length policy anchor at create-time', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /\+ Create vault/ }));
    fireEvent.change(screen.getByLabelText(/Token A/), { target: { value: ANCHOR_A } });
    fireEvent.change(screen.getByLabelText(/Token B/), { target: { value: ANCHOR_B } });
    fireEvent.change(screen.getByLabelText(/^Reserve A$/), { target: { value: '1000' } });
    fireEvent.change(screen.getByLabelText(/^Reserve B$/), { target: { value: '2000' } });
    fireEvent.change(screen.getByLabelText(/Policy anchor/), { target: { value: 'TOOSHORT' } });
    fireEvent.click(screen.getByRole('button', { name: /^Create$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));

    await waitFor(() => expect(screen.getByText(/policy anchor must decode to 32 bytes/)).toBeInTheDocument());
    expect(mockedCreate).not.toHaveBeenCalled();
  });

  /// REQUIRED PROOF: two assets sharing a ticker stay distinguishable through
  /// the UI, and the identity sent is the one selected — not the name shown.
  ///
  /// Both holdings are called RIGB. Under free-text entry they were the same
  /// asset, and a vault "RIGB/RIGB" was indistinguishable from a real market.
  it('sends the selected identity, not the shared ticker', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    mockedCreate.mockResolvedValue({ success: true, vaultIdBase32: ZERO_VAULT_ID_B32 });
    mockedPublishAd.mockResolvedValue({ success: true });
    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /\+ Create vault/ }));

    // Both options read "RIGB"; they differ only by anchor.
    fireEvent.change(screen.getByLabelText(/Token A/), { target: { value: ANCHOR_A } });
    fireEvent.change(screen.getByLabelText(/Token B/), { target: { value: ANCHOR_B } });
    fireEvent.change(screen.getByLabelText(/^Reserve A$/), { target: { value: '1000' } });
    fireEvent.change(screen.getByLabelText(/^Reserve B$/), { target: { value: '2000' } });
    fireEvent.change(screen.getByLabelText(/Policy anchor/), {
      target: { value: ANCHOR_A },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Create$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));

    await waitFor(() => expect(mockedCreate).toHaveBeenCalled());
    const arg = mockedCreate.mock.calls[0][0];
    expect(arg.tokenA.length).toBe(32);
    expect(arg.tokenB.length).toBe(32);
    expect(Array.from(arg.tokenA)).toEqual(Array.from(new Uint8Array(32).fill(0x11)));
    expect(Array.from(arg.tokenB)).toEqual(Array.from(new Uint8Array(32).fill(0x22)));
    // The ticker is never what gets sent.
    expect(Array.from(arg.tokenA)).not.toEqual(
      Array.from(new TextEncoder().encode('RIGB')),
    );
  });

  /// REQUIRED PROOF: reversing the selection produces the same canonical pair.
  ///
  /// The frontend does NOT sort — Rust does, over the commits — so what this
  /// pins is that the render layer forwards the identities verbatim and adds no
  /// ordering of its own for Rust to disagree with.
  it('forwards the pair verbatim in either selection order', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    mockedCreate.mockResolvedValue({ success: true, vaultIdBase32: ZERO_VAULT_ID_B32 });
    mockedPublishAd.mockResolvedValue({ success: true });
    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /\+ Create vault/ }));

    // Deliberately backwards: the higher anchor selected as A.
    fireEvent.change(screen.getByLabelText(/Token A/), { target: { value: ANCHOR_B } });
    fireEvent.change(screen.getByLabelText(/Token B/), { target: { value: ANCHOR_A } });
    fireEvent.change(screen.getByLabelText(/^Reserve A$/), { target: { value: '2000' } });
    fireEvent.change(screen.getByLabelText(/^Reserve B$/), { target: { value: '1000' } });
    fireEvent.change(screen.getByLabelText(/Policy anchor/), {
      target: { value: ANCHOR_A },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Create$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));

    await waitFor(() => expect(mockedCreate).toHaveBeenCalled());
    const arg = mockedCreate.mock.calls[0][0];
    // Each side still carries the amount the user entered against it — the
    // frontend has not silently re-paired reserves to a sorted order it
    // invented. Rust aligns the legs when it canonicalises.
    expect(Array.from(arg.tokenA)).toEqual(Array.from(new Uint8Array(32).fill(0x22)));
    expect(arg.reserveA).toBe(2000n);
    expect(Array.from(arg.tokenB)).toEqual(Array.from(new Uint8Array(32).fill(0x11)));
    expect(arg.reserveB).toBe(1000n);
  });

  it('happy path: form submits, refreshes list, shows toast', async () => {
    mockedList
      .mockResolvedValueOnce({ success: true, vaults: [] })
      .mockResolvedValueOnce({
        success: true,
        vaults: [
          {
            vaultIdBase32: ZERO_VAULT_ID_B32,
            tokenA: new Uint8Array(32).fill(0xa1),
            tokenB: new Uint8Array(32).fill(0xb2),
            tokenATicker: 'AAA',
            tokenBTicker: 'BBB',
            reserveA: 1000n,
            reserveB: 2000n,
            feeBps: 30,
            advertisedStateNumber: 1n,
            routingAdvertised: true,
            anchorSequence: 0n,
            anchorEnforcement: 'required' as const,
          },
        ],
      });
    mockedCreate.mockResolvedValue({ success: true, vaultIdBase32: ZERO_VAULT_ID_B32 });
    mockedPublishAd.mockResolvedValue({ success: true, vaultIdBase32: ZERO_VAULT_ID_B32 });

    render(<LiquidityScreen />);
    await waitFor(() => expect(screen.getByText(/My vaults \(0\)/)).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /\+ Create vault/ }));
    fireEvent.change(screen.getByLabelText(/Token A/), { target: { value: ANCHOR_A } });
    fireEvent.change(screen.getByLabelText(/Token B/), { target: { value: ANCHOR_B } });
    fireEvent.change(screen.getByLabelText(/^Reserve A$/), { target: { value: '1000' } });
    fireEvent.change(screen.getByLabelText(/^Reserve B$/), { target: { value: '2000' } });
    // 32 zero bytes Base32 Crockford = '0000000000000000000000000000000000000000000000000000'
    fireEvent.change(screen.getByLabelText(/Policy anchor/), {
      target: { value: '0000000000000000000000000000000000000000000000000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^Create$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));

    await waitFor(() => expect(mockedCreate).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText(/Vault created/)).toBeInTheDocument());
  });

  it('back button calls onNavigate with home', () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    const onNavigate = jest.fn();
    render(<LiquidityScreen onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('button', { name: /Back/ }));
    expect(onNavigate).toHaveBeenCalledWith('home');
  });
});
