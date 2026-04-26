import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DevAmmTradeScreen from '../DevAmmTradeScreen';

jest.mock('../../../dsm/route_commit', () => ({
  listAdvertisementsForPair: jest.fn(),
  syncVaultsForPair: jest.fn(),
  findAndBindBestPath: jest.fn(),
  signRouteCommit: jest.fn(),
  computeExternalCommitment: jest.fn(),
  publishExternalCommitment: jest.fn(),
  unlockVaultRouted: jest.fn(),
}));

import {
  listAdvertisementsForPair,
  syncVaultsForPair,
  findAndBindBestPath,
  signRouteCommit,
  computeExternalCommitment,
  publishExternalCommitment,
  unlockVaultRouted,
} from '../../../dsm/route_commit';
import { encodeBase32Crockford } from '../../../utils/textId';

const okVaultId = encodeBase32Crockford(new Uint8Array(32).fill(0x77));

describe('DevAmmTradeScreen', () => {
  beforeEach(() => jest.clearAllMocks());

  test('renders default trade inputs', () => {
    render(<DevAmmTradeScreen />);
    expect(screen.getByDisplayValue('DEMO_AAA')).toBeInTheDocument();
    expect(screen.getByDisplayValue('DEMO_BBB')).toBeInTheDocument();
    expect(screen.getByDisplayValue('10000')).toBeInTheDocument();
  });

  test('Quote click discovers and lists vaults', async () => {
    (listAdvertisementsForPair as jest.Mock).mockResolvedValue({
      success: true,
      advertisements: [
        {
          vaultIdBase32: okVaultId,
          tokenA: new TextEncoder().encode('DEMO_AAA'),
          tokenB: new TextEncoder().encode('DEMO_BBB'),
          reserveA: 1_000_000n,
          reserveB: 1_000_000n,
          feeBps: 30,
          stateNumber: 1n,
          ownerPublicKey: new Uint8Array(64),
        },
      ],
    });
    render(<DevAmmTradeScreen />);
    fireEvent.click(screen.getByText(/^Quote$/i));
    await waitFor(() =>
      expect(listAdvertisementsForPair).toHaveBeenCalledTimes(1),
    );
    await waitFor(() => expect(screen.getByText(/1 vault\(s\) discovered/i)).toBeInTheDocument());
    expect(screen.getByText(/reserves=/i)).toBeInTheDocument();
  });

  test('Trade button disabled until a vault is selected', () => {
    render(<DevAmmTradeScreen />);
    const trade = screen.getByText(/Execute trade/i) as HTMLButtonElement;
    expect(trade.disabled).toBe(true);
  });

  test('happy-path trade calls every pipeline step', async () => {
    (listAdvertisementsForPair as jest.Mock).mockResolvedValue({
      success: true,
      advertisements: [
        {
          vaultIdBase32: okVaultId,
          tokenA: new TextEncoder().encode('DEMO_AAA'),
          tokenB: new TextEncoder().encode('DEMO_BBB'),
          reserveA: 1_000_000n,
          reserveB: 1_000_000n,
          feeBps: 30,
          stateNumber: 1n,
          ownerPublicKey: new Uint8Array(64),
        },
      ],
    });
    (syncVaultsForPair as jest.Mock).mockResolvedValue({
      success: true,
      newlyMirroredBase32: [],
    });
    (findAndBindBestPath as jest.Mock).mockResolvedValue({
      success: true,
      unsignedRouteCommitBytes: new Uint8Array([0x01, 0x02]),
    });
    (signRouteCommit as jest.Mock).mockResolvedValue({
      success: true,
      signedRouteCommitBase32: encodeBase32Crockford(new Uint8Array([0x03, 0x04])),
    });
    (computeExternalCommitment as jest.Mock).mockResolvedValue({
      success: true,
      xBase32: encodeBase32Crockford(new Uint8Array(32).fill(0xAA)),
    });
    (publishExternalCommitment as jest.Mock).mockResolvedValue({
      success: true,
      xBase32: encodeBase32Crockford(new Uint8Array(32).fill(0xAA)),
    });
    (unlockVaultRouted as jest.Mock).mockResolvedValue({
      success: true,
      vaultIdBase32: okVaultId,
    });

    render(<DevAmmTradeScreen />);
    fireEvent.click(screen.getByText(/^Quote$/i));
    await waitFor(() =>
      expect(listAdvertisementsForPair).toHaveBeenCalled(),
    );
    // The auto-selected first vault should let Trade enable.
    const trade = (await screen.findByText(/Execute trade/i)) as HTMLButtonElement;
    await waitFor(() => expect(trade.disabled).toBe(false));
    fireEvent.click(trade);

    await waitFor(() =>
      expect(syncVaultsForPair).toHaveBeenCalledTimes(1),
    );
    await waitFor(() =>
      expect(findAndBindBestPath).toHaveBeenCalledTimes(1),
    );
    await waitFor(() => expect(signRouteCommit).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(computeExternalCommitment).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(publishExternalCommitment).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(unlockVaultRouted).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByText(/Trade settled/i)).toBeInTheDocument());
  });

  test('aborts pipeline if step 2 (find+bind) fails', async () => {
    (listAdvertisementsForPair as jest.Mock).mockResolvedValue({
      success: true,
      advertisements: [
        {
          vaultIdBase32: okVaultId,
          tokenA: new TextEncoder().encode('DEMO_AAA'),
          tokenB: new TextEncoder().encode('DEMO_BBB'),
          reserveA: 1_000_000n,
          reserveB: 1_000_000n,
          feeBps: 30,
          stateNumber: 1n,
          ownerPublicKey: new Uint8Array(64),
        },
      ],
    });
    (syncVaultsForPair as jest.Mock).mockResolvedValue({
      success: true,
      newlyMirroredBase32: [],
    });
    (findAndBindBestPath as jest.Mock).mockResolvedValue({
      success: false,
      error: 'NoPath { input_token, output_token, requested_input }',
    });
    render(<DevAmmTradeScreen />);
    fireEvent.click(screen.getByText(/^Quote$/i));
    await waitFor(() => expect(listAdvertisementsForPair).toHaveBeenCalled());
    fireEvent.click(await screen.findByText(/Execute trade/i));

    await waitFor(() =>
      expect(screen.getByText(/Step 2 failed: NoPath/i)).toBeInTheDocument(),
    );
    // sign / publish / unlock should never have been invoked.
    expect(signRouteCommit).not.toHaveBeenCalled();
    expect(publishExternalCommitment).not.toHaveBeenCalled();
    expect(unlockVaultRouted).not.toHaveBeenCalled();
  });
});
