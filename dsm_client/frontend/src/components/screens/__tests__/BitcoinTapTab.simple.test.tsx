// SPDX-License-Identifier: Apache-2.0
// The Bitcoin tab is simple by default: one balance, two actions, the
// receive address and activity. Accounts, network, address index and vault
// internals live under one Advanced fold; a device with no Bitcoin account
// gets the setup form inline instead.

import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import BitcoinTapTab from '../bitcoin/BitcoinTapTab';

const mockListBitcoinWalletAccounts = jest.fn();

jest.mock('../../../services/bitcoinTap', () => ({
  getDbtcBalance: jest.fn(async () => ({ available: 1_250_000n, locked: 100_000n })),
  getNativeBtcBalance: jest.fn(async () => ({ available: 2_345_678n, locked: 0n, source: 'CHAIN' })),
  listDeposits: jest.fn(async () => []),
  listVaults: jest.fn(async () => [{
    vaultId: 'vault-a',
    direction: 'btc_to_dbtc',
    amountSats: 300_000n,
    state: 'active',
    htlcAddress: 'tb1qvault',
    entryHeader: new Uint8Array(0),
  }]),
  listBitcoinWalletAccounts: (...args: unknown[]) => mockListBitcoinWalletAccounts(...args),
  getBitcoinAddress: jest.fn(async () => ({ address: 'tb1qtestaddress', index: 0, pubkey: new Uint8Array(33) })),
  peekBitcoinAddress: jest.fn(async () => null),
  selectBitcoinAddress: jest.fn(async () => null),
  getBitcoinWalletHealth: jest.fn(async () => ({ network: 'signet', reachable: true, source: 'MEMPOOL', rpcUrl: 'https://mempool.space/signet/api' })),
  createBitcoinWallet: jest.fn(async () => ({})),
  importBitcoinWallet: jest.fn(async () => ({})),
  selectBitcoinWalletAccount: jest.fn(async () => ({})),
  initiateDeposit: jest.fn(async () => ({ vaultOpId: 'mock' })),
  reviewWithdrawalPlan: jest.fn(),
  executeWithdrawalPlan: jest.fn(),
  checkConfirmations: jest.fn(),
  awaitAndComplete: jest.fn(),
  completeExitDeposit: jest.fn(),
  fundAndBroadcast: jest.fn(),
  refundDeposit: jest.fn(async () => ({})),
  getVaultDetail: jest.fn(async () => null),
  settleWithdrawals: jest.fn(async () => 'ok'),
  formatBtc: (sats: bigint) => (Number(sats) / 1e8).toFixed(8),
  normalizeBitcoinUiNetwork: (network: number) => (network === 0 || network === 1 ? network : 2),
  bitcoinNetworkLabel: (network: number) => ['mainnet', 'testnet', 'signet'][network === 0 || network === 1 ? network : 2],
  mempoolExplorerUrl: (txid: string) => `https://example.test/tx/${txid}`,
  parseBtcToSats: (btc: string) => BigInt(Math.round(parseFloat(btc) * 1e8)),
}));

jest.mock('../../../bridge/bridgeEvents', () => ({
  bridgeEvents: { on: jest.fn(() => () => {}), off: jest.fn(), emit: jest.fn() },
}));

jest.mock('../../../utils/textId', () => ({
  encodeBase32Crockford: jest.fn(() => 'MOCK32'),
}));

const ACCOUNT = {
  accountId: 'wallet-1',
  active: true,
  label: 'Main wallet',
  importKind: 'mnemonic',
  network: 2,
  firstAddress: 'tb1qtestaddress',
  activeReceiveIndex: 0,
};

describe('BitcoinTapTab simple view', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows the balance, both actions and the address; keeps accounts and vaults under Advanced', async () => {
    mockListBitcoinWalletAccounts.mockResolvedValue({ accounts: [ACCOUNT], activeAccountId: 'wallet-1' });
    render(<BitcoinTapTab />);

    expect(await screen.findByText('0.01250000')).toBeInTheDocument();
    expect(screen.getByText('tb1qtestaddress')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Deposit BTC/i })).toBeEnabled();
    expect(screen.getByRole('button', { name: /^Withdraw$/i })).toBeEnabled();

    // Account management and vault internals are folded away by default.
    expect(screen.getByText('New wallet')).not.toBeVisible();
    expect(screen.getByText('Vaults (1)')).not.toBeVisible();
    expect(screen.queryByText(/Locked in HTLCs/i)).not.toBeVisible();

    fireEvent.click(screen.getByText('Advanced'));
    expect(screen.getByText('New wallet')).toBeVisible();
    expect(screen.getByText('Vaults (1)')).toBeVisible();
    expect(screen.getByText(/mempool\.space .* connected/)).toBeVisible();
  });

  it('offers the setup form inline and disables the actions when there is no Bitcoin account', async () => {
    mockListBitcoinWalletAccounts.mockResolvedValue({ accounts: [], activeAccountId: '' });
    render(<BitcoinTapTab />);

    expect(await screen.findByText('Set up Bitcoin')).toBeVisible();
    expect(screen.getByText('New wallet')).toBeVisible();
    expect(screen.getByRole('button', { name: /Deposit BTC/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /^Withdraw$/i })).toBeDisabled();
  });
});
