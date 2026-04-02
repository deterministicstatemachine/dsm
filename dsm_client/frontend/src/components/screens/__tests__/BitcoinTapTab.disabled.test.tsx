import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import BitcoinTapTab from '../bitcoin/BitcoinTapTab';

const mockGetDbtcBalance = jest.fn();
const mockGetNativeBtcBalance = jest.fn();
const mockListDeposits = jest.fn();
const mockListVaults = jest.fn();
const mockListBitcoinWalletAccounts = jest.fn();
const mockGetBitcoinAddress = jest.fn();
const mockGetBitcoinWalletHealth = jest.fn();
const mockReviewWithdrawalPlan = jest.fn();
const mockExecuteWithdrawalPlan = jest.fn();
const mockCheckConfirmations = jest.fn();
const mockAwaitAndComplete = jest.fn();
const mockCompleteExitDeposit = jest.fn();
const mockFundAndBroadcast = jest.fn();

jest.mock('../../../services/bitcoinTap', () => ({
  getDbtcBalance: (...args: any[]) => mockGetDbtcBalance(...args),
  getNativeBtcBalance: (...args: any[]) => mockGetNativeBtcBalance(...args),
  listDeposits: (...args: any[]) => mockListDeposits(...args),
  listVaults: (...args: any[]) => mockListVaults(...args),
  listBitcoinWalletAccounts: (...args: any[]) => mockListBitcoinWalletAccounts(...args),
  getBitcoinAddress: (...args: any[]) => mockGetBitcoinAddress(...args),
  peekBitcoinAddress: jest.fn(async () => null),
  selectBitcoinAddress: jest.fn(async () => null),
  getBitcoinWalletHealth: (...args: any[]) => mockGetBitcoinWalletHealth(...args),
  createBitcoinWallet: jest.fn(async () => ({})),
  importBitcoinWallet: jest.fn(async () => ({})),
  selectBitcoinWalletAccount: jest.fn(async () => ({})),
  initiateDeposit: jest.fn(async () => ({ vaultOpId: 'mock' })),
  reviewWithdrawalPlan: (...args: any[]) => mockReviewWithdrawalPlan(...args),
  executeWithdrawalPlan: (...args: any[]) => mockExecuteWithdrawalPlan(...args),
  checkConfirmations: (...args: any[]) => mockCheckConfirmations(...args),
  awaitAndComplete: (...args: any[]) => mockAwaitAndComplete(...args),
  completeExitDeposit: (...args: any[]) => mockCompleteExitDeposit(...args),
  fundAndBroadcast: (...args: any[]) => mockFundAndBroadcast(...args),
  refundDeposit: jest.fn(async () => ({})),
  getVaultDetail: jest.fn(async () => null),
  formatBtc: (sats: bigint) => (Number(sats) / 1e8).toFixed(8),
  normalizeBitcoinUiNetwork: (network: number) => {
    if (network === 0 || network === 1) return network;
    return 2;
  },
  bitcoinNetworkLabel: (network: number) => ['mainnet', 'testnet', 'signet'][network === 0 || network === 1 ? network : 2],
  mempoolExplorerUrl: (txid: string, network: number) => {
    const prefix = network === 0 ? 'mainnet' : network === 1 ? 'testnet4' : 'signet';
    return `https://example.test/${prefix}/tx/${txid}`;
  },
  parseBtcToSats: (btc: string) => BigInt(Math.round(parseFloat(btc) * 1e8)),
}));

jest.mock('../../../bridge/bridgeEvents', () => ({
  bridgeEvents: {
    on: jest.fn(() => () => {}),
    off: jest.fn(),
    emit: jest.fn(),
  },
}));

jest.mock('../../../utils/textId', () => ({
  encodeBase32Crockford: jest.fn(() => 'MOCK32'),
}));

function setupMocks(opts: {
  balance?: { available: bigint; locked: bigint };
  vaults?: any[];
  deposits?: any[];
}) {
  mockGetDbtcBalance.mockResolvedValue(opts.balance ?? { available: 500_000n, locked: 0n });
  mockGetNativeBtcBalance.mockResolvedValue({ available: 0n, locked: 0n });
  mockListDeposits.mockResolvedValue(opts.deposits ?? []);
  mockListVaults.mockResolvedValue(opts.vaults ?? [{
    vaultId: 'vault-a',
    direction: 'btc_to_dbtc',
    amountSats: 300_000n,
    state: 'active',
    htlcAddress: 'tb1qvault',
    entryHeader: new Uint8Array(0),
  }]);
  mockListBitcoinWalletAccounts.mockResolvedValue({
    accounts: [{
      accountId: 'wallet-1',
      active: true,
      label: 'test wallet',
      importKind: 'mnemonic',
      network: 2,
      firstAddress: 'tb1qtest',
      activeReceiveIndex: 0,
    }],
    activeAccountId: 'wallet-1',
  });
  mockGetBitcoinAddress.mockResolvedValue({ address: 'tb1qtest', index: 0 });
  mockGetBitcoinWalletHealth.mockResolvedValue(null);
  mockCheckConfirmations.mockResolvedValue({ confirmations: 0, required: 6, ready: false, status: 'pending', fundingTxid: '' });
  mockAwaitAndComplete.mockResolvedValue('ok');
  mockCompleteExitDeposit.mockResolvedValue('ok');
  mockFundAndBroadcast.mockResolvedValue('funding-txid');
  mockReviewWithdrawalPlan.mockResolvedValue({
    planId: 'withdraw-1',
    planClass: 'multiple_full_plus_partial',
    requestedNetSats: 250_000n,
    plannedNetSats: 250_000n,
    totalGrossExitSats: 251_000n,
    totalFeeSats: 1_000n,
    shortfallSats: 0n,
    legs: [{
      vaultId: 'vault-a',
      kind: 'partial',
      sourceAmountSats: 300_000n,
      grossExitSats: 251_000n,
      estimatedFeeSats: 1_000n,
      estimatedNetSats: 250_000n,
      remainderSats: 49_000n,
      successorDepthAfter: 1,
    }],
    blockedVaults: [],
    routeCommitmentId: Uint8Array.from([1, 2, 3, 4]),
    routeCommitmentKey: 'dbtc/manifold/policy/routes/commitment-1',
    selectorSnapshotHash: Uint8Array.from([5, 6, 7, 8]),
    policyCommit: Uint8Array.from([9, 10, 11, 12]),
  });
  mockExecuteWithdrawalPlan.mockResolvedValue({
    planId: 'withdraw-1',
    planClass: 'multiple_full_plus_partial',
    status: 'committed',
    message: 'Broadcast 1 withdrawal leg(s). Final burn will complete after confirmation depth is reached.',
    requestedNetSats: 250_000n,
    plannedNetSats: 250_000n,
    totalGrossExitSats: 251_000n,
    totalFeeSats: 1_000n,
    shortfallSats: 0n,
    executedLegs: [{
      vaultId: 'vault-a',
      kind: 'partial',
      status: 'broadcast',
      grossExitSats: 251_000n,
      estimatedFeeSats: 1_000n,
      estimatedNetSats: 250_000n,
      actualRemainderSats: 49_000n,
      successorVaultId: 'successor-1',
      successorVaultOpId: 'test-successor-1',
      exitVaultOpId: 'exit-1',
      sweepTxid: 'a'.repeat(64),
    }],
    blockedVaults: [],
  });
}

describe('BitcoinTapTab withdrawal planner flow', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: jest.fn().mockResolvedValue(undefined) },
      configurable: true,
    });
  });

  it('shows the review flow and removes the legacy partial/full buttons', async () => {
    setupMocks({});
    render(<BitcoinTapTab />);

    fireEvent.click(await screen.findByText(/Withdraw/i, { selector: 'button' }));

    await screen.findByText(/Review Withdrawal/i);
    expect(screen.queryByText(/Partial Withdrawal/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Withdraw All/i)).not.toBeInTheDocument();
  });

  it('renders planner summary with excluded vault notes', async () => {
    setupMocks({});
    mockReviewWithdrawalPlan.mockResolvedValueOnce({
      planId: 'withdraw-2',
      planClass: 'multiple_full_sweeps',
      requestedNetSats: 200_000n,
      plannedNetSats: 190_000n,
      totalGrossExitSats: 191_000n,
      totalFeeSats: 1_000n,
      shortfallSats: 10_000n,
      legs: [{
        vaultId: 'vault-a',
        kind: 'full',
        sourceAmountSats: 191_000n,
        grossExitSats: 191_000n,
        estimatedFeeSats: 1_000n,
        estimatedNetSats: 190_000n,
        remainderSats: 0n,
        successorDepthAfter: 0,
      }],
      blockedVaults: [{
        vaultId: 'vault-busy',
        amountSats: 150_000n,
        reason: 'Exit already in progress (awaiting_confirmation)',
      }],
      routeCommitmentId: Uint8Array.from([2, 2, 2, 2]),
      routeCommitmentKey: 'dbtc/manifold/policy/routes/commitment-2',
      selectorSnapshotHash: Uint8Array.from([3, 3, 3, 3]),
      policyCommit: Uint8Array.from([4, 4, 4, 4]),
    });

    render(<BitcoinTapTab />);
    fireEvent.click(await screen.findByText(/Withdraw/i, { selector: 'button' }));
    fireEvent.change(await screen.findByLabelText(/Amount to Deliver/i), { target: { value: '0.002' } });
    fireEvent.change(screen.getByLabelText(/Destination Bitcoin Address/i), { target: { value: 'tb1qwithdrawdest' } });
    fireEvent.click(screen.getByText(/Review Withdrawal/i, { selector: 'button' }));

    await screen.findByText(/Excluded Vaults/i);
    expect(screen.getByText(/Shortfall from request/i)).toBeInTheDocument();
    expect(screen.getByText(/vault-busy/i)).toBeInTheDocument();
  });

  it('executes the reviewed plan after confirmation', async () => {
    setupMocks({});
    render(<BitcoinTapTab />);

    fireEvent.click(await screen.findByText(/Withdraw/i, { selector: 'button' }));
    fireEvent.change(await screen.findByLabelText(/Amount to Deliver/i), { target: { value: '0.0025' } });
    fireEvent.change(screen.getByLabelText(/Destination Bitcoin Address/i), { target: { value: 'tb1qwithdrawdest' } });
    fireEvent.click(screen.getByText(/Review Withdrawal/i, { selector: 'button' }));

    await screen.findByText(/Confirm Withdrawal/i, { selector: 'button' });
    fireEvent.click(screen.getByText(/Confirm Withdrawal/i, { selector: 'button' }));
    fireEvent.click(await screen.findByText(/^Confirm$/i, { selector: 'button' }));

    await waitFor(() => {
      expect(mockExecuteWithdrawalPlan).toHaveBeenCalledWith(
        'withdraw-1',
        'tb1qwithdrawdest',
      );
    });
    expect(await screen.findByText(/Execution: committed/i)).toBeInTheDocument();
  });

  it('does not render manual exit claim controls in deposit cards', async () => {
    setupMocks({
      deposits: [{
        vaultOpId: 'test-exit-1',
        direction: 'dbtc_to_btc',
        status: 'awaiting_confirmation',
        btcAmountSats: 100_000n,
        htlcAddress: 'tb1qtest',
        vaultId: 'vault-a',
        isFractionalSuccessor: false,
        fundingTxid: 'a'.repeat(64),
      }],
    });

    render(<BitcoinTapTab />);
    fireEvent.click(await screen.findByText(/BTC → BTC|dBTC → BTC|BTC → dBTC/i, { selector: 'div' }));

    expect(screen.queryByPlaceholderText(/Destination address/i)).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/Funding txid/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Preview fee/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Claim BTC/i)).not.toBeInTheDocument();
  });
});
