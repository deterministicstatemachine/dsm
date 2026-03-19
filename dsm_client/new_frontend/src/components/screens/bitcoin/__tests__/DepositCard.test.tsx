import React from 'react';
import { render, waitFor } from '@testing-library/react';

import DepositCard from '../DepositCard';

const mockFundAndBroadcast = jest.fn();
const mockCheckConfirmations = jest.fn();
const mockAwaitAndComplete = jest.fn();
const mockCompleteExitDeposit = jest.fn();

jest.mock('../../../../services/bitcoinTap', () => ({
  fundAndBroadcast: (...args: unknown[]) => mockFundAndBroadcast(...args),
  checkConfirmations: (...args: unknown[]) => mockCheckConfirmations(...args),
  awaitAndComplete: (...args: unknown[]) => mockAwaitAndComplete(...args),
  completeExitDeposit: (...args: unknown[]) => mockCompleteExitDeposit(...args),
  autoClaimHtlc: jest.fn(),
  getTxStatus: jest.fn(),
  estimateFee: jest.fn(),
  refundDeposit: jest.fn(),
  formatBtc: (sats: bigint) => sats.toString(),
  mempoolExplorerUrl: (txid: string) => `https://example.test/tx/${txid}`,
}));

describe('DepositCard auto-funding', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFundAndBroadcast.mockResolvedValue('funding-txid');
    mockCheckConfirmations.mockResolvedValue({ confirmations: 0, required: 100, ready: false });
    mockAwaitAndComplete.mockResolvedValue('ok');
    mockCompleteExitDeposit.mockResolvedValue('ok');
  });

  it('auto-funds initiated BTC deposits', async () => {
    render(
      <DepositCard
        deposit={{
          vaultOpId: 'test-deposit',
          direction: 'btc_to_dbtc',
          status: 'initiated',
          btcAmountSats: 100000n,
          htlcAddress: 'tb1qdeposit',
          vaultId: 'vault-deposit',
          isFractionalSuccessor: false,
          fundingTxid: '',
        }}
        onRefresh={async () => {}}
        network={2}
      />,
    );

    await waitFor(() => {
      expect(mockFundAndBroadcast).toHaveBeenCalledWith('test-deposit');
    });
  });

  it('does not auto-fund initiated recipient exit deposits', async () => {
    render(
      <DepositCard
        deposit={{
          vaultOpId: 'test-exit',
          direction: 'dbtc_to_btc',
          status: 'initiated',
          btcAmountSats: 100000n,
          htlcAddress: 'tb1qexit',
          vaultId: 'vault-exit',
          isFractionalSuccessor: false,
          fundingTxid: '',
        }}
        onRefresh={async () => {}}
        network={2}
      />,
    );

    await waitFor(() => {
      expect(mockFundAndBroadcast).not.toHaveBeenCalled();
    });
  });
});
