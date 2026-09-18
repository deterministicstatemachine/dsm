// SPDX-License-Identifier: Apache-2.0
import React, { useCallback, useState } from 'react';
import {
  executeWithdrawalPlan,
  formatBtc,
  mempoolExplorerUrl,
  parseBtcToSats,
  reviewWithdrawalPlan,
} from '../../../services/bitcoinTap';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import logger from '../../../utils/logger';
import ConfirmModal from '../../ConfirmModal';
import ExplorerLink from './ExplorerLink';
import { Disclosure } from '../../common/ScreenFrame';
import { InfoTip } from '../../common/InfoTip';
import type {
  DbtcBalance,
  VaultSummary,
  WithdrawalExecuteResult,
  WithdrawalPlanResult,
} from '../../../services/bitcoinTap';

type Props = {
  balance: DbtcBalance | null;
  nativeBalance?: import('../../../services/bitcoinTap').NativeBtcBalance | null;
  vaults: VaultSummary[];
  network: number;
  onBack: () => void;
  onRefresh: () => Promise<void>;
};

const PLAN_CLASS_LABELS: Record<string, string> = {
  single_full_sweep: 'Single full sweep',
  single_partial_sweep: 'Single partial sweep',
  multiple_full_sweeps: 'Multiple full sweeps',
  multiple_full_plus_partial: 'Multiple full sweeps + partial change',
  unavailable: 'No route available',
  insufficient_dbtc: 'Insufficient dBTC balance',
};

function planClassLabel(planClass: string): string {
  return PLAN_CLASS_LABELS[planClass] || planClass;
}

function executionHeadline(status: string): string {
  switch (status) {
    case 'committed': return 'Withdrawal sent';
    case 'failed': return 'Withdrawal failed';
    default: return `Withdrawal ${status.replace(/_/g, ' ')}`;
  }
}

export default function WithdrawView({
  balance,
  nativeBalance = null,
  vaults,
  network,
  onBack,
  onRefresh,
}: Props): JSX.Element {
  const [withdrawAmount, setWithdrawAmount] = useState('');
  const [withdrawDest, setWithdrawDest] = useState('');
  const [reviewLoading, setReviewLoading] = useState(false);
  const [executeLoading, setExecuteLoading] = useState(false);
  const [reviewResult, setReviewResult] = useState<WithdrawalPlanResult | null>(null);
  const [executionResult, setExecutionResult] = useState<WithdrawalExecuteResult | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  const activeVaultCount = vaults.filter((vault) => vault.state === 'active').length;

  const resetReviewedState = useCallback(() => {
    setReviewResult(null);
    setExecutionResult(null);
    setMessage(null);
  }, []);

  const handleReview = useCallback(async () => {
    if (!withdrawAmount.trim() || !withdrawDest.trim() || reviewLoading || executeLoading) return;
    setReviewLoading(true);
    setExecutionResult(null);
    setMessage(null);
    try {
      const requestedNetSats = parseBtcToSats(withdrawAmount);
      const reviewed = await reviewWithdrawalPlan(requestedNetSats, withdrawDest.trim());
      setReviewResult(reviewed);
      if (!reviewed.planId || reviewed.legs.length === 0) {
        logger.warn(
          `[WithdrawView] plan unavailable: class=${reviewed.planClass} eligible_legs=0 blocked=${reviewed.blockedVaults.length} shortfall=${reviewed.shortfallSats}`,
        );
        for (const bv of reviewed.blockedVaults) {
          logger.warn(
            `[WithdrawView]   blocked: vault=${bv.vaultId.slice(0, 12)} amount=${bv.amountSats} reason=${bv.reason}`,
          );
        }
        setMessage('No executable withdrawal route matched the requested amount.');
      }
    } catch (e) {
      setReviewResult(null);
      setMessage(`Error: ${e instanceof Error ? e.message : 'Withdrawal review failed'}`);
    } finally {
      setReviewLoading(false);
    }
  }, [withdrawAmount, withdrawDest, reviewLoading, executeLoading]);

  const handleExecute = useCallback(async () => {
    if (!reviewResult?.planId || executeLoading || reviewLoading) return;
    setExecuteLoading(true);
    setMessage(null);
    try {
      const result = await executeWithdrawalPlan(reviewResult.planId, withdrawDest.trim());
      setExecutionResult(result);
      await onRefresh();
      bridgeEvents.emit('wallet.refresh', { source: 'bitcoin.tap' });
      if (result.status === 'committed') {
        setWithdrawAmount('');
        setWithdrawDest('');
        setMessage('Withdrawal broadcast. It finalizes once the Bitcoin network confirms it; refresh to follow along.');
      }
    } catch (e) {
      setExecutionResult(null);
      setMessage(`Error: ${e instanceof Error ? e.message : 'Withdrawal execution failed'}`);
    } finally {
      setExecuteLoading(false);
    }
  }, [reviewResult, executeLoading, reviewLoading, withdrawDest, onRefresh]);

  const confirmMessage = reviewResult
    ? `Withdraw ${formatBtc(reviewResult.totalGrossExitSats)} BTC to ${withdrawDest.slice(0, 12)}…?\nBitcoin network fee: ${formatBtc(reviewResult.totalFeeSats)} BTC (deducted from amount)\nYou receive: ${formatBtc(reviewResult.plannedNetSats)} BTC`
    : 'Execute withdrawal?';

  const canExecute = Boolean(
    reviewResult
    && reviewResult.planId
    && reviewResult.legs.length > 0
    && reviewResult.planClass !== 'insufficient_dbtc'
    && !executeLoading
    && !reviewLoading,
  );

  return (
    <div className="bitcoin-tap-tab">
      <div className="sb-subhead">
        <button type="button" className="sb-icon-btn" onClick={onBack} aria-label="Back" title="Back">{'‹'}</button>
        <h3>Withdraw to Bitcoin</h3>
        <InfoTip title="Withdraw to Bitcoin" label="About withdrawals">
          <p>Sends dBTC out of this wallet to any Bitcoin address, as BTC.</p>
          <p>Enter how much dBTC to spend. The Bitcoin network fee comes out of that amount, so the recipient gets less than you type. <b>Review</b> shows exactly what leaves your balance and what arrives, and nothing moves until you confirm.</p>
          <p>The withdrawal is paid out of the on-chain vaults behind your dBTC. It finalizes once the Bitcoin network confirms it. Until then the amount is held aside and is not part of your spendable balance.</p>
        </InfoTip>
      </div>

      <div className="sb-card">
        <div className="sb-kv">
          <span className="sb-kv__k">Available dBTC</span>
          <span className="sb-kv__v">{balance ? formatBtc(balance.available) : '0.00000000'} dBTC</span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">On-chain BTC</span>
          <span className="sb-kv__v">{nativeBalance ? formatBtc(nativeBalance.available) : '0.00000000'} BTC</span>
        </div>
      </div>

      <div className="sb-field">
        <label htmlFor="withdraw-amount">Amount to spend (BTC)</label>
        <div className="sb-input-row">
          <input
            id="withdraw-amount"
            type="text"
            inputMode="decimal"
            value={withdrawAmount}
            onChange={(e) => { setWithdrawAmount(e.target.value); resetReviewedState(); }}
            placeholder="0.00100000"
            className="sb-input sb-input--mono"
          />
          <button
            type="button"
            className="sb-btn sb-btn--small"
            disabled={!balance || balance.available <= 0n}
            onClick={() => {
              if (balance && balance.available > 0n) {
                setWithdrawAmount(formatBtc(balance.available));
                resetReviewedState();
              }
            }}
          >
            Max
          </button>
        </div>
      </div>

      <div className="sb-field">
        <label htmlFor="withdraw-dest">Destination Bitcoin address</label>
        <input
          id="withdraw-dest"
          type="text"
          value={withdrawDest}
          onChange={(e) => { setWithdrawDest(e.target.value); resetReviewedState(); }}
          placeholder="bc1q…"
          className="sb-input sb-input--mono"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
        />
      </div>

      {!reviewResult && (
        <div className="sb-actions">
          <button type="button" onClick={onBack} className="sb-btn">Cancel</button>
          <button
            type="button"
            onClick={handleReview}
            className="sb-btn sb-btn--primary"
            disabled={!withdrawAmount || !withdrawDest || reviewLoading || executeLoading}
          >
            {reviewLoading ? 'Reviewing…' : 'Review withdrawal'}
          </button>
        </div>
      )}

      {reviewResult && (
        <div className="sb-card">
          <div className="sb-card__title"><span>Review</span></div>
          <div className="sb-kv">
            <span className="sb-kv__k">Recipient gets</span>
            <span className="sb-kv__v"><b>{formatBtc(reviewResult.plannedNetSats)} BTC</b></span>
          </div>
          <div className="sb-kv">
            <span className="sb-kv__k">Network fee</span>
            <span className="sb-kv__v">{formatBtc(reviewResult.totalFeeSats)} BTC</span>
          </div>
          <div className="sb-kv">
            <span className="sb-kv__k">Taken from your dBTC</span>
            <span className="sb-kv__v">{formatBtc(reviewResult.totalGrossExitSats)} dBTC</span>
          </div>
          {reviewResult.shortfallSats > 0n && (
            <div className="sb-kv">
              <span className="sb-kv__k">Shortfall from request</span>
              <span className="sb-kv__v">{formatBtc(reviewResult.shortfallSats)} BTC</span>
            </div>
          )}

          {reviewResult.planClass === 'insufficient_dbtc' && (
            <p className="sb-notice sb-notice--error" style={{ marginTop: 8 }}>
              This needs {formatBtc(reviewResult.totalGrossExitSats)} dBTC including the network fee. You have {formatBtc(reviewResult.availableDbtcSats)} dBTC.
            </p>
          )}

          <Disclosure summary={`Route details (${reviewResult.legs.length} leg${reviewResult.legs.length === 1 ? '' : 's'})`} className="sb-details--plain">
            <p className="sb-hint">Active vaults: {activeVaultCount}.</p>
            <div className="sb-kv"><span className="sb-kv__k">Plan</span><span className="sb-kv__v">{planClassLabel(reviewResult.planClass)}</span></div>
            {reviewResult.legs.map((leg, index) => (
              <div key={`${leg.vaultId}-${index}`} className="sb-card" style={{ padding: '4px 8px' }}>
                <div className="sb-kv"><span className="sb-kv__k">Leg {index + 1}</span><span className="sb-kv__v">{leg.kind === 'full' ? 'Full sweep' : 'Partial sweep'}</span></div>
                <div className="sb-kv"><span className="sb-kv__k">Vault</span><span className="sb-kv__v sb-kv__v--mono">{leg.vaultId.slice(0, 12)}…</span></div>
                <div className="sb-kv"><span className="sb-kv__k">Source</span><span className="sb-kv__v">{formatBtc(leg.sourceAmountSats)} BTC</span></div>
                <div className="sb-kv"><span className="sb-kv__k">Delivered</span><span className="sb-kv__v">{formatBtc(leg.estimatedNetSats)} BTC</span></div>
                <div className="sb-kv"><span className="sb-kv__k">Fee</span><span className="sb-kv__v">{formatBtc(leg.estimatedFeeSats)} BTC</span></div>
                {leg.kind === 'partial' && (
                  <div className="sb-kv"><span className="sb-kv__k">Remainder</span><span className="sb-kv__v">{formatBtc(leg.remainderSats)} BTC</span></div>
                )}
              </div>
            ))}
          </Disclosure>

          <div className="sb-actions" style={{ marginBottom: 0 }}>
            <button type="button" onClick={resetReviewedState} className="sb-btn" disabled={executeLoading}>Edit</button>
            <button
              type="button"
              onClick={() => setShowConfirm(true)}
              className="sb-btn sb-btn--primary"
              disabled={!canExecute}
            >
              {executeLoading ? 'Sending…' : 'Confirm withdrawal'}
            </button>
          </div>
        </div>
      )}

      {message && (
        <div className={`sb-notice${message.startsWith('Error') ? ' sb-notice--error' : ''}`} role="status">
          <span style={{ whiteSpace: 'pre-wrap' }}>{message}</span>
        </div>
      )}

      {executionResult && (
        <div className="sb-card">
          <div className="sb-card__title"><span>{executionHeadline(executionResult.status)}</span></div>
          <div style={{ fontSize: 10, marginBottom: 6 }}>{executionResult.message}</div>
          <div className="sb-hint sb-hint--tight">Execution: {executionResult.status}</div>
          <Disclosure summary={`Legs (${executionResult.executedLegs.length})`} className="sb-details--plain">
            {executionResult.executedLegs.map((leg, index) => (
              <div key={`${leg.vaultId}-${leg.sweepTxid || index}`} className="sb-card" style={{ padding: '4px 8px' }}>
                <div className="sb-kv"><span className="sb-kv__k">Leg {index + 1}</span><span className="sb-kv__v">{leg.kind === 'full' ? 'Full sweep' : 'Partial sweep'} ({leg.status})</span></div>
                <div className="sb-kv"><span className="sb-kv__k">Vault</span><span className="sb-kv__v sb-kv__v--mono">{leg.vaultId.slice(0, 12)}…</span></div>
                <div className="sb-kv"><span className="sb-kv__k">Delivered</span><span className="sb-kv__v">{formatBtc(leg.estimatedNetSats)} BTC</span></div>
                {leg.actualRemainderSats > 0n && (
                  <div className="sb-kv"><span className="sb-kv__k">Remainder</span><span className="sb-kv__v">{formatBtc(leg.actualRemainderSats)} BTC</span></div>
                )}
                {leg.sweepTxid && (
                  <ExplorerLink
                    url={mempoolExplorerUrl(leg.sweepTxid, network)}
                    onCopied={() => setMessage(`Explorer link copied for leg ${index + 1}`)}
                    onCopyFailed={(url) => setMessage(`URL: ${url}`)}
                  />
                )}
              </div>
            ))}
          </Disclosure>
        </div>
      )}

      <ConfirmModal
        visible={showConfirm}
        title="Confirm Withdrawal"
        message={confirmMessage}
        onConfirm={() => { setShowConfirm(false); void handleExecute(); }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}
