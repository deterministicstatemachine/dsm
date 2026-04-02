// SPDX-License-Identifier: Apache-2.0
import React, { useCallback, useMemo, useState } from 'react';
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

  const activeVaultCount = useMemo(
    () => vaults.filter((vault) => vault.state === 'active').length,
    [vaults],
  );

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
      const result = await executeWithdrawalPlan(
        reviewResult.planId,
        withdrawDest.trim(),
      );
      setExecutionResult(result);
      await onRefresh();
      bridgeEvents.emit('wallet.refresh', { source: 'bitcoin.tap' });
      if (result.status === 'committed') {
        setWithdrawAmount('');
        setWithdrawDest('');
        setMessage('Withdrawal broadcast. Keep refreshing until the burn is finalized.');
      }
    } catch (e) {
      setExecutionResult(null);
      setMessage(`Error: ${e instanceof Error ? e.message : 'Withdrawal execution failed'}`);
    } finally {
      setExecuteLoading(false);
    }
  }, [reviewResult, executeLoading, reviewLoading, withdrawDest, onRefresh]);

  const confirmMessage = reviewResult
    ? `Withdraw ${formatBtc(reviewResult.totalGrossExitSats)} BTC to ${
      withdrawDest.slice(0, 12)
    }…?\nBitcoin network fee: ${formatBtc(reviewResult.totalFeeSats)} BTC (deducted from amount)\nYou receive: ${
      formatBtc(reviewResult.plannedNetSats)
    } BTC`
    : 'Execute withdrawal?';

  return (
    <div className="bitcoin-tap-tab" style={{ padding: '0 4px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
        <button
          onClick={onBack}
          className="button-brick"
          style={{ padding: '4px 8px', background: 'transparent', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-dark)', fontSize: 11, cursor: 'pointer' }}
        >
          Back
        </button>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 500 }}>Withdraw dBTC</h3>
      </div>

      <div style={{ fontSize: 11, marginBottom: 12, color: 'var(--text-disabled)' }}>
        Enter the BTC amount the recipient should receive. The SDK will plan the route across active vaults and show the fee impact before anything executes.
        {' '}
        Estimates labeled &quot;Bitcoin network fee&quot; are <strong>L1 miner fees</strong> for burns and payouts on Bitcoin.
        DSM does not add a separate withdrawal service fee on top of those estimates.
      </div>

      <div className="balance-card btc-tap-summary-card">
        <div className="balance-info btc-tap-summary-col">
          <span className="token-symbol">Available dBTC</span>
          <span className="balance-amount btc-tap-summary-amount">
            {balance ? formatBtc(balance.available) : '0.00000000'}
          </span>
        </div>
        <div className="balance-info btc-tap-summary-col btc-tap-summary-col-right">
          <span className="token-symbol">Native BTC</span>
          <span className="balance-amount btc-tap-summary-amount-sm">
            {nativeBalance ? formatBtc(nativeBalance.available) : '0.00000000'}
          </span>
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', fontSize: 10, color: 'var(--text-disabled)', marginTop: -8, marginBottom: 8 }}>
        Active vaults: {activeVaultCount}
      </div>

      <div className="form-group">
        <label htmlFor="withdraw-amount" style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-dark)', display: 'block', marginBottom: 6 }}>
          Amount to Deliver (BTC)
        </label>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input
            id="withdraw-amount"
            type="text"
            inputMode="decimal"
            value={withdrawAmount}
            onChange={(e) => {
              setWithdrawAmount(e.target.value);
              resetReviewedState();
            }}
            placeholder="0.00100000"
            className="form-input"
            style={{ flex: 1, boxSizing: 'border-box' }}
          />
          <button
            type="button"
            className="button-brick"
            disabled={!balance || balance.available <= 0n}
            onClick={() => {
              if (balance && balance.available > 0n) {
                setWithdrawAmount(formatBtc(balance.available));
                resetReviewedState();
              }
            }}
            style={{ fontSize: 10, padding: '6px 10px', borderRadius: 8, whiteSpace: 'nowrap' }}
          >
            Max
          </button>
        </div>
      </div>

      <div className="form-group">
        <label htmlFor="withdraw-dest" style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-dark)', display: 'block', marginBottom: 6 }}>
          Destination Bitcoin Address
        </label>
        <input
          id="withdraw-dest"
          type="text"
          value={withdrawDest}
          onChange={(e) => {
            setWithdrawDest(e.target.value);
            resetReviewedState();
          }}
          placeholder="bc1q..."
          className="form-input"
          style={{ width: '100%', boxSizing: 'border-box' }}
        />
      </div>

      <div className="form-actions" style={{ marginTop: 16 }}>
        <button type="button" onClick={onBack} className="cancel-button" style={{ flex: 1 }}>
          Cancel
        </button>
        <button
          type="button"
          onClick={handleReview}
          className="send-button button-brick"
          disabled={!withdrawAmount || !withdrawDest || reviewLoading || executeLoading}
          style={{ flex: 1 }}
        >
          {reviewLoading ? 'Reviewing...' : 'Review Withdrawal'}
        </button>
      </div>

      {reviewResult && (
        <div style={{ marginTop: 12, padding: '10px 12px', border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-dark)' }}>
              {planClassLabel(reviewResult.planClass)}
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-disabled)' }}>
              {reviewResult.legs.length} leg{reviewResult.legs.length === 1 ? '' : 's'}
            </div>
          </div>

          <div style={{ fontSize: 11, color: 'var(--text-dark)', display: 'grid', gap: 4 }}>
            <div>Withdrawal amount: <strong>{formatBtc(reviewResult.totalGrossExitSats)} BTC</strong></div>
            <div>Est. Bitcoin network fee: <strong>{formatBtc(reviewResult.totalFeeSats)} BTC</strong></div>
            <div>Estimated delivery: <strong>{formatBtc(reviewResult.plannedNetSats)} BTC</strong></div>
            {reviewResult.shortfallSats > 0n && (
              <div style={{ color: 'var(--text-disabled)' }}>
                Shortfall from request: <strong>{formatBtc(reviewResult.shortfallSats)} BTC</strong>
              </div>
            )}
          </div>

          <div style={{ marginTop: 10, display: 'grid', gap: 6 }}>
            {reviewResult.legs.map((leg, index) => (
              <div key={`${leg.vaultId}-${index}`} style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'rgba(0,0,0,0.03)', fontSize: 10, color: 'var(--text-dark)' }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>
                  Leg {index + 1}: {leg.kind === 'full' ? 'Full sweep' : 'Partial sweep'}
                </div>
                <div>Vault: {leg.vaultId.slice(0, 12)}…</div>
                <div>Source amount: {formatBtc(leg.sourceAmountSats)} BTC</div>
                <div>Estimated delivered: {formatBtc(leg.estimatedNetSats)} BTC</div>
                <div>Est. BTC network fee: {formatBtc(leg.estimatedFeeSats)} BTC</div>
                {leg.kind === 'partial' && (
                  <div>Successor remainder: {formatBtc(leg.remainderSats)} BTC</div>
                )}
              </div>
            ))}
          </div>

          {reviewResult.blockedVaults.length > 0 && (
            <div style={{ marginTop: 10, padding: '8px 10px', border: '1px dashed var(--border)', borderRadius: 6, fontSize: 10, background: 'var(--bg-secondary)', color: 'var(--text-dark)' }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Excluded Vaults</div>
              {reviewResult.blockedVaults.map((vault) => (
                <div key={`${vault.vaultId}-${vault.reason}`}>
                  {vault.vaultId.slice(0, 10)}…: {vault.reason}
                </div>
              ))}
            </div>
          )}

          {reviewResult.planClass === 'insufficient_dbtc' && (
            <div style={{ marginTop: 10, padding: '8px 10px', border: '1px solid var(--warning-border, #e0a800)', borderRadius: 6, fontSize: 11, background: 'var(--warning-bg, #fff3cd)', color: 'var(--warning-text, #856404)' }}>
              You need <strong>{formatBtc(reviewResult.totalGrossExitSats)} dBTC</strong> to cover this withdrawal (includes est. Bitcoin network fees).
              You have <strong>{formatBtc(reviewResult.availableDbtcSats)} dBTC</strong> available.
            </div>
          )}

          <div style={{ marginTop: 12 }}>
            <button
              type="button"
              onClick={() => setShowConfirm(true)}
              className="send-button button-brick"
              disabled={!reviewResult.planId || reviewResult.legs.length === 0 || reviewResult.planClass === 'insufficient_dbtc' || executeLoading || reviewLoading}
              style={{ width: '100%' }}
            >
              {executeLoading ? 'Executing...' : 'Confirm Withdrawal'}
            </button>
          </div>
        </div>
      )}

      {message && (
        <div style={{ marginTop: 12, padding: '8px 10px', border: '1px dashed var(--border)', borderRadius: 6, fontSize: 11, whiteSpace: 'pre-wrap', color: 'var(--text-dark)', background: 'var(--bg-secondary)' }}>
          {message}
        </div>
      )}

      {executionResult && (
        <div style={{ marginTop: 12, padding: '10px 12px', border: '1px solid var(--border)', borderRadius: 8, background: executionResult.status === 'committed' ? 'var(--bg)' : 'var(--bg-secondary)', color: 'var(--text-dark)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8 }}>
            Execution: {executionResult.status}
          </div>
          <div style={{ fontSize: 11, marginBottom: 8 }}>{executionResult.message}</div>
          <div style={{ display: 'grid', gap: 6 }}>
            {executionResult.executedLegs.map((leg, index) => (
              <div key={`${leg.vaultId}-${leg.sweepTxid || index}`} style={{ padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'rgba(0,0,0,0.03)', fontSize: 10 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>
                  Leg {index + 1}: {leg.kind === 'full' ? 'Full sweep' : 'Partial sweep'} ({leg.status})
                </div>
                <div>Vault: {leg.vaultId.slice(0, 12)}…</div>
                <div>Estimated delivered: {formatBtc(leg.estimatedNetSats)} BTC</div>
                {leg.actualRemainderSats > 0n && (
                  <div>Remainder: {formatBtc(leg.actualRemainderSats)} BTC</div>
                )}
                {leg.sweepTxid && (() => {
                  const url = mempoolExplorerUrl(leg.sweepTxid, network);
                  return (
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => navigator.clipboard.writeText(url).then(
                        () => setMessage(`Explorer link copied for leg ${index + 1}`),
                        () => setMessage(`URL: ${url}`),
                      )}
                      onKeyDown={(e) => e.key === 'Enter' && navigator.clipboard.writeText(url).then(
                        () => setMessage(`Explorer link copied for leg ${index + 1}`),
                        () => setMessage(`URL: ${url}`),
                      )}
                      style={{ marginTop: 6, fontSize: 10, color: 'var(--text-dark)', textDecoration: 'underline', wordBreak: 'break-all', cursor: 'copy', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', padding: '2px 0' }}
                      title="Click to copy explorer link"
                    >
                      {url}
                    </div>
                  );
                })()}
              </div>
            ))}
          </div>
        </div>
      )}

      <ConfirmModal
        visible={showConfirm}
        title="Confirm Withdrawal"
        message={confirmMessage}
        onConfirm={() => {
          setShowConfirm(false);
          void handleExecute();
        }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}
