// SPDX-License-Identifier: Apache-2.0
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { refundDeposit, formatBtc, mempoolExplorerUrl } from '../../../services/bitcoinTap';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import ExplorerLink from './ExplorerLink';
import { depositStatusLabel, directionLabel, isRefundableDeposit } from './labels';
import { middleTruncate } from '../../common/ScreenFrame';
import type { DepositEntry } from '../../../services/bitcoinTap';

type Props = {
  deposit: DepositEntry;
  onRefresh: () => Promise<void>;
  network: number;
};

export default function DepositCard({ deposit, onRefresh, network }: Props): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [completing, setCompleting] = useState(false);
  const [confirmations, setConfirmations] = useState<number | null>(null);
  const [confirmReady, setConfirmReady] = useState(false);
  const [confirmRequired, setConfirmRequired] = useState<number | null>(null);
  const [liveFundingTxid, setLiveFundingTxid] = useState(deposit.fundingTxid || '');
  const [refunding, setRefunding] = useState(false);
  const [refundResult, setRefundResult] = useState<string | null>(null);

  const completingRef = useRef(false);
  const completedOnceRef = useRef(false);
  const isExitDeposit = deposit.direction === 'dbtc_to_btc';
  const fundingTxid = liveFundingTxid || null;

  useEffect(() => {
    if (deposit.fundingTxid && !liveFundingTxid) setLiveFundingTxid(deposit.fundingTxid);
  }, [deposit.fundingTxid, liveFundingTxid]);

  useEffect(() => {
    const shouldPoll = (
      fundingTxid
      || deposit.status === 'awaiting_confirmation'
      || deposit.status === 'awaiting_confirmations'
      || (isExitDeposit && deposit.status === 'initiated')
    ) && deposit.status !== 'completed';
    if (!shouldPoll) return;

    let cancelled = false;
    const poll = async () => {
      try {
        const { checkConfirmations, awaitAndComplete, completeExitDeposit } = await import('../../../services/bitcoinTap');
        const info = await checkConfirmations(deposit.vaultOpId);
        if (cancelled) return;
        if (info.fundingTxid && !liveFundingTxid) setLiveFundingTxid(info.fundingTxid);
        setConfirmations(info.confirmations);
        setConfirmRequired(info.required);
        setConfirmReady(info.ready);
        if (info.ready && !completingRef.current && !completedOnceRef.current) {
          completingRef.current = true;
          setCompleting(true);
          setStatusMessage(isExitDeposit ? 'Finalizing withdrawal…' : 'Completing deposit…');
          try {
            const result = isExitDeposit
              ? await completeExitDeposit(deposit.vaultOpId)
              : await awaitAndComplete(deposit.vaultOpId);
            if (cancelled) return;
            completedOnceRef.current = true;
            setStatusMessage(isExitDeposit ? `Withdrawal completed: ${result}` : `Deposit completed: ${result}`);
            bridgeEvents.emit('deposit.completed', { depositId: deposit.vaultOpId, amount: formatBtc(deposit.btcAmountSats) });
            bridgeEvents.emit('wallet.creditReceived', {
              source: isExitDeposit ? 'bitcoin.exit_completed' : 'bitcoin.deposit_completed',
              tokenId: isExitDeposit ? 'BTC_CHAIN' : 'dBTC',
              amount: deposit.btcAmountSats.toString(),
              creditCount: 1,
            });
            await onRefresh();
          } catch (e) {
            if (cancelled) return;
            setStatusMessage(`Error: ${e instanceof Error ? e.message : 'Auto-complete failed'}`);
          } finally {
            completingRef.current = false;
            setCompleting(false);
          }
        }
      } catch {
        // Ignore polling errors; the next cycle will retry.
      }
    };

    void poll();
    const timer = setInterval(() => { void poll(); }, 30000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [fundingTxid, liveFundingTxid, deposit.status, deposit.vaultOpId, deposit.btcAmountSats, isExitDeposit, onRefresh]);

  useEffect(() => {
    const shouldAutoFund = deposit.direction === 'btc_to_dbtc' || deposit.isFractionalSuccessor;
    if (deposit.status !== 'initiated' || deposit.fundingTxid || !shouldAutoFund) return;

    let cancelled = false;
    const autoFund = async () => {
      try {
        setStatusMessage('Funding deposit…');
        const { fundAndBroadcast } = await import('../../../services/bitcoinTap');
        const txid = await fundAndBroadcast(deposit.vaultOpId);
        if (cancelled) return;
        setStatusMessage(`Broadcast. txid: ${txid.slice(0, 16)}…`);
        await onRefresh();
      } catch (e) {
        if (cancelled) return;
        setStatusMessage(`Funding failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
      }
    };

    void autoFund();
    return () => { cancelled = true; };
  }, [deposit.status, deposit.fundingTxid, deposit.vaultOpId, deposit.direction, deposit.isFractionalSuccessor, onRefresh]);

  const handleRefund = useCallback(async () => {
    if (refunding) return;
    setRefunding(true);
    setRefundResult(null);
    try {
      await refundDeposit(deposit.vaultOpId);
      setRefundResult('Deposit refunded.');
      await onRefresh();
    } catch (e) {
      setRefundResult(`Error: ${e instanceof Error ? e.message : 'Refund failed'}`);
    } finally {
      setRefunding(false);
    }
  }, [refunding, deposit.vaultOpId, onRefresh]);

  const isDone = deposit.status === 'completed';
  const isRefundable = isRefundableDeposit(deposit.status);
  const isWaiting = !isDone && (fundingTxid || deposit.status === 'awaiting_confirmation' || (isExitDeposit && deposit.status === 'initiated'));
  const hasProgress = confirmations !== null && confirmRequired !== null && confirmRequired > 0;
  const progressPct = hasProgress ? Math.min(100, Math.round((confirmations! / confirmRequired!) * 100)) : 0;

  const statusText = completing
    ? (isExitDeposit ? 'Finalizing' : 'Completing')
    : hasProgress && !isDone && !isRefundable
      ? (confirmReady ? 'Confirmed' : `${confirmations}/${confirmRequired} confirmed`)
      : depositStatusLabel(deposit.status);

  return (
    <div
      className="sb-card btc-deposit"
      style={{ cursor: 'pointer', padding: '8px 10px' }}
      onClick={() => setExpanded(!expanded)}
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      onKeyDown={(e) => e.key === 'Enter' && setExpanded(!expanded)}
    >
      <div className="sb-row" style={{ padding: 0, borderBottom: 0 }}>
        <div className="sb-row__main">
          <div className="sb-row__title">{isExitDeposit ? 'Withdrawal' : 'Deposit'}</div>
          <div className="sb-row__sub">{directionLabel(deposit.direction)}</div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div className="sb-row__amount">{formatBtc(deposit.btcAmountSats)} BTC</div>
          <span className={`sb-tag${isDone ? ' sb-tag--solid' : isRefundable ? ' sb-tag--dim' : ''}`}>{statusText}</span>
        </div>
      </div>
      {isWaiting && hasProgress && !confirmReady && (
        <div className="sb-progress" style={{ marginTop: 6 }} aria-label="Confirmation progress">
          <div className="sb-progress__fill" style={{ width: `${progressPct}%` }} />
        </div>
      )}

      {expanded && (
        <div style={{ marginTop: 8, paddingTop: 6, borderTop: '1px dashed var(--border)' }} onClick={(e) => e.stopPropagation()}>
          {isWaiting && (
            <p className="sb-hint">
              {completing
                ? (isExitDeposit ? 'Finalizing withdrawal…' : 'Completing deposit…')
                : hasProgress
                  ? (confirmReady
                    ? `Confirmed (${confirmations}/${confirmRequired}). Completing…`
                    : `Waiting for the Bitcoin network: ${confirmations} of ${confirmRequired} confirmations.`)
                  : isExitDeposit && !fundingTxid
                    ? 'Waiting for the withdrawal transaction to broadcast…'
                    : 'Checking confirmation status…'}
            </p>
          )}
          <div className="sb-kv">
            <span className="sb-kv__k">Deposit ID</span>
            <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(deposit.vaultOpId, 8, 8)}</span>
          </div>
          {deposit.htlcAddress && (
            <div className="sb-kv">
              <span className="sb-kv__k">HTLC address</span>
              <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(deposit.htlcAddress, 10, 10)}</span>
            </div>
          )}
          {deposit.vaultId && (
            <div className="sb-kv">
              <span className="sb-kv__k">Vault</span>
              <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(deposit.vaultId, 8, 8)}</span>
            </div>
          )}
          <div className="sb-kv">
            <span className="sb-kv__k">Status</span>
            <span className="sb-kv__v">{deposit.status}</span>
          </div>
          {fundingTxid && (
            <>
              <div className="sb-kv">
                <span className="sb-kv__k">{isExitDeposit ? 'Withdrawal tx' : 'Funding tx'}</span>
                <span className="sb-kv__v sb-kv__v--mono">{middleTruncate(fundingTxid, 10, 10)}</span>
              </div>
              <ExplorerLink
                url={mempoolExplorerUrl(fundingTxid, network)}
                onCopied={() => setStatusMessage('Explorer link copied to clipboard')}
                onCopyFailed={(url) => setStatusMessage(`URL: ${url}`)}
              />
            </>
          )}

          {statusMessage && (
            <div className={`sb-notice${statusMessage.startsWith('Error') || statusMessage.includes('failed') ? ' sb-notice--error' : ''}`} style={{ marginTop: 8 }}>
              <span className="sb-mono" style={{ whiteSpace: 'pre-wrap' }}>{statusMessage}</span>
            </div>
          )}

          {isRefundable && (
            <div style={{ marginTop: 8 }}>
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); void handleRefund(); }}
                className="sb-btn sb-btn--block"
                disabled={refunding}
              >
                {refunding ? 'Refunding…' : 'Refund expired deposit'}
              </button>
              {refundResult && (
                <div className={`sb-notice${refundResult.startsWith('Error') ? ' sb-notice--error' : ''}`} style={{ marginTop: 6 }}>
                  {refundResult}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
