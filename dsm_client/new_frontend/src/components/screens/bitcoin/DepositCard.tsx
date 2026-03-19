// SPDX-License-Identifier: Apache-2.0
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { refundDeposit, formatBtc, mempoolExplorerUrl } from '../../../services/bitcoinTap';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import type { DepositEntry } from '../../../services/bitcoinTap';

type Props = {
  deposit: DepositEntry;
  onRefresh: () => Promise<void>;
  network: number;
};

const statusLabel: Record<string, string> = {
  initiated: 'Initiated',
  awaiting_confirmation: 'Confirming',
  claimable: 'Claimable',
  completed: 'Complete',
  expired: 'Expired',
  refunded: 'Refunded',
};

export default function DepositCard({ deposit, onRefresh, network }: Props): JSX.Element {
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
          setStatusMessage(isExitDeposit ? 'Finalizing exit...' : 'Completing deposit...');
          try {
            const result = isExitDeposit
              ? await completeExitDeposit(deposit.vaultOpId)
              : await awaitAndComplete(deposit.vaultOpId);
            if (cancelled) return;
            completedOnceRef.current = true;
            setStatusMessage(isExitDeposit ? `Exit completed: ${result}` : `Deposit completed: ${result}`);
            bridgeEvents.emit('deposit.completed', { depositId: deposit.vaultOpId, amount: formatBtc(deposit.btcAmountSats) });
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
        setStatusMessage('Auto-funding deposit...');
        const { fundAndBroadcast } = await import('../../../services/bitcoinTap');
        const txid = await fundAndBroadcast(deposit.vaultOpId);
        if (cancelled) return;
        setStatusMessage(`Broadcast! txid: ${txid.slice(0, 16)}...`);
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
      setRefundResult('Deposit refunded successfully');
      await onRefresh();
    } catch (e) {
      setRefundResult(`Error: ${e instanceof Error ? e.message : 'Refund failed'}`);
    } finally {
      setRefunding(false);
    }
  }, [refunding, deposit.vaultOpId, onRefresh]);

  const displayStatus = statusLabel[deposit.status] || deposit.status;
  const directionLabel = deposit.direction === 'btc_to_dbtc' ? 'BTC \u2192 dBTC' : 'dBTC \u2192 BTC';
  const statusColor = deposit.status === 'completed'
    ? 'var(--text-dark)'
    : deposit.status === 'expired'
      ? 'var(--text-disabled)'
      : 'var(--text-dark)';
  const isRefundable = deposit.status === 'expired' || deposit.status === 'timed_out' || deposit.status === 'timeout';

  return (
    <div
      className={`transaction-item ${expanded ? 'expanded' : ''}`}
      style={{ cursor: 'pointer', flexDirection: 'column', alignItems: 'stretch' }}
      onClick={() => setExpanded(!expanded)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && setExpanded(!expanded)}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%' }}>
        <div className="transaction-type" style={{ fontSize: 11 }}>{directionLabel}</div>
        <div style={{ flex: 1, textAlign: 'right', fontSize: 12, fontWeight: 500 }}>{formatBtc(deposit.btcAmountSats)} BTC</div>
        <div style={{ fontSize: 10, color: statusColor, fontWeight: 500, whiteSpace: 'nowrap' }}>{displayStatus}</div>
      </div>

      {expanded && (
        <div className="transaction-expanded-details" onClick={(e) => e.stopPropagation()}>
          <div className="detail-row">
            <span className="detail-label">Deposit ID</span>
            <span className="detail-value tx-id">{deposit.vaultOpId.length > 16 ? `${deposit.vaultOpId.slice(0, 8)}...${deposit.vaultOpId.slice(-8)}` : deposit.vaultOpId}</span>
          </div>
          {deposit.htlcAddress && (
            <div className="detail-row">
              <span className="detail-label">HTLC Address</span>
              <span className="detail-value tx-id">{deposit.htlcAddress.length > 20 ? `${deposit.htlcAddress.slice(0, 10)}...${deposit.htlcAddress.slice(-10)}` : deposit.htlcAddress}</span>
            </div>
          )}
          {deposit.vaultId && (
            <div className="detail-row">
              <span className="detail-label">Vault ID</span>
              <span className="detail-value tx-id">{deposit.vaultId.length > 16 ? `${deposit.vaultId.slice(0, 8)}...${deposit.vaultId.slice(-8)}` : deposit.vaultId}</span>
            </div>
          )}
          <div className="detail-row">
            <span className="detail-label">Direction</span>
            <span className="detail-value">{deposit.direction}</span>
          </div>

          {fundingTxid && (
            <div style={{ marginTop: 4 }}>
              <div className="detail-row">
                <span className="detail-label">{isExitDeposit ? 'Withdrawal TX' : 'Funding TX'}</span>
                <span className="detail-value tx-id" style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 10 }}>
                  {fundingTxid.length > 20 ? `${fundingTxid.slice(0, 10)}\u2026${fundingTxid.slice(-10)}` : fundingTxid}
                </span>
              </div>
              {(() => {
                const url = mempoolExplorerUrl(fundingTxid, network);
                return (
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={(e) => {
                      e.stopPropagation();
                      navigator.clipboard.writeText(url).then(
                        () => setStatusMessage('Explorer link copied to clipboard'),
                        () => setStatusMessage(`URL: ${url}`),
                      );
                    }}
                    onKeyDown={(e) => e.key === 'Enter' && (e.stopPropagation(), navigator.clipboard.writeText(url).then(
                      () => setStatusMessage('Explorer link copied to clipboard'),
                      () => setStatusMessage(`URL: ${url}`),
                    ))}
                    style={{ marginTop: 4, fontSize: 10, color: 'var(--text-dark)', textDecoration: 'underline', wordBreak: 'break-all', cursor: 'copy', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', padding: '2px 0' }}
                    title="Click to copy explorer link"
                  >
                    {url}
                  </div>
                );
              })()}
            </div>
          )}

          {(fundingTxid || deposit.status === 'awaiting_confirmation' || (isExitDeposit && deposit.status === 'initiated')) && deposit.status !== 'completed' && (
            <div style={{ marginTop: 8 }}>
              <div style={{ padding: '6px 8px', border: '1px solid var(--border)', borderRadius: 6, fontSize: 10, color: 'var(--text-dark)', background: 'var(--bg)', textAlign: 'center' }}>
                {completing
                  ? 'Completing deposit...'
                  : confirmations !== null && confirmRequired !== null
                    ? confirmReady
                      ? `Confirmed (${confirmations}/${confirmRequired}) \u2014 completing...`
                      : `Waiting for confirmations: ${confirmations}/${confirmRequired}`
                    : isExitDeposit && !fundingTxid
                      ? 'Waiting for withdrawal transaction broadcast...'
                      : 'Checking confirmation status...'}
              </div>
            </div>
          )}

          {statusMessage && (
            <div style={{ marginTop: 8, padding: '6px 8px', border: '1px solid var(--border)', borderRadius: 4, fontSize: 10, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: 'var(--text-dark)', background: statusMessage.startsWith('Error') ? 'var(--bg-secondary)' : 'var(--bg)', borderStyle: statusMessage.startsWith('Error') ? 'dashed' : 'solid' }}>
              {statusMessage}
            </div>
          )}

          {isRefundable && (
            <div style={{ marginTop: 8 }}>
              <button
                onClick={(e) => { e.stopPropagation(); void handleRefund(); }}
                className="button-brick"
                disabled={refunding}
                style={{ width: '100%', padding: '8px 12px', fontSize: 11, borderRadius: 8, cursor: refunding ? 'not-allowed' : 'pointer', background: 'var(--bg)', border: '2px dashed var(--border)', color: 'var(--text-dark)' }}
              >
                {refunding ? 'Refunding...' : 'Refund Expired Deposit'}
              </button>
              {refundResult && (
                <div style={{ marginTop: 6, padding: '4px 8px', border: '1px solid var(--border)', borderRadius: 4, fontSize: 10, color: 'var(--text-dark)', background: refundResult.startsWith('Error') ? 'var(--bg-secondary)' : 'var(--bg)', borderStyle: refundResult.startsWith('Error') ? 'dashed' : 'solid' }}>
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
