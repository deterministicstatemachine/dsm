// SPDX-License-Identifier: Apache-2.0
// Pending Bilateral Transactions Screen - Handle incoming/outgoing bilateral transfers

import React, { useEffect, useState, useCallback } from 'react';
import ArrowIcon from '../icons/ArrowIcon';
import logger from '../../utils/logger';
import {
  getPendingBilateralListStrictBridge,
  addDsmEventListener,
} from '../../dsm/WebViewBridge';
// Move protobuf parsing out of UI; use domain decoder
import { decodeOfflinePendingList, PendingBilateralDto, PendingBilateralPhase } from '../../domain/bilateral';
import {
  acceptPendingTransfer,
  cancelPendingTransfer,
  rejectPendingTransfer,
} from '../../services/bilateral/pendingBilateralService';
import '../../styles/BilateralTransfer.css';

type PendingTransaction = PendingBilateralDto;

/** Each phase as the SDK's session store defines it. */
const PHASE_LABEL: Record<PendingBilateralPhase, string> = {
  preparing: 'PREPARING',
  prepared: 'SENT, AWAITING PEER',
  pending_user_action: 'AWAITING YOUR DECISION',
  accepted: 'ACCEPTED',
  rejected: 'REJECTED',
  confirm_pending: 'CONFIRMED, AWAITING PEER',
  committed: 'COMMITTED',
  failed: 'FAILED',
};

function amountLabel(tx: PendingTransaction): string {
  return tx.displayAmount !== undefined
    ? `${tx.displayAmount} ${tx.tokenId}`
    : `${tx.amount.toString()} ${tx.tokenId} base units`;
}

type ScreenType =
  | 'home'
  | 'wallet'
  | 'vault'
  | 'transactions'
  | 'contacts'
  | 'accounts'
  | 'storage'
  | 'settings'
  | 'tokens'
  | 'qr'
  | 'mycontact'
  | 'pending_bilateral'
  | 'dev_policy';

interface Props {
  onNavigate?: (screen: ScreenType) => void;
}

const PendingBilateralPanel: React.FC<Props> = ({ onNavigate }) => {
  const [pending, setPending] = useState<PendingTransaction[]>([]);
  // Until the SDK has answered once, there is no list to show, empty or not.
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string>('');
  const [syncError, setSyncError] = useState<string>('');
  const [processing, setProcessing] = useState<string | null>(null);

  // Extract sync logic to useCallback so we can trigger it from multiple places
  const sync = useCallback(async () => {
    try {
      const bytes = await getPendingBilateralListStrictBridge();
      const mapped = await decodeOfflinePendingList(bytes);
      setPending(mapped);
      setLoaded(true);
      setSyncError('');
    } catch (err) {
      logger.error('[PendingBilateral] Failed to sync authoritative state:', err);
      // The list below is the last one the SDK answered; say so rather than
      // present it as current.
      setSyncError(`Could not read the pending list: ${err instanceof Error ? err.message : String(err)}`);
    }
  }, []);

  useEffect(() => {
    // 1. Initial sync
    sync();

    // 2. Foreground sync (self-healing on app resume)
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        logger.info('[PendingBilateral] App resumed, forcing authoritative sync');
        sync();
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);

    // 3. Event trigger sync (replace accumulation)
    // Listen for any 'bilateral.*' event and re-fetch.
    const cleanup = addDsmEventListener((evt) => {
        if (evt.topic.startsWith('bilateral.')) {
             logger.info('[PendingBilateral] Event received, triggering sync:', evt.topic);
             sync();
        }
    });

    return () => {
        document.removeEventListener('visibilitychange', onVisibilityChange);
        cleanup();
    };
  }, [sync]);

  const act = async (
    tx: PendingTransaction,
    verb: string,
    action: () => Promise<{ success: true } | { success: false; error: string }>,
  ) => {
    setProcessing(tx.id);
    setError('');
    try {
      logger.info(`[PendingBilateral] ${verb}:`, tx.id);
      const result = await action();
      if (!result.success) {
        setError(`${verb} failed: ${result.error}`);
        return;
      }
      await sync();
    } catch (err) {
      logger.error(`[PendingBilateral] ${verb} failed:`, err);
      setError(`${verb} failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setProcessing(null);
    }
  };

  const handleAccept = (tx: PendingTransaction) =>
    act(tx, 'Accept', () =>
      acceptPendingTransfer({
        commitmentHashB32: tx.commitmentHash,
        counterpartyDeviceIdB32: tx.counterpartyDeviceId,
      }),
    );

  const handleReject = (tx: PendingTransaction) =>
    act(tx, 'Reject', () =>
      rejectPendingTransfer({
        commitmentHashB32: tx.commitmentHash,
        counterpartyDeviceIdB32: tx.counterpartyDeviceId,
        reason: 'User declined transfer',
      }),
    );

  const handleCancel = (tx: PendingTransaction) =>
    act(tx, 'Cancel', () =>
      cancelPendingTransfer({
        commitmentHashB32: tx.commitmentHash,
        reason: 'Sender cancelled transfer',
      }),
    );

  return (
    <div style={{ padding: '16px', fontFamily: "'Martian Mono', monospace", color: 'var(--text)' }}>
      <h2 style={{ fontSize: '14px', marginBottom: '16px', borderBottom: '2px solid var(--border)', paddingBottom: '8px', textTransform: 'uppercase' }}>
        PENDING BILATERAL TRANSFERS
      </h2>

      {syncError && (
        <div role="alert" style={{
          padding: '12px',
          marginBottom: '16px',
          background: 'rgba(var(--text-rgb),0.15)',
          border: '2px solid var(--border)',
          color: 'var(--text)',
          fontSize: '11px',
          borderRadius: '8px',
        }}>
          {syncError}
        </div>
      )}

      {error && (
        <div role="alert" style={{
          padding: '12px',
          marginBottom: '16px',
          background: 'rgba(var(--text-rgb),0.15)',
          border: '2px solid var(--border)',
          color: 'var(--text)',
          fontSize: '11px',
          borderRadius: '8px',
        }}>
          {error}
        </div>
      )}

      {!loaded ? null : pending.length === 0 ? (
        <div style={{
          padding: '32px',
          textAlign: 'center',
          color: 'var(--text-disabled)',
          fontSize: '12px',
          border: '2px dashed var(--border)',
          borderRadius: '8px',
        }}>
          <div style={{ marginBottom: '8px', fontSize: '16px', fontWeight: 'bold' }} aria-hidden>[ OK ]</div>
          <div>No pending bilateral transfers</div>
          <div style={{ marginTop: '8px', fontSize: '10px' }}>
            Incoming transfer requests will appear here
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {pending.map(tx => (
            <div
              key={tx.id}
              style={{
                padding: '16px',
                background: 'rgba(var(--text-rgb),0.08)',
                border: '2px solid var(--border)',
                borderRadius: '8px',
              }}
            >
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                marginBottom: '12px',
                paddingBottom: '8px',
                borderBottom: '1px solid var(--border)',
              }}>
                <span style={{ fontSize: '10px', color: 'var(--text)', textTransform: 'uppercase', display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                  <ArrowIcon direction={tx.direction === 'incoming' ? 'down' : 'up'} size={12} color={'var(--stateboy-dark)'} />
                  {tx.direction === 'incoming' ? 'INCOMING' : 'OUTGOING'}
                </span>
                <span style={{
                  fontSize: '10px',
                  color: 'var(--text)',
                  textTransform: 'uppercase',
                  fontWeight: 'bold',
                }}>
                  [{PHASE_LABEL[tx.phase]}]
                </span>
              </div>

              <div style={{ marginBottom: '12px' }}>
                <div style={{ fontSize: '12px', marginBottom: '4px' }}>
                  <span style={{ color: 'var(--text-disabled)' }}>{tx.direction === 'incoming' ? 'From:' : 'To:'}</span>{' '}
                  {tx.counterpartyAlias !== undefined && (
                    <span style={{ color: 'var(--text)' }}>{tx.counterpartyAlias}</span>
                  )}
                  <span style={{ color: 'var(--text-disabled)', fontSize: '9px', marginLeft: '8px' }}>
                    ({tx.counterpartyDeviceId.slice(0, 8)}...)
                  </span>
                </div>
                <div style={{ fontSize: '14px', fontWeight: 'bold', marginBottom: '4px', color: 'var(--text)' }}>
                  {amountLabel(tx)}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-disabled)' }}>
                  Commitment: {tx.commitmentHash.slice(0, 16)}...
                </div>
                {tx.bleAddress && (
                  <div style={{ fontSize: '9px', color: 'var(--text-disabled)', marginTop: '2px' }}>
                    BLE: {tx.bleAddress}
                  </div>
                )}
              </div>

              {tx.direction === 'incoming' && tx.phase === 'pending_user_action' && (
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => handleAccept(tx)}
                    disabled={processing === tx.id}
                    style={{
                      flex: 1,
                      padding: '10px',
                      background: 'linear-gradient(0deg, rgba(var(--text-rgb),0.15), rgba(var(--bg-rgb),0.3))',
                      color: 'var(--text)',
                      border: '2px solid var(--border)',
                      borderRadius: '8px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      fontFamily: "'Martian Mono', monospace",
                      textTransform: 'uppercase',
                      cursor: processing === tx.id ? 'not-allowed' : 'pointer',
                      opacity: processing === tx.id ? 0.5 : 1,
                    }}
                  >
                    {processing === tx.id ? <span className="bilateral-spinner" /> : 'ACCEPT'}
                  </button>
                  <button
                    onClick={() => handleReject(tx)}
                    disabled={processing === tx.id}
                    style={{
                      flex: 1,
                      padding: '10px',
                      background: 'rgba(var(--text-rgb),0.08)',
                      color: 'var(--text)',
                      border: '2px solid var(--border)',
                      borderRadius: '8px',
                      fontSize: '11px',
                      fontWeight: 'bold',
                      fontFamily: "'Martian Mono', monospace",
                      textTransform: 'uppercase',
                      cursor: processing === tx.id ? 'not-allowed' : 'pointer',
                      opacity: processing === tx.id ? 0.5 : 1,
                    }}
                  >
                    REJECT
                  </button>
                </div>
              )}

              {tx.cancellable && (
                <button
                  onClick={() => handleCancel(tx)}
                  disabled={processing === tx.id}
                  style={{
                    width: '100%',
                    padding: '10px',
                    background: 'rgba(var(--text-rgb),0.08)',
                    color: 'var(--text)',
                    border: '2px solid var(--border)',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontWeight: 'bold',
                    fontFamily: "'Martian Mono', monospace",
                    textTransform: 'uppercase',
                    cursor: processing === tx.id ? 'not-allowed' : 'pointer',
                    opacity: processing === tx.id ? 0.5 : 1,
                  }}
                >
                  {processing === tx.id ? <span className="bilateral-spinner" /> : 'CANCEL'}
                </button>
              )}

              {tx.direction === 'incoming' && tx.phase === 'accepted' && (
                <div style={{
                  padding: '8px',
                  background: 'rgba(var(--text-rgb),0.15)',
                  borderRadius: '4px',
                  fontSize: '10px',
                  color: 'var(--text)',
                  border: '1px solid var(--border)',
                }}>
                  {'>'} Accepted. Waiting for the sender to finalize over BLE.
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {onNavigate && (
        <button
          onClick={() => onNavigate('home')}
          style={{
            marginTop: '24px',
            width: '100%',
            padding: '12px',
            background: 'rgba(var(--text-rgb),0.08)',
            color: 'var(--text)',
            border: '2px solid var(--border)',
            borderRadius: '8px',
            fontSize: '11px',
            fontFamily: "'Martian Mono', monospace",
            textTransform: 'uppercase',
            cursor: 'pointer',
          }}
        >
          {'<'} BACK TO HOME
        </button>
      )}
    </div>
  );
};

export default PendingBilateralPanel;
