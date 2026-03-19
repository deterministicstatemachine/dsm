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
import { decodeOfflinePendingList, PendingBilateralDto } from '../../domain/bilateral';
import { acceptPendingTransfer, rejectPendingTransfer } from '../../services/bilateral/pendingBilateralService';
import '../../styles/BilateralTransfer.css';

type PendingTransaction = PendingBilateralDto;

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
  | 'dev_dlv'
  | 'dev_policy';

interface Props {
  onNavigate?: (screen: ScreenType) => void;
}

const PendingBilateralPanel: React.FC<Props> = ({ onNavigate }) => {
  const [pending, setPending] = useState<PendingTransaction[]>([]);
  const [error, setError] = useState<string>('');
  const [processing, setProcessing] = useState<string | null>(null);

  // Extract sync logic to useCallback so we can trigger it from multiple places
  const sync = useCallback(async () => {
    try {
      const bytes = await getPendingBilateralListStrictBridge();
      const mapped = await decodeOfflinePendingList(bytes);
      setPending(mapped);
    } catch (err) {
      logger.error('[PendingBilateral] Failed to sync authoritative state:', err);
      // Do not set global error that blocks UI, just log it. 
      // We want the panel to remain usable even if one sync fails.
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

  const handleAccept = async (tx: PendingTransaction) => {
    setProcessing(tx.id);
    setError('');

    try {
      logger.info('[PendingBilateral] Accepting transaction:', tx.id, 'commitment:', tx.commitmentHash);

      const result = await acceptPendingTransfer({
        commitmentHashB32: tx.commitmentHash,
        counterpartyDeviceIdB32: tx.counterpartyDeviceId,
      });

      if (!result.success) {
        // Display RAW error from bridge result if available
        const msg = result.error || 'Accept failed (unknown)';
        setError(msg);
        return;
      }
      
      // Force immediate sync
      // (The event listener will also catch it, but this makes UI snappy)
      await getPendingBilateralListStrictBridge();
      // ... same decoding logic ... (simplified for button handler, relying on main sync usually)
      // Actually, relying on the event listener triggered by the native side is safer for SSOT.
      // But we can manually trigger the sync logic if we extract `sync` to a ref or useCallback.
      // For now, let's trust the event + visibility + initial. 
      // Or we can just call the bridge again here.
      
      logger.info('[PendingBilateral] Transaction accepted and response sent');

    } catch (err) {
      logger.error('[PendingBilateral] Accept failed:', err);
      setError(`Accept failed: ${err}`);
    } finally {
      setProcessing(null);
    }
  };

  const handleReject = async (tx: PendingTransaction) => {
    setProcessing(tx.id);
    setError('');

    try {
      logger.info('[PendingBilateral] Rejecting transaction:', tx.id);

      const result = await rejectPendingTransfer({
        commitmentHashB32: tx.commitmentHash,
        counterpartyDeviceIdB32: tx.counterpartyDeviceId,
        reason: 'User declined transfer',
      });

      if (!result.success) {
         // Display RAW error
        const msg = result.error || 'Reject failed (unknown)';
        setError(msg);
        return;
      }

      logger.info('[PendingBilateral] Transaction rejected and response sent');

    } catch (err) {
      logger.error('[PendingBilateral] Reject failed:', err);
      setError(`Reject failed: ${err}`);
    } finally {
      setProcessing(null);
    }
  };

  return (
    <div style={{ padding: '16px', fontFamily: "'Martian Mono', monospace", color: 'var(--text)' }}>
      <h2 style={{ fontSize: '14px', marginBottom: '16px', borderBottom: '2px solid var(--border)', paddingBottom: '8px', textTransform: 'uppercase' }}>
        PENDING BILATERAL TRANSFERS
      </h2>

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

      {pending.length === 0 ? (
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
                  <ArrowIcon direction={tx.type === 'incoming' ? 'down' : 'up'} size={12} color={'var(--stateboy-dark)'} />
                  {tx.type === 'incoming' ? 'INCOMING' : 'OUTGOING'}
                </span>
                <span style={{
                  fontSize: '10px',
                  color: 'var(--text)',
                  textTransform: 'uppercase',
                  fontWeight: 'bold',
                }}>
                  {tx.status === 'verified' ? '[VERIFIED]' : 
                   tx.status === 'hash_mismatch' ? '[HASH MISMATCH]' :
                   tx.status === 'rejected' ? '[REJECTED]' :
                   tx.status === 'committed' ? `[COMMITTED ${tx.commitmentHash.slice(0, 8)}]` :
                   tx.status === 'accepted' ? `[ACCEPTED ${tx.commitmentHash.slice(0, 8)}]` :
                   tx.status === 'failed' ? '[FAILED]' :
                   `[${tx.status.toUpperCase()}]`}
                </span>
              </div>

              {tx.verificationStatus && (
                <div style={{
                  padding: '8px',
                  marginBottom: '12px',
                  borderRadius: '4px',
                  fontSize: '10px',
                  background: 'rgba(var(--text-rgb),0.15)',
                  border: '1px solid var(--border)',
                  color: 'var(--text)',
                }}>
                  {tx.verificationStatus === 'verified' && '> Chain tip verified - sender has correct view of your state'}
                  {tx.verificationStatus === 'failed' && '> Chain tip mismatch - sender has stale view, needs online sync'}
                  {tx.verificationStatus === 'pending' && '> Verification pending...'}
                </div>
              )}

              <div style={{ marginBottom: '12px' }}>
                <div style={{ fontSize: '12px', marginBottom: '4px' }}>
                  <span style={{ color: 'var(--text-disabled)' }}>From:</span>{' '}
                  <span style={{ color: 'var(--text)' }}>{tx.counterpartyAlias}</span>
                  <span style={{ color: 'var(--text-disabled)', fontSize: '9px', marginLeft: '8px' }}>
                    ({tx.counterpartyDeviceId.slice(0, 8)}...)
                  </span>
                </div>
                <div style={{ fontSize: '14px', fontWeight: 'bold', marginBottom: '4px', color: 'var(--text)' }}>
                  {tx.amount} {tx.tokenId}
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

              {tx.type === 'incoming' && (tx.status === 'pending' || tx.status === 'verified') && (
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

              {tx.status === 'hash_mismatch' && (
                <div style={{ 
                  padding: '8px', 
                  background: 'rgba(var(--text-rgb),0.15)', 
                  borderRadius: '4px',
                  fontSize: '10px',
                  color: 'var(--text)',
                  border: '1px solid var(--border)',
                }}>
                  {'>'} Auto-rejected: Chain tip mismatch detected. Sender needs to perform online reconciliation.
                </div>
              )}

              {tx.status === 'accepted' && (
                <div style={{
                  padding: '8px',
                  background: 'rgba(var(--text-rgb),0.15)',
                  borderRadius: '4px',
                  fontSize: '10px',
                  color: 'var(--text)',
                  border: '1px solid var(--border)',
                }}>
                  {'>'} Accepted. Waiting for sender to finalize commit over BLE.
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
