// SPDX-License-Identifier: Apache-2.0
// Bilateral Transfer Accept/Reject Dialog and Status Display
import React, { useState, useEffect, useCallback } from 'react';
import { on as eventBridgeOn } from '../dsm/EventBridge';
import { acceptIncomingTransfer, BilateralEventType, BilateralTransferEvent, decodeBilateralEvent, rejectIncomingTransfer } from '../services/bilateral/bilateralEventService';
import { useWallet } from '../contexts/WalletContext';
import { useUX } from '../contexts/UXContext';
import '../styles/BilateralTransfer.css';
import { emitWalletRefresh } from '../dsm/events';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { formatTokenAmount } from '../utils/tokenMeta';

interface BilateralTransferDialogProps {
  /** Optional: limit to specific contact alias */
  contactAlias?: string;
}

export const BilateralTransferDialog: React.FC<BilateralTransferDialogProps> = ({ contactAlias: _contactAlias }) => {
  const [incomingTransfer, setIncomingTransfer] = useState<BilateralTransferEvent | null>(null);
  const [outgoingTransfer, setOutgoingTransfer] = useState<BilateralTransferEvent | null>(null);
  const [processing, setProcessing] = useState(false);
  const { refreshAll } = useWallet();
  const { hideComplexity } = useUX();
  const [inboxOpen, setInboxOpen] = useState(false);

  // Hide bilateral overlay when inbox is open
  useEffect(() => {
    const handler = (detail: { open: boolean }) => {
      setInboxOpen(Boolean(detail?.open));
    };
    return bridgeEvents.on('inbox.open', handler);
  }, []);

  // Subscribe to bilateral events
  useEffect(() => {
    const unsubscribe = eventBridgeOn('bilateral.event', (payload: Uint8Array) => {
      try {
        const event = decodeBilateralEvent(payload);
        if (!event) return;

        // Handle different event types
        switch (event.eventType) {
          case BilateralEventType.PREPARE_RECEIVED:
            // Incoming transfer request
            console.warn('[BilateralTransfer] PREPARE_RECEIVED event: senderBleAddress=', event.senderBleAddress, 'commitmentHash=', event.commitmentHash);
            setIncomingTransfer(event);
            break;

          case BilateralEventType.ACCEPT_SENT:
            // We accepted an incoming transfer
            setIncomingTransfer(null);
            break;

          case BilateralEventType.TRANSFER_COMPLETE:
            // Transfer completed (either direction) - refresh wallet to show updated balance
            console.warn('[BilateralTransfer] TRANSFER_COMPLETE - refreshing wallet state');
            setIncomingTransfer(null);
            setOutgoingTransfer(null);
            // Refresh balances and transaction history to reflect the completed transfer
            refreshAll().catch(err => console.error('[BilateralTransfer] refreshAll failed:', err));
            // Also dispatch events for other listeners (e.g., TransactionList / Wallet screens)
            // Ensure we broadcast both balance and history refresh so all wallet UI tabs update
            try { emitWalletRefresh({ source: 'bilateral.transfer_complete_dialog' }); } catch {}
            break;

          case BilateralEventType.REJECTED:
          case BilateralEventType.FAILED:
            // Transfer failed
            setIncomingTransfer(null);
            setOutgoingTransfer(null);
            break;

          default:
            break;
        }
      } catch {
        // Error parsing bilateral event
      }
    });

    return () => unsubscribe();
  }, [refreshAll]);

  const handleAccept = useCallback(async () => {
    if (!incomingTransfer) return;
    
    setProcessing(true);
    try {
      const result = await acceptIncomingTransfer(incomingTransfer);

      if (result.success) {
        setIncomingTransfer(null);
      } else {
        alert('Failed to accept transfer');
      }
    } catch (err) {
      console.error('[BilateralTransfer] Accept error:', err);
      alert(`Error accepting transfer: ${err}`);
    } finally {
      setProcessing(false);
    }
  }, [incomingTransfer]);

  const handleReject = useCallback(async () => {
    if (!incomingTransfer) return;
    setProcessing(true);
    try {
      const result = await rejectIncomingTransfer(incomingTransfer, 'User rejected transfer');
      if (!result.success) alert('Failed to reject transfer');
      setIncomingTransfer(null);
    } catch (err) {
      console.error('[BilateralTransfer] Reject error:', err);
      alert(`Error rejecting transfer: ${err}`);
    } finally {
      setProcessing(false);
    }
  }, [incomingTransfer]);

  // Don't render if no active transfers or inbox is open
  if ((!incomingTransfer && !outgoingTransfer) || inboxOpen) {
    return null;
  }

  return (
    <div className="bilateral-transfer-overlay">
      {incomingTransfer && (
        <div className="bilateral-transfer-dialog">
          <div className="bilateral-transfer-header">
            <h3>Incoming Offline Transfer</h3>
          </div>
          <div className="bilateral-transfer-body">
            <div className="bilateral-transfer-info">
              <div className="bilateral-transfer-label">From:</div>
              <div className="bilateral-transfer-value">
                {incomingTransfer.counterpartyDeviceId.slice(0, 12)}…
              </div>
            </div>
            
            {incomingTransfer.amount !== undefined && incomingTransfer.amount !== null && (
              <div className="bilateral-transfer-info">
                <div className="bilateral-transfer-label">Amount:</div>
                <div className="bilateral-transfer-value">
                  {(() => {
                    const raw = incomingTransfer.amount;
                    const rawTid = incomingTransfer.tokenId || 'ERA';
                    const tid = rawTid.toUpperCase();
                    const abs = typeof raw === 'bigint' ? raw : BigInt(String(raw));
                    return `${formatTokenAmount(abs, rawTid)} ${tid}`;
                  })()}
                </div>
              </div>
            )}
            <div className="bilateral-transfer-message">
              {incomingTransfer.message}
            </div>
            {!hideComplexity && (
              <div className="bilateral-transfer-info">
                <div className="bilateral-transfer-label">Commitment (Audit):</div>
                <div className="bilateral-transfer-value" style={{ fontFamily: 'monospace', fontSize: '0.8em', wordBreak: 'break-all' }}>
                  {incomingTransfer.commitmentHash}
                </div>
              </div>
            )}
          </div>
          <div className="bilateral-transfer-actions">
            <button
              className="bilateral-btn bilateral-btn-reject"
              onClick={handleReject}
              disabled={processing}
            >
              Reject
            </button>
            <button
              className="bilateral-btn bilateral-btn-accept"
              onClick={handleAccept}
              disabled={processing}
              style={{
                 opacity: processing ? 0.6 : 1,
                 cursor: processing ? 'not-allowed' : 'pointer'
              }}
            >
              {processing ? <span className="bilateral-spinner" /> : 'Accept'}
            </button>
          </div>
        </div>
      )}

      {outgoingTransfer && (
        <div className="bilateral-transfer-status">
          <div className="bilateral-transfer-status-header">
            <h4>Outgoing Transfer</h4>
          </div>
          <div className="bilateral-transfer-status-body">
            <div className="bilateral-transfer-status-progress">
              <div className="progress-step active">Preparing</div>
              <div className={`progress-step ${outgoingTransfer.eventType >= BilateralEventType.ACCEPT_SENT ? 'active' : ''}`}>
                Accepted
              </div>
              <div className={`progress-step ${outgoingTransfer.eventType >= BilateralEventType.COMMIT_RECEIVED ? 'active' : ''}`}>
                Committed
              </div>
              <div className={`progress-step ${outgoingTransfer.eventType === BilateralEventType.TRANSFER_COMPLETE ? 'active' : ''}`}>
                Complete
              </div>
            </div>
            <div className="bilateral-transfer-status-message">
              {outgoingTransfer.message}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BilateralTransferDialog;
