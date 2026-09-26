// SPDX-License-Identifier: Apache-2.0
// Reusable transaction row component for overview and history tabs. Renders
// the row exactly as Rust reported it.
import React from 'react';
import { txTypeLabel, txTypeDetail, formatTxAmount } from './helpers';
import ArrowIcon from '../../icons/ArrowIcon';
import { TokenMark } from '../../TokenMark';
import StitchedReceiptDetails from '../../receipts/StitchedReceiptDetails';
import type { DomainTransaction } from '../../../domain/types';

type Props = {
  tx: DomainTransaction;
  expandedTxId: string | null;
  onToggle: (txId: string) => void;
};

function TransactionItemInner({ tx, expandedTxId, onToggle }: Props): React.JSX.Element {
  const isOutgoing = tx.amount < 0n;
  const isExpanded = expandedTxId === tx.txId;

  return (
    <div
      className={`transaction-item ${isExpanded ? 'expanded' : ''}`}
      onClick={() => onToggle(tx.txId)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onToggle(tx.txId)}
    >
      <div className="transaction-main">
        <div className="transaction-type">
          {txTypeLabel(tx.txType)}
          {tx.txType === 'bilateral_offline' && (
            <span className="bilateral-badge" title="Bilateral Offline (BLE)">BLE</span>
          )}
        </div>
        <div className={`transaction-status status-${tx.status}`}>
          {tx.status}
        </div>
        <div className="expand-indicator">
          <ArrowIcon direction={isExpanded ? 'up' : 'down'} size={14} color={isExpanded ? 'var(--stateboy-dark)' : 'var(--stateboy-gray)'} />
        </div>
      </div>
      <div className={`transaction-amount-line ${isOutgoing ? 'outgoing' : 'incoming'}`}>
        <TokenMark ticker={tx.tokenId} className="sb-coin sb-coin--sm" />
        <span className="transaction-amount-value">
          {isOutgoing ? '-' : '+'}{formatTxAmount(tx)}
        </span>
        <span className="transaction-amount-token">{tx.tokenId}</span>
      </div>
      <div className="transaction-details">
        <div className="transaction-recipient">
          <span className="transaction-recipient-label">{isOutgoing ? 'To' : 'From'}</span>
          <span className="transaction-recipient-value">{tx.recipient}</span>
        </div>
      </div>

      {isExpanded && (
        <div className="transaction-expanded-details">
          {tx.memo && (
            <div className="detail-row">
              <span className="detail-label">Memo</span>
              <span className="detail-value">{tx.memo}</span>
            </div>
          )}
          <div className="detail-row detail-row-hash">
            <span className="detail-label">From</span>
            <span className="detail-value detail-value-hash">{tx.fromDeviceId}</span>
          </div>
          <div className="detail-row detail-row-hash">
            <span className="detail-label">To</span>
            <span className="detail-value detail-value-hash">{tx.toDeviceId}</span>
          </div>
          <div className="detail-row detail-row-hash">
            <span className="detail-label">Tx Hash</span>
            <span className="detail-value detail-value-hash">{tx.txHash}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Type</span>
            <span className="detail-value">{txTypeDetail(tx.txType)}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Status</span>
            <span className={`detail-value status-${tx.status}`}>{tx.status.toUpperCase()}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Receipt</span>
            <span className={`detail-value ${tx.receiptVerified ? 'status-confirmed' : tx.stitchedReceipt ? 'status-failed' : ''}`}>
              {tx.receiptVerified ? 'Verified' : tx.stitchedReceipt ? 'Invalid' : 'N/A'}
            </span>
          </div>
          {tx.stitchedReceipt && (
            <StitchedReceiptDetails bytes={tx.stitchedReceipt} />
          )}
        </div>
      )}
    </div>
  );
}

const TransactionItem = React.memo(TransactionItemInner);
export default TransactionItem;
