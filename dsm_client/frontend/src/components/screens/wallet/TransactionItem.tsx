// SPDX-License-Identifier: Apache-2.0
// Reusable transaction row component for overview and history tabs.
import React from 'react';
import { txTypeLabel, txTypeDetail, txTypeNumber, formatTxAmount, b32, shortStr, resolveAlias } from './helpers';
import { formatTimeAgo, formatDateTime } from '../../../utils/time';
import ArrowIcon from '../../icons/ArrowIcon';
import StitchedReceiptDetails from '../../receipts/StitchedReceiptDetails';
import type { DomainTransaction } from '../../../domain/types';

type Props = {
  tx: DomainTransaction;
  idx: number;
  expandedTxId: string | null;
  onToggle: (txId: string) => void;
  aliasLookup: Map<string, string>;
  showRecoveredBadge?: boolean;
};

function TransactionItemInner({ tx, idx, expandedTxId, onToggle, aliasLookup, showRecoveredBadge = false }: Props): JSX.Element {
  const amtBI = tx.amountSigned ?? tx.amount ?? 0n;
  const isOutgoing = amtBI < 0n;
  const token = (tx.tokenId?.length ?? 0) > 0 ? tx.tokenId! : 'ERA';
  const absAmt = isOutgoing ? -amtBI : amtBI;
  const magnitude = formatTxAmount(absAmt, token);
  const txTypeVal = txTypeNumber(tx);
  const createdAt = tx.createdAt ?? 0;
  const memo = (tx.memo?.length ?? 0) > 0 ? tx.memo : undefined;
  const recipient = (tx.recipient?.length ?? 0) > 0 ? tx.recipient : undefined;
  const statusStr = (tx.status?.length ?? 0) > 0 ? tx.status : 'confirmed';
  const fromB32 = b32(tx.fromDeviceId);
  const toB32 = b32(tx.toDeviceId);
  const txHashB32 = b32(tx.txHash);
  const receiptBytes = tx.stitchedReceipt?.length ? tx.stitchedReceipt : undefined;
  const txId = (tx.txId?.length ?? 0) > 0 ? tx.txId : `tx:idx:${idx}`;
  const isExpanded = expandedTxId === txId;
  const counterparty = recipient || (isOutgoing ? resolveAlias(toB32, aliasLookup) : resolveAlias(fromB32, aliasLookup)) || '\u2014';

  return (
    <div
      className={`transaction-item ${isExpanded ? 'expanded' : ''}`}
      onClick={() => onToggle(txId!)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onToggle(txId!)}
    >
      <div className="transaction-main">
        <div className="transaction-type">
          {txTypeLabel(txTypeVal)}
          {(txTypeVal === 2 || txTypeVal === 3) && (
            <span className="bilateral-badge" title="Bilateral Offline (BLE)">BLE</span>
          )}
          {showRecoveredBadge && txTypeVal === 3 && (
            <span className="recovered-badge" title="Recovered">{'\u27F3'}</span>
          )}
        </div>
        <div className={`transaction-amount ${isOutgoing ? 'outgoing' : 'incoming'}`}>
          {isOutgoing ? '-' : '+'}{magnitude} {token}
        </div>
        <div className={`transaction-status status-${statusStr}`}>
          {statusStr}
        </div>
        <div className="expand-indicator">
          <ArrowIcon direction={isExpanded ? 'up' : 'down'} size={14} color={isExpanded ? 'var(--stateboy-dark)' : 'var(--stateboy-gray)'} />
        </div>
      </div>
      <div className="transaction-details">
        <div className="transaction-recipient">
          {isOutgoing ? 'To' : 'From'}: {counterparty.length > 20 ? shortStr(counterparty, 10, 8) : counterparty}
        </div>
        {createdAt > 0 && (
          <div className="transaction-time">{formatTimeAgo(createdAt)}</div>
        )}
      </div>

      {isExpanded && (
        <div className="transaction-expanded-details">
          {createdAt > 0 && (
            <div className="detail-row">
              <span className="detail-label">Date</span>
              <span className="detail-value">{formatDateTime(createdAt)}</span>
            </div>
          )}
          {memo && (
            <div className="detail-row">
              <span className="detail-label">Memo</span>
              <span className="detail-value">{memo}</span>
            </div>
          )}
          {fromB32 && (
            <div className="detail-row">
              <span className="detail-label">From</span>
              <span className="detail-value">{shortStr(fromB32, 10, 8)}</span>
            </div>
          )}
          {toB32 && (
            <div className="detail-row">
              <span className="detail-label">To</span>
              <span className="detail-value">{shortStr(toB32, 10, 8)}</span>
            </div>
          )}
          {txHashB32 && (
            <div className="detail-row">
              <span className="detail-label">Tx Hash</span>
              <span className="detail-value tx-id">{shortStr(txHashB32, 12, 8)}</span>
            </div>
          )}
          <div className="detail-row">
            <span className="detail-label">Type</span>
            <span className="detail-value">{txTypeDetail(txTypeVal)}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Status</span>
            <span className={`detail-value status-${statusStr}`}>{statusStr!.toUpperCase()}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Receipt</span>
            <span className={`detail-value ${tx.receiptVerified ? 'status-confirmed' : receiptBytes ? 'status-failed' : ''}`}>
              {tx.receiptVerified ? 'Verified' : receiptBytes ? 'Invalid' : 'N/A'}
            </span>
          </div>
          {receiptBytes && (
            <StitchedReceiptDetails bytes={receiptBytes} />
          )}
        </div>
      )}
    </div>
  );
}

const TransactionItem = React.memo(TransactionItemInner);
export default TransactionItem;
