/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState } from 'react';
import { formatTimeAgo, formatDateTime } from '../utils/time';
import { useTransactions, Transaction } from '../hooks/useTransactions';
import { useWalletRefreshListener } from '@/hooks/useWalletRefreshListener';
import ArrowIcon from './icons/ArrowIcon';
import StitchedReceiptDetails from './receipts/StitchedReceiptDetails';
import { formatSignedTokenAmount } from '../utils/tokenMeta';

interface TransactionListProps {
  className?: string;
}

export const TransactionList: React.FC<TransactionListProps> = ({ className = '' }) => {
  const { transactions, isProcessing, error, refresh } = useTransactions();
  const [expandedTxId, setExpandedTxId] = useState<string | null>(null);

  const toggleExpand = (txId: string) => {
    setExpandedTxId(prev => prev === txId ? null : txId);
  };

  const getStatusColor = (status: Transaction['status']) => {
    switch (status) {
      case 'confirmed':
        return 'status-confirmed';
      case 'pending':
        return 'status-pending';
      case 'failed':
        return 'status-failed';
      default:
        return 'status-unknown';
    }
  };

  const getSyncStatusIcon = (syncStatus?: Transaction['syncStatus']) => {
    switch (syncStatus) {
      case 'synced':
        return 'SYNCED';
      case 'syncing':
        return 'SYNCING';
      case 'unsynced':
        return 'UNSYNCED';
      default:
        return '';
    }
  };

  // Canonical wallet refresh: single deterministic pathway.
  useWalletRefreshListener(refresh, [refresh]);

  if (error) {
    return (
      <div className={`transaction-list error ${className}`}>
        <div className="error-message">
          Failed to load transactions: {error}
        </div>
        <button onClick={refresh} className="retry-button">
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className={`transaction-list ${className}`}>
      <div className="transaction-list-header">
        <h3>Transaction History</h3>
        <button
          onClick={refresh}
          disabled={isProcessing}
          className="refresh-button"
          aria-label="Refresh"
        >
          <img
            src="images/icons/icon_refresh.svg"
            alt=""
            className={`icon-refresh ${isProcessing ? 'spinning' : ''}`}
            aria-hidden
          />
        </button>
      </div>

      {transactions.length === 0 ? (
        <div className="empty-state">
          <p>No transactions yet</p>
          <small>Your transaction history will appear here</small>
        </div>
      ) : (
        <div className="transaction-items">
          {transactions.map((transaction: Transaction) => {
            const isExpanded = expandedTxId === transaction.txId;
            const isOutgoing = transaction.amount < 0n;
            const counterparty = transaction.recipient || 'Unknown';
            const hasReceipt = transaction.stitchedReceipt && transaction.stitchedReceipt.length > 0;

            return (
              <div
                key={transaction.txId}
                className={`transaction-item ${isExpanded ? 'expanded' : ''}`}
                onClick={() => toggleExpand(transaction.txId)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === 'Enter' && toggleExpand(transaction.txId)}
              >
                <div className="transaction-main">
                  <div className="transaction-type">
                    {transaction.type === 'online' ? 'ONLINE' : 'OFFLINE'}
                    {((transaction as any).txType === 'bilateral_offline' || (transaction as any).txType === 'bilateral_offline_recovered') && (
                      <span className="bilateral-badge" title="Bilateral Offline Transfer (BLE)">
                        BLE
                      </span>
                    )}
                    {(transaction as any).txType === 'bilateral_offline_recovered' && (
                      <span className="recovered-badge" title="Recovered from interrupted session">
                        ⟳
                      </span>
                    )}
                  </div>
                  <div className={`transaction-amount ${isOutgoing ? 'outgoing' : 'incoming'}`}>
                    {formatSignedTokenAmount(transaction.amount, transaction.tokenId || 'ERA')} {transaction.tokenId || 'ERA'}
                  </div>
                  <div className={`transaction-status ${getStatusColor(transaction.status)}`}>
                    {transaction.status}
                    {getSyncStatusIcon(transaction.syncStatus) && (
                      <span className="sync-indicator" title={`Sync: ${transaction.syncStatus}`}>
                        {getSyncStatusIcon(transaction.syncStatus)}
                      </span>
                    )}
                  </div>
                  <div className="expand-indicator">
                    <ArrowIcon
                      direction={isExpanded ? 'up' : 'down'}
                      size={14}
                      color={isExpanded ? 'var(--stateboy-dark)' : 'var(--stateboy-gray)'}
                    />
                  </div>
                </div>

                {isExpanded && (
                  <div className="transaction-expanded-details">
                    <div className="detail-row">
                      <span className="detail-label">{isOutgoing ? 'To' : 'From'}:</span>
                      <span className="detail-value">{counterparty}</span>
                    </div>
                    {transaction.createdAt ? (
                      <div className="detail-row">
                        <span className="detail-label">Date:</span>
                        <span className="detail-value">{formatDateTime(transaction.createdAt)}</span>
                      </div>
                    ) : null}
                    {transaction.memo ? (
                      <div className="detail-row">
                        <span className="detail-label">Memo:</span>
                        <span className="detail-value">{transaction.memo}</span>
                      </div>
                    ) : null}
                    <div className="detail-row">
                      <span className="detail-label">Transaction ID:</span>
                      <span className="detail-value tx-id">{transaction.txId}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Type:</span>
                      <span className="detail-value">
                        {(transaction as any).txType === 'bilateral_offline'
                          ? 'Bilateral Offline (BLE)'
                          : (transaction as any).txType === 'bilateral_offline_recovered'
                          ? 'Bilateral Offline (BLE - Recovered)'
                          : (transaction as any).txType === 'faucet'
                          ? 'Faucet Claim'
                          : transaction.type === 'online' ? 'Online' : 'Offline'}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Tx Hash:</span>
                      <span className="detail-value">
                        {(() => {
                          const h = transaction.txHash;
                          if (typeof h === 'string' && h.length > 0) {
                            return h.length > 24 ? `${h.slice(0, 24)}...` : h;
                          }
                          const id = transaction.txId;
                          return id.length > 24 ? `${id.slice(0, 24)}...` : id;
                        })()}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Status:</span>
                      <span className={`detail-value status-${transaction.status}`}>
                        {transaction.status.toUpperCase()}
                      </span>
                    </div>
                    {transaction.syncStatus && (
                      <div className="detail-row">
                        <span className="detail-label">Sync:</span>
                        <span className={`detail-value sync-${transaction.syncStatus}`}>
                          {transaction.syncStatus.toUpperCase()}
                        </span>
                      </div>
                    )}
                    <div className="detail-row">
                      <span className="detail-label">Receipt:</span>
                      <span className={`detail-value ${transaction.receiptVerified ? 'status-confirmed' : hasReceipt ? 'status-failed' : ''}`}>
                        {transaction.receiptVerified ? 'Verified' : hasReceipt ? 'Invalid' : 'N/A'}
                      </span>
                    </div>
                    {hasReceipt && (
                      <StitchedReceiptDetails bytes={transaction.stitchedReceipt} />
                    )}
                  </div>
                )}

                {!isExpanded && (
                  <div className="transaction-details">
                    <div className="transaction-recipient">
                      {isOutgoing ? 'To' : 'From'}: {counterparty.length > 16 ? `${counterparty.slice(0, 16)  }...` : counterparty}
                    </div>
                    {transaction.createdAt ? (
                      <div className="transaction-time">
                        {formatTimeAgo(transaction.createdAt)}
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
