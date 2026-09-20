// SPDX-License-Identifier: Apache-2.0
// History tab — full transaction list with expand/collapse.
import React, { useState, useCallback } from 'react';
import TransactionItem from './TransactionItem';
import type { DomainTransaction } from '../../../domain/types';

type Props = {
  transactions: DomainTransaction[];
  aliasLookup: Map<string, string>;
};

function HistoryTabInner({ transactions, aliasLookup }: Props): React.JSX.Element {
  const [expandedTxId, setExpandedTxId] = useState<string | null>(null);

  const handleToggleTx = useCallback((txId: string) => {
    setExpandedTxId(prev => prev === txId ? null : txId);
  }, []);

  return (
    <div className="history-tab">
      <h3 className="sb-section-title">Transaction History</h3>
      {transactions.length === 0 ? (
        <div className="sb-empty">No transactions yet.</div>
      ) : (
        <div className="transaction-items">
          {transactions.map((tx, idx) => (
            <TransactionItem
              key={(tx.txId?.length ?? 0) > 0 ? tx.txId! : `tx:idx:${idx}`}
              tx={tx}
              idx={idx}
              expandedTxId={expandedTxId}
              onToggle={handleToggleTx}
              aliasLookup={aliasLookup}
              showRecoveredBadge
            />
          ))}
        </div>
      )}
    </div>
  );
}

const HistoryTab = React.memo(HistoryTabInner);
export default HistoryTab;
