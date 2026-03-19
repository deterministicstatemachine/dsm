// SPDX-License-Identifier: Apache-2.0
// Overview tab for the wallet screen — balances, recent activity, wallet info.
import React, { useState, useMemo, useCallback } from 'react';
import TransactionItem from './TransactionItem';
import { shortStr } from './helpers';
import type { Balance } from './helpers';
import type { DomainTransaction } from '../../../domain/types';

const MAX_OVERVIEW_BALANCES = 5;

type Props = {
  balances: Balance[];
  transactions: DomainTransaction[];
  aliasLookup: Map<string, string>;
  eraGif: string;
  genesisB32: string;
  deviceB32: string;
  onSwitchToSend: () => void;
  onSwitchToHistory: () => void;
};

function OverviewTabInner({ balances, transactions, aliasLookup, eraGif, genesisB32, deviceB32, onSwitchToSend, onSwitchToHistory }: Props): JSX.Element {
  const [showAllBalances, setShowAllBalances] = useState(false);
  const [expandedTxId, setExpandedTxId] = useState<string | null>(null);

  const tokenOptions = useMemo(() => {
    if (!Array.isArray(balances) || balances.length === 0) {
      return [{ tokenId: 'ERA', symbol: 'ERA', balance: '0' } as Balance];
    }
    return balances;
  }, [balances]);

  const visibleBalances = useMemo(() => {
    if (showAllBalances) return tokenOptions;
    return tokenOptions.slice(0, MAX_OVERVIEW_BALANCES);
  }, [tokenOptions, showAllBalances]);

  const recentTransactions = useMemo(() => transactions.slice(0, 5), [transactions]);

  const handleToggleTx = useCallback((txId: string) => {
    setExpandedTxId(prev => prev === txId ? null : txId);
  }, []);

  return (
    <div className="overview-tab">
      <div className="balance-section">
        <h3>
          <img src={eraGif} alt="ERA" className="era-gif" />
          Your Balances
        </h3>
        {balances.length === 0 ? (
          <div className="balance-card">
            <div className="balance-info">
              <span className="token-symbol">ERA</span>
              <span className="balance-amount">0</span>
            </div>
            <div className="balance-usd" style={{ fontSize: 10, opacity: 0.7 }}>Claim tokens from the faucet to get started</div>
          </div>
        ) : (
          <div className="balance-card balance-card-stacked">
            <div className="balance-list">
              {visibleBalances.map((b) => (
                <div key={b.tokenId} className="balance-list-row">
                  <span className="token-symbol">{b.symbol || b.tokenId}</span>
                  <span className="balance-amount balance-amount-inline">{String(b.balance ?? '0')}</span>
                </div>
              ))}
            </div>
            {tokenOptions.length > MAX_OVERVIEW_BALANCES && (
              <button
                type="button"
                onClick={() => setShowAllBalances((prev) => !prev)}
                className="view-all-button"
                style={{ marginTop: 10 }}
              >
                {showAllBalances
                  ? 'Show Less'
                  : `Show ${tokenOptions.length - MAX_OVERVIEW_BALANCES} More`}
              </button>
            )}
          </div>
        )}
      </div>
      <div className="quick-actions">
        <button onClick={onSwitchToSend} className="action-button button-brick">Send</button>
      </div>
      {recentTransactions.length > 0 && (
        <div className="recent-transactions">
          <h3>Recent Activity</h3>
          <div className="transaction-items">
            {recentTransactions.map((tx, idx) => (
              <TransactionItem
                key={(tx.txId?.length ?? 0) > 0 ? tx.txId! : `tx:idx:${idx}`}
                tx={tx}
                idx={idx}
                expandedTxId={expandedTxId}
                onToggle={handleToggleTx}
                aliasLookup={aliasLookup}
              />
            ))}
          </div>
          <button onClick={onSwitchToHistory} className="view-all-button">View All Transactions</button>
        </div>
      )}
      <div className="wallet-info">
        <div className="info-item"><label>Genesis Hash:</label><span className="info-value">{shortStr(genesisB32, 12, 10)}</span></div>
        <div className="info-item"><label>Device ID:</label><span className="info-value">{shortStr(deviceB32, 12, 10)}</span></div>
      </div>
    </div>
  );
}

const OverviewTab = React.memo(OverviewTabInner);
export default OverviewTab;
