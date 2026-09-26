// SPDX-License-Identifier: Apache-2.0
// Overview tab for the wallet screen — balances, recent activity, wallet identity.
import React, { useState, useMemo, useCallback } from 'react';
import TransactionItem from './TransactionItem';
import { Disclosure } from '../../common/ScreenFrame';
import type { Balance } from './helpers';
import { TokenMark } from '../../TokenMark';
import type { DomainTransaction } from '../../../domain/types';

const MAX_OVERVIEW_BALANCES = 5;

type Props = {
  balances: Balance[];
  transactions: DomainTransaction[];
  genesisB32: string;
  deviceB32: string;
  onSwitchToSend: () => void;
  onSwitchToHistory: () => void;
};

function OverviewTabInner({ balances, transactions, genesisB32, deviceB32, onSwitchToSend, onSwitchToHistory }: Props): React.JSX.Element {
  const [showAllBalances, setShowAllBalances] = useState(false);
  const [expandedTxId, setExpandedTxId] = useState<string | null>(null);

  const visibleBalances = useMemo(() => {
    if (showAllBalances) return balances;
    return balances.slice(0, MAX_OVERVIEW_BALANCES);
  }, [balances, showAllBalances]);

  const recentTransactions = useMemo(() => transactions.slice(0, 5), [transactions]);

  const handleToggleTx = useCallback((txId: string) => {
    setExpandedTxId(prev => prev === txId ? null : txId);
  }, []);

  return (
    <div className="overview-tab">
      <section className="sb-card" aria-label="Your balances">
        <div className="sb-card__title">
          <span className="sb-hero__label">Your Balances</span>
        </div>
        {balances.length === 0 ? (
          <>
            <div className="sb-hero__sub" style={{ textAlign: 'center' }}>No balances yet. Claim tokens from the faucet to get started.</div>
          </>
        ) : (
          <>
            {visibleBalances.map((b) => (
              <div key={b.tokenId} className="sb-kv" style={{ padding: '6px 0' }}>
                <span className="sb-kv__k" style={{ fontSize: 11, textTransform: 'none', letterSpacing: 0, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <TokenMark ticker={b.symbol || b.tokenId} iconUrl={b.iconUrl} />
                  {b.symbol || b.tokenId}
                </span>
                <span className="sb-kv__v" style={{ fontSize: 15, fontWeight: 700 }}>{String(b.balance ?? '0')}</span>
              </div>
            ))}
            {balances.length > MAX_OVERVIEW_BALANCES && (
              <button
                type="button"
                onClick={() => setShowAllBalances((prev) => !prev)}
                className="sb-btn sb-btn--ghost sb-btn--small sb-btn--block"
                style={{ marginTop: 6 }}
              >
                {showAllBalances
                  ? 'Show Less'
                  : `Show ${balances.length - MAX_OVERVIEW_BALANCES} More`}
              </button>
            )}
          </>
        )}
      </section>

      <div className="sb-actions" style={{ marginTop: 0 }}>
        <button type="button" onClick={onSwitchToSend} className="sb-btn sb-btn--primary">Send</button>
      </div>

      {recentTransactions.length > 0 && (
        <section className="recent-transactions" style={{ marginBottom: 8 }}>
          <h3 className="sb-section-title">Recent Activity</h3>
          <div className="transaction-items">
            {recentTransactions.map((tx) => (
              <TransactionItem
                key={tx.txId}
                tx={tx}
                expandedTxId={expandedTxId}
                onToggle={handleToggleTx}
              />
            ))}
          </div>
          <button type="button" onClick={onSwitchToHistory} className="sb-btn sb-btn--ghost sb-btn--small sb-btn--block">
            View All Transactions
          </button>
        </section>
      )}

      <Disclosure summary="Wallet identity">
        <div className="sb-kv">
          <span className="sb-kv__k">Genesis</span>
          <span className="sb-kv__v sb-kv__v--mono">{genesisB32 || '—'}</span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">Device</span>
          <span className="sb-kv__v sb-kv__v--mono">{deviceB32 || '—'}</span>
        </div>
      </Disclosure>
    </div>
  );
}

const OverviewTab = React.memo(OverviewTabInner);
export default OverviewTab;
