// SPDX-License-Identifier: Apache-2.0
// Overview tab for the wallet screen — balances, recent activity, wallet identity.
import React, { useState, useMemo, useCallback } from 'react';
import TransactionItem from './TransactionItem';
import { Disclosure } from '../../common/ScreenFrame';
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
      <section className="sb-card" aria-label="Your balances">
        <div className="sb-card__title">
          <span className="sb-hero__label"><img src={eraGif} alt="" />Your Balances</span>
        </div>
        {balances.length === 0 ? (
          <>
            <div className="sb-hero__value" style={{ textAlign: 'center' }}>0<span className="sb-hero__unit">ERA</span></div>
            <div className="sb-hero__sub" style={{ textAlign: 'center' }}>Claim tokens from the faucet to get started</div>
          </>
        ) : (
          <>
            {visibleBalances.map((b) => (
              <div key={b.tokenId} className="sb-kv" style={{ padding: '6px 0' }}>
                <span className="sb-kv__k" style={{ fontSize: 11, textTransform: 'none', letterSpacing: 0 }}>{b.symbol || b.tokenId}</span>
                <span className="sb-kv__v" style={{ fontSize: 15, fontWeight: 700 }}>{String(b.balance ?? '0')}</span>
              </div>
            ))}
            {tokenOptions.length > MAX_OVERVIEW_BALANCES && (
              <button
                type="button"
                onClick={() => setShowAllBalances((prev) => !prev)}
                className="sb-btn sb-btn--ghost sb-btn--small sb-btn--block"
                style={{ marginTop: 6 }}
              >
                {showAllBalances
                  ? 'Show Less'
                  : `Show ${tokenOptions.length - MAX_OVERVIEW_BALANCES} More`}
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
