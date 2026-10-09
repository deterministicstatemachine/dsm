// SPDX-License-Identifier: Apache-2.0
// Overview tab for the wallet screen — balances, recent activity, wallet identity.
import React, { useState, useMemo, useCallback } from 'react';
import TransactionItem from './TransactionItem';
import { Disclosure } from '../../common/ScreenFrame';
import type { BalanceHoldingView, TokenBalanceView } from '../../../dsm/types';
import { TokenMark } from '../../TokenMark';
import BluetoothIcon from '../../icons/BluetoothIcon';
import type { DomainTransaction } from '../../../domain/types';

const MAX_OVERVIEW_BALANCES = 5;

type Props = {
  balances: TokenBalanceView[];
  /** The store has not answered balances yet: neither a holding nor an empty wallet is known. */
  balancesLoading: boolean;
  transactions: DomainTransaction[];
  genesisB32: string;
  deviceB32: string;
  onSwitchToSend: () => void;
  onSwitchToHistory: () => void;
};

function OverviewTabInner({ balances, balancesLoading, transactions, genesisB32, deviceB32, onSwitchToSend, onSwitchToHistory }: Props): React.JSX.Element {
  const [showAllBalances, setShowAllBalances] = useState(false);
  const [expandedTxId, setExpandedTxId] = useState<string | null>(null);
  // Currencies, or the state objects (supply-one tokens: creatures, items) the wallet holds.
  const [shown, setShown] = useState<BalanceHoldingView>('currency');
  const showingObjects = shown === 'object';
  const listed = useMemo(() => balances.filter((b) => (b.holding ?? 'currency') === shown), [balances, shown]);

  const visibleBalances = useMemo(() => {
    if (showAllBalances) return listed;
    return listed.slice(0, MAX_OVERVIEW_BALANCES);
  }, [listed, showAllBalances]);

  const recentTransactions = useMemo(() => transactions.slice(0, 5), [transactions]);

  const handleToggleTx = useCallback((txId: string) => {
    setExpandedTxId(prev => prev === txId ? null : txId);
  }, []);

  return (
    <div className="overview-tab">
      <section className="sb-card" aria-label="Your balances">
        <div className="sb-card__title">
          <span className="sb-hero__label">Your Balances</span>
          <button
            type="button"
            role="switch"
            className="sb-switch"
            aria-checked={showingObjects}
            aria-label="Show state objects"
            title={showingObjects ? 'State objects' : 'Currencies'}
            onClick={() => setShown(showingObjects ? 'currency' : 'object')}
          />
        </div>
        {balancesLoading ? (
          <div className="sb-hero__sub" style={{ textAlign: 'center' }}>Loading balances{'…'}</div>
        ) : listed.length === 0 && showingObjects ? (
          <div className="sb-hero__sub" style={{ textAlign: 'center' }}>No state objects yet.</div>
        ) : listed.length === 0 ? (
          <>
            <div className="sb-hero__sub" style={{ textAlign: 'center' }}>No balances yet. Claim tokens from the faucet to get started.</div>
          </>
        ) : (
          <>
            {visibleBalances.map((b) => (
              <React.Fragment key={b.tokenId}>
                <div className="sb-kv" style={{ padding: '6px 0' }}>
                  <span className="sb-kv__k" style={{ fontSize: 11, textTransform: 'none', letterSpacing: 0, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <TokenMark ticker={b.symbol} iconUrl={b.iconUrl} />
                    {b.symbol}
                  </span>
                  <span className="sb-kv__v" style={{ fontSize: 15, fontWeight: 700 }}>{b.displayAmount}</span>
                </div>
                {/* Cash in hand, under the token it belongs to: the offline
                    allocation an offline send spends, which the amount above
                    does not include. Shown once there is some. */}
                {b.offline && b.offline.baseUnits > BigInt(0) && (
                  <div className="sb-kv" style={{ padding: '0 0 6px 22px' }} data-testid={`offline-allocation-${b.tokenId}`}>
                    <span className="sb-kv__k" style={{ fontSize: 10, textTransform: 'none', letterSpacing: 0, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      <BluetoothIcon size={11} title="Offline allocation" />
                      offline
                    </span>
                    <span className="sb-kv__v" style={{ fontSize: 12, fontWeight: 600 }}>{b.offline.displayAmount}</span>
                  </div>
                )}
              </React.Fragment>
            ))}
            {listed.length > MAX_OVERVIEW_BALANCES && (
              <button
                type="button"
                onClick={() => setShowAllBalances((prev) => !prev)}
                className="sb-btn sb-btn--ghost sb-btn--small sb-btn--block"
                style={{ marginTop: 6 }}
              >
                {showAllBalances
                  ? 'Show Less'
                  : `Show ${listed.length - MAX_OVERVIEW_BALANCES} More`}
              </button>
            )}
          </>
        )}
      </section>

      <div className="sb-actions" style={{ marginTop: 0 }}>
        <button type="button" onClick={onSwitchToSend} className="sb-btn sb-btn--primary">Send</button>
      </div>

      {recentTransactions.length > 0 && (
        <section className="recent-transactions" style={{ marginBottom: 8 }} data-tour="recent-activity">
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

      <Disclosure summary="Wallet identity" className="wallet-identity">
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
