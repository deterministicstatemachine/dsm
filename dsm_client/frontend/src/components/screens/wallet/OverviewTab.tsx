// SPDX-License-Identifier: Apache-2.0
// Overview tab for the wallet screen — balances, recent activity, wallet identity.
import React, { useState, useMemo, useCallback } from 'react';
import TransactionItem from './TransactionItem';
import { Disclosure } from '../../common/ScreenFrame';
import type { BalanceHoldingView, TokenBalanceView } from '../../../dsm/types';
import { TokenMark } from '../../TokenMark';
import BluetoothIcon from '../../icons/BluetoothIcon';
import type { DomainTransaction } from '../../../domain/types';
import type { PendingOfflineState } from './hooks/usePendingOffline';
import { dsmClient } from '../../../services/dsmClient';
import type { ReceivedUnload } from '../../../dsm/offlineCash';

const MAX_OVERVIEW_BALANCES = 5;

type Props = {
  balances: TokenBalanceView[];
  /** The store has not answered balances yet: neither a holding nor an empty wallet is known. */
  balancesLoading: boolean;
  /** Payments received offline, in this phone's offline balance: in no balance above until unloaded. */
  pendingOffline: PendingOfflineState;
  /** Read the wallet again once received money has moved into the balance. */
  onReceivedMoved: () => Promise<void>;
  transactions: DomainTransaction[];
  genesisB32: string;
  deviceB32: string;
  onSwitchToSend: () => void;
  onSwitchToHistory: () => void;
};

function OverviewTabInner({ balances, balancesLoading, pendingOffline, onReceivedMoved, transactions, genesisB32, deviceB32, onSwitchToSend, onSwitchToHistory }: Props): React.JSX.Element {
  const [showAllBalances, setShowAllBalances] = useState(false);
  // The unload asked for and not yet answered, if any.
  const [unloading, setUnloading] = useState<Promise<ReceivedUnload> | null>(null);
  const [unloadNotice, setUnloadNotice] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  // One tap moves every payment received offline that is ready (owner, 2026-11-07); Rust says
  // which moved and which still wait for their payers.
  const unloadReceived = useCallback(async () => {
    const asked = dsmClient.unloadReceived();
    setUnloading(asked);
    setUnloadNotice(null);
    try {
      const res = await asked;
      setUnloadNotice({ kind: 'success', text: res.message });
      await onReceivedMoved();
    } catch (e) {
      setUnloadNotice({ kind: 'error', text: e instanceof Error ? e.message : String(e) });
    } finally {
      setUnloading(null);
    }
  }, [onReceivedMoved]);
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

      {/* Received offline: committed by this phone's own board into its
          offline balance, shown apart from the balances, which do not include
          it. It moves into the balance when the user unloads it, each payment
          once its payer has been back online. */}
      {(pendingOffline.receipts.length > 0 || pendingOffline.error) && (
        <section className="sb-card" aria-label="Received offline" data-testid="pending-offline">
          <div className="sb-card__title">
            <span className="sb-hero__label">Received offline</span>
          </div>
          <div className="sb-hero__sub">In this phone's offline balance. Move it to your balance once the payer is back online.</div>
          {pendingOffline.receipts.map((r, i) => (
            <div className="sb-kv" style={{ padding: '6px 0' }} key={i} data-testid="pending-offline-receipt">
              <span className="sb-kv__k" style={{ fontSize: 11, textTransform: 'none', letterSpacing: 0, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <TokenMark ticker={r.ticker} />
                {r.ticker} from {r.payer}
              </span>
              <span className="sb-kv__v" style={{ fontSize: 13, fontWeight: 600 }}>{r.displayAmount}</span>
            </div>
          ))}
          {pendingOffline.error && (
            <div className="sb-hero__sub" role="alert">Pending payments could not be read: {pendingOffline.error}</div>
          )}
          {pendingOffline.receipts.length > 0 && (
            <button
              type="button"
              className="sb-btn sb-btn--ghost sb-btn--small sb-btn--block"
              style={{ marginTop: 6 }}
              onClick={unloadReceived}
              disabled={unloading !== null}
              data-testid="unload-received"
            >
              {unloading !== null ? 'Moving…' : 'Move to balance'}
            </button>
          )}
          {unloadNotice && (
            <div className="sb-hero__sub" role={unloadNotice.kind === 'error' ? 'alert' : 'status'} data-testid="unload-received-notice">
              {unloadNotice.text}
            </div>
          )}
        </section>
      )}

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
