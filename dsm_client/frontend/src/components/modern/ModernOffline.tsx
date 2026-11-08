// SPDX-License-Identifier: Apache-2.0
// The Modern skin's offline part of the Send page: the DSM Anchor appliance that spends cash in
// hand, and the funding that moves a token between the online account and the offline
// allocation. The same Rust calls the DGen skin makes (anchor.status, the try-run and install,
// wallet.loadOffline / wallet.unloadOffline); this renders what Rust reports and carries the
// taps. Choosing Offline reads the appliance by itself: the first time Android asks the user to
// allow it, and while it stays plugged in it connects on its own after that.

import React, { useCallback, useEffect, useState } from 'react';
import { dsmClient } from '../../services/dsmClient';
import { getAnchorStatus } from '../../dsm/anchor';
import AnchorInstallPanel from '../AnchorInstallPanel';
import { applianceConnected, applianceStateText, type ApplianceRead } from '../applianceRead';
import type { TokenBalanceView } from '../../dsm/types';

type Direction = 'load' | 'unload';

type Props = {
  /** The token the form sends; its allocation is the one shown and moved. */
  token: TokenBalanceView | null;
  /** Re-reads the wallet after a move or a connection, so the balances shown are the store's. */
  onMoved: () => Promise<void>;
};

const reason = (e: unknown) => (e instanceof Error ? e.message : String(e));

export default function ModernOffline({ token, onMoved }: Props): React.JSX.Element {
  const [read, setRead] = useState<ApplianceRead>({ kind: 'unread' });
  const [reading, setReading] = useState<'reading' | 'idle'>('idle');
  const [direction, setDirection] = useState<Direction>('load');
  const [amount, setAmount] = useState('');
  const [moving, setMoving] = useState<'moving' | 'idle'>('idle');
  const [moved, setMoved] = useState<{ kind: 'done' | 'refused'; text: string } | null>(null);

  // Rust attaches an installed appliance on this read, and a new one stays as it is. Once it is
  // connected the balances can name their offline allocations, so they are read again.
  const connect = useCallback(async () => {
    setReading('reading');
    try {
      const status = await getAnchorStatus();
      setRead({ kind: 'read', status });
      if (status.connected) await onMoved();
    } catch (e) {
      setRead({ kind: 'error', message: reason(e) });
    } finally {
      setReading('idle');
    }
  }, [onMoved]);

  // `connect` settles every failure into `read`, so there is nothing left for a caller to catch.
  useEffect(() => {
    connect();
  }, [connect]);

  const move = async () => {
    if (token === null || amount.trim().length === 0) return;
    setMoving('moving');
    setMoved(null);
    try {
      const res = direction === 'load'
        ? await dsmClient.loadOfflineCash(token.tokenId, amount)
        : await dsmClient.unloadOfflineCash(token.tokenId, amount);
      setMoved({ kind: 'done', text: res.message });
      setAmount('');
      await onMoved();
    } catch (e) {
      setMoved({ kind: 'refused', text: reason(e) });
    } finally {
      setMoving('idle');
    }
  };

  const connected = applianceConnected(read);
  const busy = reading === 'reading';
  const canMove = token !== null && amount.trim().length > 0 && moving === 'idle';

  return (
    <>
      <section className="s-card" aria-label="Appliance">
        <div className="s-label">Appliance</div>
        <p className="s-hint">
          Offline sends need the <strong>DSM Anchor</strong> appliance plugged into this phone. Plug it into the
          USB port and tap Connect; when Android asks, allow DSM to use it. Android asks once.
        </p>
        <div className="s-kv">
          <span className="s-kv-k">State</span>
          <span className="s-kv-v" data-testid="appliance-state">{applianceStateText(read)}</span>
        </div>
        {read.kind === 'read' && read.status.connected ? (
          <>
            <div className="s-kv">
              <span className="s-kv-k">Anchor</span>
              <span className="s-kv-v s-mono">{read.status.anchorIdB32}</span>
            </div>
            <div className="s-kv">
              <span className="s-kv-k">Counter</span>
              <span className="s-kv-v s-mono">{String(read.status.anchorCounter)}</span>
            </div>
          </>
        ) : null}
        {read.kind === 'read' && read.status.awaitingInstall ? <AnchorInstallPanel onInstalled={connect} /> : null}
        {read.kind === 'error' ? <div className="s-notice s-error" role="alert">{read.message}</div> : null}
        <button type="button" className="s-btn s-btn-quiet" disabled={busy} onClick={() => connect()}>
          {busy ? 'Connecting…' : connected ? 'Check again' : 'Connect'}
        </button>
      </section>

      <section className="s-card" aria-label="Offline funding">
        <div className="s-label">Cash in hand</div>
        {token !== null ? (
          <>
            <div className="s-kv">
              <span className="s-kv-k">Online account</span>
              <span className="s-kv-v">{`${token.displayAmount} ${token.symbol}`}</span>
            </div>
            <div className="s-kv">
              <span className="s-kv-k">Offline allocation</span>
              <span className="s-kv-v" data-testid="offline-allocation">
                {token.offline ? `${token.offline.displayAmount} ${token.symbol}` : 'Unknown until the appliance connects'}
              </span>
            </div>
          </>
        ) : (
          <div className="s-notice">There is no token to move yet.</div>
        )}
        <p className="s-hint">
          Your wallet keeps two balances of each token: the online account spends through the storage nodes, the
          offline allocation is cash in hand that the appliance spends. Load moves tokens into cash in hand; unload moves
          them back. Both need the appliance connected.
        </p>
        <div className="s-field">
          <div className="s-seg" role="group" aria-label="Funding direction">
            <button type="button" aria-pressed={direction === 'load'} onClick={() => setDirection('load')}>Load offline</button>
            <button type="button" aria-pressed={direction === 'unload'} onClick={() => setDirection('unload')}>Unload to online</button>
          </div>
        </div>
        <div className="s-field">
          <label className="s-label" htmlFor="s-offline-amount">Amount</label>
          <input
            id="s-offline-amount"
            className="s-input"
            inputMode="decimal"
            value={amount}
            onChange={(e) => {
              const typed = e.target.value.replace(/,/g, '.').replace(/[^\d.]/g, '');
              const point = typed.indexOf('.');
              setAmount(point < 0 ? typed : `${typed.slice(0, point + 1)}${typed.slice(point + 1).replace(/\./g, '')}`);
            }}
          />
        </div>
        {moved !== null ? (
          <div className={`s-notice${moved.kind === 'refused' ? ' s-error' : ''}`} role={moved.kind === 'refused' ? 'alert' : 'status'}>
            {moved.text}
          </div>
        ) : null}
        <button type="button" className="s-btn s-btn-primary" disabled={!canMove} onClick={() => move()}>
          {moving === 'moving' ? 'Moving…' : direction === 'load' ? 'Load' : 'Unload'}
        </button>
      </section>
    </>
  );
}
