// SPDX-License-Identifier: Apache-2.0
// Inbox (b0x) overlay — the transfers received and not yet looked at, and the
// items still queued on the storage nodes, both as Rust lists them.
//
// The count on the b0x button is Rust's count of received transfers the user
// has not opened the b0x on (owner, 2026-10-23) — the same count Rust hands
// the app icon. Rust announces a change with `money.waiting`. Opening the
// overlay shows those transfers and reports them seen, which clears the count;
// one that lands while it is open counts until the next opening. Opening it
// also lists what `inbox.pull` finds queued, every item as Rust described it,
// including those Rust marked as found on a previous-tip route.
import React, { useState, useCallback, useEffect } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import type { InboxItemView } from '../../../dsm/types';
import type { DomainTransaction } from '../../../domain/types';
import { getMoneyWaiting, markMoneySeen, type MoneyWaiting } from '../../../dsm/moneyWaiting';

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
type Props = { headerHeight: number };

function InboxOverlayInner({ headerHeight }: Props): React.JSX.Element {
  const [open, setOpen] = useState(false);
  const [waiting, setWaiting] = useState<MoneyWaiting | null>(null);
  const [shown, setShown] = useState<DomainTransaction[]>([]);
  const [pending, setPending] = useState<InboxItemView[]>([]);
  const [loadingPending, setLoadingPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Rust's count of received transfers not yet looked at; none drawn until read.
  const badgeCount = waiting === null ? 0 : waiting.received.length;

  // A read that fails is shown, and the count stays as it was last read.
  const report = useCallback((e: unknown) => {
    setError(e instanceof Error ? e.message : 'The received transfers could not be read');
  }, []);

  const readWaiting = useCallback(
    () => getMoneyWaiting().then(setWaiting, report),
    [report],
  );

  useEffect(() => {
    readWaiting();
    return bridgeEvents.on('money.waiting', () => { readWaiting(); });
  }, [readWaiting]);

  // Show what is waiting, then report it seen: the count clears for exactly
  // what was shown.
  const showReceived = useCallback(
    () => getMoneyWaiting()
      .then((now) => {
        setShown(now.received);
        return markMoneySeen(now.through);
      })
      .then(setWaiting, report),
    [report],
  );

  const loadPending = useCallback(async () => {
    setLoadingPending(true);
    setError(null);
    try {
      const res = await dsmClient.getInbox();
      setPending(res.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally { setLoadingPending(false); }
  }, []);

  // Other overlays (the bilateral transfer dialog) stand aside while the
  // inbox is open; they learn of it from `inbox.open`.
  const handleOpen = useCallback(() => {
    if (open) {
      setOpen(false);
      bridgeEvents.emit('inbox.open', { open: false });
      return;
    }
    setOpen(true);
    bridgeEvents.emit('inbox.open', { open: true });
    showReceived();
    void loadPending();
  }, [open, loadPending, showReceived]);

  const handleClose = useCallback(() => {
    setOpen(false);
    setError(null);
    bridgeEvents.emit('inbox.open', { open: false });
  }, []);

  const mono: React.CSSProperties = { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' };

  return (
    <>
      {/* ---- Header button ---- */}
      <button
        onClick={handleOpen}
        type="button"
        className={`sb-icon-btn b0x-button${badgeCount > 0 ? ' has-items' : ''}`}
        title={badgeCount > 0 ? `Inbox — ${badgeCount} new` : 'Inbox'}
        aria-label={badgeCount > 0 ? `Inbox (${badgeCount} new)` : 'Inbox'}
      >
        <img src="images/icons/Mail-DSM-b0x.svg" alt="" style={{ width: 20, height: 20 }} />
      </button>

      {/* ---- Overlay ---- */}
      {open && (
        <>
          <div onClick={handleClose} style={{ position: 'absolute', inset: 0, zIndex: 9997, background: 'transparent' }} />
          <div role="dialog" aria-label="Inbox" style={{ position: 'absolute', top: headerHeight + 8, right: 8, width: 300, maxWidth: 'calc(100% - 16px)', maxHeight: 'calc(100% - 24px)', overflowY: 'auto', overflowX: 'hidden', zIndex: 9998, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', borderRadius: 12, boxSizing: 'border-box' }}>

            {/* Header row */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '8px 10px', borderBottom: '2px solid var(--border)' }}>
              <strong style={{ ...mono, fontSize: 12 }}>Inbox — b0x</strong>
              <button onClick={handleClose} aria-label="Close inbox" style={{ minWidth: 28, minHeight: 28, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, background: 'transparent', border: '1px solid var(--border)', borderRadius: 8, color: 'inherit', cursor: 'pointer' }}>
                {'\u00D7'}
              </button>
            </div>

            <div style={{ padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {error && (
                <div role="alert" style={{ ...mono, fontSize: 11, color: '#e53e3e', padding: '4px 6px', border: '1px solid #e53e3e' }}>{error}</div>
              )}

              {/* ---- Received since the b0x was last opened, as Rust lists them ---- */}
              {shown.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ ...mono, fontSize: 10, opacity: 0.6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Received
                  </div>
                  {shown.map((tx) => (
                    <div key={tx.txId} style={{ border: '1px solid var(--border)', padding: '8px 10px', background: 'rgba(var(--text-dark-rgb),0.06)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <div style={{ ...mono, fontSize: 12 }}>{tx.displayAmount} {tx.tokenId}</div>
                      <div style={{ ...mono, fontSize: 10, opacity: 0.7, wordBreak: 'break-all', overflowWrap: 'break-word' }}>from {tx.recipient}</div>
                      {tx.memo && <div style={{ ...mono, fontSize: 10, opacity: 0.7 }}>{tx.memo}</div>}
                    </div>
                  ))}
                </div>
              )}

              {/* ---- Items queued on the storage nodes, as Rust lists them ---- */}
              {(loadingPending || pending.length > 0) && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ ...mono, fontSize: 10, opacity: 0.6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Queued on storage node
                  </div>
                  {loadingPending ? (
                    <div style={{ ...mono, fontSize: 12 }}>Loading{'\u2026'}</div>
                  ) : pending.map((it) => (
                    <div key={it.id} style={{ border: it.isStaleRoute ? '1px solid #b8860b' : '1px solid var(--border)', padding: '8px 8px', fontSize: 12, background: it.isStaleRoute ? 'rgba(184,134,11,0.08)' : 'rgba(var(--text-dark-rgb),0.06)' }}>
                      {it.isStaleRoute && (
                        <div style={{ ...mono, fontSize: 10, color: '#b8860b', marginBottom: 4 }}>STALE ROUTE — awaiting reconciliation</div>
                      )}
                      <div style={{ ...mono, wordBreak: 'break-all', overflowWrap: 'break-word' }}>{it.preview}</div>
                    </div>
                  ))}
                </div>
              )}

              {shown.length === 0 && pending.length === 0 && !loadingPending && (
                <div style={{ ...mono, fontSize: 12, opacity: 0.6 }}>No new notifications.</div>
              )}

              {/* ---- Footer (notification-only, no manual sync) ---- */}
            </div>
          </div>
        </>
      )}
    </>
  );
}

const InboxOverlay = React.memo(InboxOverlayInner);
export default InboxOverlay;
