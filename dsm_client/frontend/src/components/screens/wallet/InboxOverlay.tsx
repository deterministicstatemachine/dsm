// SPDX-License-Identifier: Apache-2.0
// Inbox (b0x) overlay — transient notices for applied transfers, and the items
// still queued on the storage nodes as Rust lists them.
//
// Transfers are applied by the background poller (`storage.sync`). When it
// reports processed transfers via `inbox.updated`, a short-lived in-memory
// notice is shown; the screen's own listener reloads the wallet data. Opening
// the overlay lists what `inbox.pull` finds queued, every item as Rust
// described it, including those Rust marked as found on a previous-tip route.
import React, { useState, useCallback, useEffect } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import type { InboxItemView } from '../../../dsm/types';

// ---------------------------------------------------------------------------
// Notification record — ephemeral UI state only.
// unix_ts is display-only; it never enters any hash preimage.
// ---------------------------------------------------------------------------
type NotificationRecord = {
  id: string;
  count: number;
  unix_ts: number;
};

const APPLIED_NOTICE_TTL_MS = 8_000;

function formatTime(ts: number): string {
  try { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
  catch { return ''; }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
type Props = { headerHeight: number };

function InboxOverlayInner({ headerHeight }: Props): React.JSX.Element {
  const [open, setOpen] = useState(false);
  const [records, setRecords] = useState<NotificationRecord[]>([]);
  const [pending, setPending] = useState<InboxItemView[]>([]);
  const [loadingPending, setLoadingPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Badge = total transfer count across all active transient notices.
  const badgeCount = records.reduce((acc, r) => acc + r.count, 0);

  // Append a short-lived notice whenever the poller processes transfers.
  useEffect(() => {
    return bridgeEvents.on('inbox.updated', (detail) => {
      const processed = detail?.newItems ?? 0;
      if (processed > 0) {
        const rec: NotificationRecord = {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          count: processed,
          unix_ts: Date.now(),
        };
        setRecords((prev) => [rec, ...prev]);
        window.setTimeout(() => {
          setRecords((prev) => prev.filter((item) => item.id !== rec.id));
        }, APPLIED_NOTICE_TTL_MS);
      }
    });
  }, []);

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
    void loadPending();
  }, [open, loadPending]);

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

              {/* ---- Applied transfer notices (auto-expire) ---- */}
              {records.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ ...mono, fontSize: 10, opacity: 0.6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Recently applied
                  </div>
                  {records.map((rec) => (
                    <div key={rec.id} style={{ border: '1px solid var(--border)', padding: '8px 10px', background: 'rgba(var(--text-dark-rgb),0.06)', display: 'flex', flexDirection: 'column', gap: 6 }}>
                      <div style={{ ...mono, fontSize: 12 }}>
                        {rec.count === 1 ? '1 transfer received and applied' : `${rec.count} transfers received and applied`}
                      </div>
                      <span style={{ ...mono, fontSize: 10, opacity: 0.55 }}>{formatTime(rec.unix_ts)}</span>
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

              {records.length === 0 && pending.length === 0 && !loadingPending && (
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
