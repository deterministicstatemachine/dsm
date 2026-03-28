// SPDX-License-Identifier: Apache-2.0
// Inbox (b0x) overlay — transient notification surface for applied transfers.
//
// Transfers are applied automatically by the background poller (`storage.sync`).
// When the poller reports processed transfers via `inbox.updated`, a short-lived
// in-memory notification is shown. These notices are informational only and do
// not require manual acknowledgement.
import React, { useState, useCallback, useEffect } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { bridgeEvents } from '../../../bridge/bridgeEvents';

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
// Live pending items from storage node (pre-ACK, informational).
// ---------------------------------------------------------------------------
type PendingItem = { id: string; preview: string; isStaleRoute: boolean };

function mapPendingItems(items: unknown[]): PendingItem[] {
  return items.map((x, i: number) => {
    const e = typeof x === 'object' && x !== null ? (x as Record<string, unknown>) : {};
    return {
      id: typeof e.id === 'string' ? e.id : String(i),
      preview: typeof e.preview === 'string' ? e.preview : 'Pending item',
      isStaleRoute: e.isStaleRoute === true,
    };
  });
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
type Props = { headerHeight: number; loadWalletData: () => Promise<void> };

function InboxOverlayInner({ headerHeight, loadWalletData }: Props): JSX.Element {
  const [open, setOpen] = useState(false);
  const [records, setRecords] = useState<NotificationRecord[]>([]);
  const [pending, setPending] = useState<PendingItem[]>([]);
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
        void loadWalletData();
      }
    });
  }, [loadWalletData]);

  const loadPending = useCallback(async () => {
    setLoadingPending(true);
    setError(null);
    try {
      const res = await dsmClient.listB0xMessages();
      const nextPending = Array.isArray(res)
        ? mapPendingItems(res).filter((item) => !item.isStaleRoute)
        : [];
      setPending(nextPending);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally { setLoadingPending(false); }
  }, []);

  const handleOpen = useCallback(() => {
    if (open) { setOpen(false); return; }
    setOpen(true);
    void loadPending();
  }, [open, loadPending]);

  const handleClose = useCallback(() => { setOpen(false); setError(null); }, []);

  const mono: React.CSSProperties = { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' };

  return (
    <>
      {/* ---- Header button ---- */}
      <button
        onClick={handleOpen}
        className={`b0x-button${badgeCount > 0 ? ' has-items' : ''}`}
        title={badgeCount > 0 ? `Inbox — ${badgeCount} new` : 'Inbox'}
        aria-label={badgeCount > 0 ? `Inbox (${badgeCount} new)` : 'Inbox'}
        style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: 8, border: '1px solid var(--border)', borderRadius: 4, background: 'transparent' }}
      >
        <img src="images/icons/Mail-DSM-b0x.svg" alt="Inbox" style={{ width: 24, height: 24, imageRendering: 'pixelated' }} />
      </button>

      {/* ---- Overlay ---- */}
      {open && (
        <>
          <div onClick={handleClose} style={{ position: 'absolute', inset: 0, zIndex: 9997, background: 'transparent' }} />
          <div role="dialog" aria-label="Inbox" style={{ position: 'absolute', top: headerHeight + 8, right: 12, width: 320, maxWidth: 'calc(100% - 24px)', maxHeight: 'calc(100% - 24px)', overflowY: 'auto', overflowX: 'hidden', zIndex: 9998, background: 'var(--bg)', color: 'var(--text-dark)', border: '2px solid var(--border)', boxSizing: 'border-box' }}>

            {/* Header row */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '8px 10px', borderBottom: '2px solid var(--border)' }}>
              <strong style={{ ...mono, fontSize: 12 }}>Inbox — B0x</strong>
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

              {/* ---- Live items queued on storage node (pre-ACK) ---- */}
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
