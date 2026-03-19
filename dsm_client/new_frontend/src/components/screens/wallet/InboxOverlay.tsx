// SPDX-License-Identifier: Apache-2.0
// Inbox (b0x) overlay — notification log for applied transfers.
//
// Transfers are applied automatically by the background poller (storage.sync).
// When the poller reports processed transfers via `inbox.updated`, a
// NotificationRecord is appended to localStorage. The badge shows the total
// count of unacknowledged records and does NOT clear on overlay open — it
// clears only when the user explicitly taps "Got it" on each notification.
import React, { useState, useCallback, useEffect } from 'react';
import { dsmClient } from '../../../services/dsmClient';
import { bridgeEvents } from '../../../bridge/bridgeEvents';

// ---------------------------------------------------------------------------
// Notification record — persisted so it survives app restarts.
// timestamp is display-only; it never enters any hash preimage.
// ---------------------------------------------------------------------------
type NotificationRecord = {
  id: string;
  count: number;
  timestamp: number;
};

const RECORDS_KEY = 'dsm_inbox_notifications_v1';

function loadRecords(): NotificationRecord[] {
  try {
    const raw = localStorage.getItem(RECORDS_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return (parsed as unknown[]).filter(
      (r): r is NotificationRecord =>
        typeof r === 'object' && r !== null &&
        typeof (r as Record<string, unknown>).id === 'string' &&
        typeof (r as Record<string, unknown>).count === 'number'
    );
  } catch { return []; }
}

function saveRecords(records: NotificationRecord[]): void {
  try { localStorage.setItem(RECORDS_KEY, JSON.stringify(records)); } catch { /* ignore */ }
}

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
  const [records, setRecords] = useState<NotificationRecord[]>(loadRecords);
  const [pending, setPending] = useState<PendingItem[]>([]);
  const [loadingPending, setLoadingPending] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Badge = total transfer count across all unacknowledged records.
  const badgeCount = records.reduce((acc, r) => acc + r.count, 0);

  useEffect(() => { saveRecords(records); }, [records]);

  // Append a record whenever the poller processes transfers.
  useEffect(() => {
    return bridgeEvents.on('inbox.updated', (detail) => {
      const processed = detail?.newItems ?? 0;
      if (processed > 0) {
        const rec: NotificationRecord = {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          count: processed,
          timestamp: Date.now(),
        };
        setRecords((prev) => { const next = [rec, ...prev]; saveRecords(next); return next; });
        void loadWalletData();
      }
    });
  }, [loadWalletData]);

  const loadPending = useCallback(async () => {
    setLoadingPending(true);
    setError(null);
    try {
      const res = await dsmClient.listB0xMessages();
      setPending(Array.isArray(res) ? mapPendingItems(res) : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally { setLoadingPending(false); }
  }, []);

  const handleOpen = useCallback(() => {
    if (open) { setOpen(false); return; }
    setOpen(true);
    void loadPending();
  }, [open, loadPending]);

  const handleSyncNow = useCallback(async () => {
    if (syncing) return;
    setSyncing(true);
    setError(null);
    try {
      await dsmClient.syncWithStorage({ pullInbox: true });
      await loadWalletData();
      await loadPending();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Sync failed');
    } finally { setSyncing(false); }
  }, [syncing, loadWalletData, loadPending]);

  // Remove one record — badge shrinks by that record's count.
  const handleGotIt = useCallback((id: string) => {
    setRecords((prev) => { const next = prev.filter((r) => r.id !== id); saveRecords(next); return next; });
  }, []);

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

              {/* ---- Notification records (persist until Got it) ---- */}
              {records.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ ...mono, fontSize: 10, opacity: 0.6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Received — tap Got it to clear
                  </div>
                  {records.map((rec) => (
                    <div key={rec.id} style={{ border: '1px solid var(--border)', padding: '8px 10px', background: 'rgba(var(--text-dark-rgb),0.06)', display: 'flex', flexDirection: 'column', gap: 6 }}>
                      <div style={{ ...mono, fontSize: 12 }}>
                        {rec.count === 1 ? '1 transfer received and applied' : `${rec.count} transfers received and applied`}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                        <span style={{ ...mono, fontSize: 10, opacity: 0.55 }}>{formatTime(rec.timestamp)}</span>
                        <button onClick={() => handleGotIt(rec.id)} className="button-brick" style={{ ...mono, fontSize: 11, padding: '4px 10px', borderRadius: 8, border: '1px solid var(--border)', background: 'transparent', color: 'inherit', cursor: 'pointer' }}>
                          Okay
                        </button>
                      </div>
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

              {/* ---- Footer ---- */}
              <div style={{ display: 'flex', gap: 8 }}>
                {records.length > 0 && (
                  <button
                    onClick={() => { setRecords([]); saveRecords([]); }}
                    className="button-brick"
                    style={{ flex: 1, ...mono, fontSize: 11, padding: '6px 10px', borderRadius: 8, border: '1px solid var(--border)', background: 'transparent', color: 'inherit', cursor: 'pointer' }}
                  >
                    Okay to all
                  </button>
                )}
                <button
                  onClick={() => void handleSyncNow()}
                  disabled={syncing || loadingPending}
                  className="button-brick"
                  style={{ flex: 1, ...mono, fontSize: 11, padding: '6px 10px', borderRadius: 8, border: '1px solid var(--border)', background: 'transparent', color: 'inherit', cursor: 'pointer' }}
                >
                  {syncing ? 'Syncing…' : 'Sync now'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  );
}

const InboxOverlay = React.memo(InboxOverlayInner);
export default InboxOverlay;
