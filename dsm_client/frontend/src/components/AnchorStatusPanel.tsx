// SPDX-License-Identifier: Apache-2.0

import React, { useCallback, useEffect, useState } from 'react';
import { getAnchorStatus, AnchorStatus } from '../dsm/anchor';
import logger from '../utils/logger';

const cardStyle: React.CSSProperties = {
  background: 'rgba(var(--bg-rgb),0.55)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: 10,
  marginBottom: 10,
  color: 'var(--text-dark)',
  fontSize: '10px',
  lineHeight: 1.4,
};

const rowStyle: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  gap: 8,
  wordBreak: 'break-all',
  marginTop: 2,
};

/**
 * Read-only offline-bearer anchor status (Stage 4 Slice 3, signal c). Pure rendering: reads the
 * `anchor.status` route and displays the sender's appliance snapshot (connected state, live counter
 * floor u, enrolled counter, anchor identity/chip-key/frontier prefixes). No protocol logic here —
 * all state comes from the Rust handler.
 */
export default function AnchorStatusPanel() {
  const [status, setStatus] = useState<AnchorStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setStatus(await getAnchorStatus());
    } catch (e) {
      logger.warn('[AnchorStatusPanel] getAnchorStatus failed', e);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const dot = (ok: boolean) => (
    <span
      style={{
        display: 'inline-block',
        width: 8,
        height: 8,
        borderRadius: 4,
        marginRight: 6,
        background: ok ? 'var(--good, #3fb950)' : 'var(--muted, #8b949e)',
      }}
    />
  );

  const label = (text: string) => <span style={{ opacity: 0.7 }}>{text}</span>;

  return (
    <div style={cardStyle} data-testid="anchor-status-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <strong style={{ fontSize: '11px' }}>Offline anchor</strong>
        <button
          onClick={() => void refresh()}
          disabled={loading}
          data-testid="anchor-status-refresh"
          style={{
            fontSize: '9px',
            padding: '3px 8px',
            border: '1px solid var(--border)',
            borderRadius: 6,
            background: 'transparent',
            color: 'var(--text-dark)',
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? '…' : 'Refresh'}
        </button>
      </div>

      {error ? (
        <div data-testid="anchor-status-error" style={{ opacity: 0.8 }}>
          Status unavailable: {error}
        </div>
      ) : !status ? (
        <div style={{ opacity: 0.7 }}>Reading anchor…</div>
      ) : !status.connected ? (
        <div data-testid="anchor-status-disconnected">
          {dot(false)} No anchor device connected — {status.statusText}
        </div>
      ) : (
        <div data-testid="anchor-status-connected">
          <div style={{ marginBottom: 6 }}>
            {dot(true)} {status.statusText}
          </div>
          <div style={rowStyle}>
            {label('Counter (u)')}
            <span>{String(status.anchorCounter)}</span>
          </div>
          <div style={rowStyle}>
            {label('Enrolled at')}
            <span>{String(status.enrolledCounter)}</span>
          </div>
          {status.anchorIdB32 && (
            <div style={rowStyle}>
              {label('Anchor ID')}
              <span>{status.anchorIdB32}…</span>
            </div>
          )}
          {status.pkChipB32 && (
            <div style={rowStyle}>
              {label('Chip key')}
              <span>{status.pkChipB32}…</span>
            </div>
          )}
          {status.frontierRootB32 && (
            <div style={rowStyle}>
              {label('Frontier')}
              <span>{status.frontierRootB32}…</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
