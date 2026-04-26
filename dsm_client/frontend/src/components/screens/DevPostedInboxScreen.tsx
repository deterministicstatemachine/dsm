/* eslint-disable @typescript-eslint/no-explicit-any, no-console */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/DevPostedInboxScreen.tsx
//
// Posted-mode DLV inbox — receiver flow.  Lists pending posted DLVs
// addressed to the local device's Kyber public key, mirrors them
// into the local DLVManager, and lets the user claim with one tap.
//
// All protocol logic stays Rust-side (per the architecture rule).
// The screen does pure UI framing: each button corresponds to one
// bridge call.

import React, { useState, useMemo, useCallback } from 'react';
import { useDpadNav } from '../../hooks/useDpadNav';
import {
  listPostedDlvs,
  syncPostedDlvs,
  claimPostedDlv,
  type PostedDlvSummary,
} from '../../dsm/posted_dlv';
import { decodeBase32Crockford } from '../../utils/textId';
import './SettingsScreen.css';

interface VaultRowState {
  status: 'pending' | 'syncing' | 'mirrored' | 'claiming' | 'claimed' | 'error';
  detail?: string;
}

export default function DevPostedInboxScreen(): JSX.Element {
  const [pending, setPending] = useState<PostedDlvSummary[]>([]);
  const [rowState, setRowState] = useState<Record<string, VaultRowState>>({});
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>('');

  const refreshList = useCallback(async () => {
    setBusy(true);
    setStatus('');
    try {
      const result = await listPostedDlvs();
      if (!result.success) {
        setStatus(`Refresh failed: ${result.error ?? 'unknown'}`);
        return;
      }
      setPending(result.vaults ?? []);
      // Reset row states for vaults that disappeared.
      setRowState((prev) => {
        const next: Record<string, VaultRowState> = {};
        for (const v of result.vaults ?? []) {
          next[v.dlvIdBase32] = prev[v.dlvIdBase32] ?? { status: 'pending' };
        }
        return next;
      });
      setStatus(
        (result.vaults ?? []).length === 0
          ? 'Inbox empty.'
          : `${(result.vaults ?? []).length} pending DLV(s).`,
      );
    } catch (e: any) {
      setStatus(e?.message || 'Refresh failed');
    } finally {
      setBusy(false);
    }
  }, []);

  const handleSyncAll = useCallback(async () => {
    setBusy(true);
    setStatus('');
    try {
      // Mark all pending rows as syncing.
      setRowState((prev) => {
        const next = { ...prev };
        for (const v of pending) {
          if (next[v.dlvIdBase32]?.status === 'pending') {
            next[v.dlvIdBase32] = { status: 'syncing' };
          }
        }
        return next;
      });
      const result = await syncPostedDlvs();
      if (!result.success) {
        setStatus(`Sync failed: ${result.error ?? 'unknown'}`);
        // Roll syncing rows back to pending.
        setRowState((prev) => {
          const next = { ...prev };
          for (const v of pending) {
            if (next[v.dlvIdBase32]?.status === 'syncing') {
              next[v.dlvIdBase32] = { status: 'pending' };
            }
          }
          return next;
        });
        return;
      }
      const mirrored = new Set(result.newlyMirroredBase32 ?? []);
      setRowState((prev) => {
        const next = { ...prev };
        for (const v of pending) {
          // newlyMirroredBase32 contains only freshly-inserted ids.
          // Already-mirrored vaults are silently absent from the
          // response, but they ARE locally claimable too — so any
          // pending / syncing row that wasn't an explicit failure
          // can advance to "mirrored".
          if (
            next[v.dlvIdBase32]?.status === 'syncing' ||
            mirrored.has(v.dlvIdBase32)
          ) {
            next[v.dlvIdBase32] = { status: 'mirrored' };
          }
        }
        return next;
      });
      setStatus(
        `Synced. ${(result.newlyMirroredBase32 ?? []).length} newly mirrored.`,
      );
    } catch (e: any) {
      setStatus(e?.message || 'Sync failed');
    } finally {
      setBusy(false);
    }
  }, [pending]);

  const handleClaim = useCallback(async (vaultIdBase32: string) => {
    setBusy(true);
    setStatus('');
    setRowState((prev) => ({
      ...prev,
      [vaultIdBase32]: { status: 'claiming' },
    }));
    try {
      const vaultIdBytes = new Uint8Array(decodeBase32Crockford(vaultIdBase32));
      if (vaultIdBytes.length !== 32) {
        throw new Error('decoded vault id is not 32 bytes');
      }
      const result = await claimPostedDlv({ vaultId: vaultIdBytes });
      if (!result.success) {
        setRowState((prev) => ({
          ...prev,
          [vaultIdBase32]: { status: 'error', detail: result.error },
        }));
        setStatus(`Claim failed: ${result.error ?? 'unknown'}`);
        return;
      }
      setRowState((prev) => ({
        ...prev,
        [vaultIdBase32]: { status: 'claimed', detail: result.vaultIdBase32 },
      }));
      setStatus(`Claimed ${vaultIdBase32}.`);
    } catch (e: any) {
      setRowState((prev) => ({
        ...prev,
        [vaultIdBase32]: { status: 'error', detail: e?.message },
      }));
      setStatus(e?.message || 'Claim failed');
    } finally {
      setBusy(false);
    }
  }, []);

  const navActions = useMemo(
    () => [() => void refreshList(), () => void handleSyncAll()],
    [refreshList, handleSyncAll],
  );
  useDpadNav({ actions: navActions });

  return (
    <div className="settings-screen">
      <h1>Posted DLV Inbox (Dev)</h1>
      <p className="settings-subtitle">
        DLVs addressed to this device's Kyber public key.  Refresh
        discovers pending vaults; Sync mirrors them locally; Claim
        runs `dlv.claim` per vault.
      </p>

      <section style={{ marginBottom: 16 }}>
        <button type="button" onClick={refreshList} disabled={busy}>
          {busy ? 'Working…' : 'Refresh inbox'}
        </button>{' '}
        <button
          type="button"
          onClick={handleSyncAll}
          disabled={busy || pending.length === 0}
        >
          {busy ? 'Working…' : `Sync all (${pending.length})`}
        </button>
      </section>

      {pending.length === 0 && (
        <p style={{ color: '#888', fontFamily: 'monospace', fontSize: 12 }}>
          No pending DLVs.  Hit Refresh to query storage nodes.
        </p>
      )}

      {pending.length > 0 && (
        <section style={{ marginBottom: 16 }}>
          <h2>Pending vaults</h2>
          {pending.map((v) => {
            const state = rowState[v.dlvIdBase32] ?? { status: 'pending' };
            const claimable =
              state.status === 'mirrored' || state.status === 'pending';
            const indicator =
              state.status === 'claimed'
                ? '✓'
                : state.status === 'error'
                  ? '✗'
                  : state.status === 'claiming' || state.status === 'syncing'
                    ? '·'
                    : ' ';
            return (
              <div
                key={v.dlvIdBase32}
                style={{
                  padding: 6,
                  marginBottom: 4,
                  fontFamily: 'monospace',
                  fontSize: 12,
                  background:
                    state.status === 'claimed'
                      ? '#22884422'
                      : state.status === 'error'
                        ? '#cc444422'
                        : 'transparent',
                }}
              >
                <div>
                  <span style={{ marginRight: 6 }}>{indicator}</span>
                  vault={v.dlvIdBase32.slice(0, 12)}…{' '}
                  creator={v.creatorPublicKeyBase32.slice(0, 12)}…
                </div>
                <div style={{ marginTop: 4 }}>
                  state: {state.status}
                  {state.detail && (
                    <span style={{ color: '#888', marginLeft: 6 }}>
                      — {state.detail}
                    </span>
                  )}
                  {claimable && (
                    <button
                      type="button"
                      onClick={() => void handleClaim(v.dlvIdBase32)}
                      disabled={busy}
                      style={{ marginLeft: 8 }}
                    >
                      Claim
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </section>
      )}

      {status && (
        <p
          style={{
            padding: 8,
            background: status.toLowerCase().includes('fail') ? '#cc444433' : '#44cc4433',
            fontFamily: 'monospace',
            fontSize: 12,
            wordBreak: 'break-all',
          }}
        >
          {status}
        </p>
      )}
    </div>
  );
}
