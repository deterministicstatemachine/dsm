/* eslint-disable @typescript-eslint/no-explicit-any, no-console */
// SPDX-License-Identifier: Apache-2.0
// path: src/components/screens/DevAmmMonitorScreen.tsx
//
// AMM vault monitor — owner-side inventory of constant-product
// vaults this wallet created, with live reserves + advertised state
// numbers.  Pure UI; the Rust handler `dlv.listOwnedAmmVaults` does
// all filtering + storage cross-reference.

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useDpadNav } from '../../hooks/useDpadNav';
import { listOwnedAmmVaults, type AmmVaultSummary } from '../../dsm/amm';
import './SettingsScreen.css';

function tokenLabel(bytes: Uint8Array): string {
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return `<${bytes.length} bytes>`;
  }
}

export default function DevAmmMonitorScreen(): JSX.Element {
  const [vaults, setVaults] = useState<AmmVaultSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>('');

  const refresh = useCallback(async () => {
    setBusy(true);
    setStatus('');
    try {
      const result = await listOwnedAmmVaults();
      if (!result.success) {
        setStatus(`Refresh failed: ${result.error ?? 'unknown'}`);
        return;
      }
      setVaults(result.vaults ?? []);
      setStatus(
        (result.vaults ?? []).length === 0
          ? 'No AMM vaults owned by this wallet.'
          : `${(result.vaults ?? []).length} owned vault(s).`,
      );
    } catch (e: any) {
      setStatus(e?.message || 'Refresh failed');
    } finally {
      setBusy(false);
    }
  }, []);

  // Auto-refresh on mount.
  useEffect(() => {
    void refresh();
  }, [refresh]);

  const navActions = useMemo(
    () => [() => void refresh()],
    [refresh],
  );
  useDpadNav({ actions: navActions });

  return (
    <div className="settings-screen">
      <h1>AMM Vault Monitor (Dev)</h1>
      <p className="settings-subtitle">
        Constant-product vaults this wallet has created.  Reserves
        and advertised state_number reflect the post-trade republish
        chain — chunk &#35;7 plus republish-on-settled keeps these
        synced after every accepted unlock.
      </p>

      <section style={{ marginBottom: 16 }}>
        <button type="button" onClick={refresh} disabled={busy}>
          {busy ? 'Refreshing…' : 'Refresh'}
        </button>
      </section>

      {vaults.length === 0 && (
        <p style={{ color: '#888', fontFamily: 'monospace', fontSize: 12 }}>
          {status || 'Loading…'}
        </p>
      )}

      {vaults.length > 0 && (
        <section style={{ marginBottom: 16 }}>
          {vaults.map((v) => (
            <div
              key={v.vaultIdBase32}
              style={{
                padding: 8,
                marginBottom: 6,
                fontFamily: 'monospace',
                fontSize: 12,
                background: '#22222244',
              }}
            >
              <div style={{ wordBreak: 'break-all' }}>
                <strong>vault</strong>{' '}
                <code style={{ fontSize: 11 }}>
                  {v.vaultIdBase32.slice(0, 16)}…
                </code>
              </div>
              <div>
                <strong>pair</strong> {tokenLabel(v.tokenA)}/{tokenLabel(v.tokenB)}{' '}
                <strong>fee</strong> {v.feeBps} bps
              </div>
              <div>
                <strong>reserves</strong> ({String(v.reserveA)},{' '}
                {String(v.reserveB)})
              </div>
              <div>
                <strong>routing ad</strong>:{' '}
                {v.routingAdvertised
                  ? `✓ published (state_number=${String(v.advertisedStateNumber)})`
                  : '✗ not published — run "Publish routing ad" on the vault screen'}
              </div>
            </div>
          ))}
        </section>
      )}

      {status && vaults.length > 0 && (
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
