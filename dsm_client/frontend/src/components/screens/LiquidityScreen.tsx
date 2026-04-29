// SPDX-License-Identifier: Apache-2.0
// Liquidity screen — owner-side AMM vault list + create flow.
//
// Reached from the home brick `LIQUIDITY`.  Replaces the dev-side
// DevAmmVaultScreen + DevAmmMonitorScreen pair: shows owned vaults at
// the top, "+ Create vault" at the bottom expands an inline form that
// confirms via ConfirmModal and emits a toast on success.
//
// All cryptographic work stays Rust-side (Track C.4 accept-or-stamp on
// `dlv.create`).  This screen frames typed inputs.

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createAmmVault,
  listOwnedAmmVaults,
  type AmmVaultSummary,
} from '../../dsm/amm';
import { decodeBase32Crockford } from '../../utils/textId';
import ConfirmModal from '../ConfirmModal';
import '../../styles/EnhancedWallet.css';

type Phase = 'idle' | 'loading' | 'creating' | 'created' | 'error';

interface Props {
  onNavigate?: (screen: string) => void;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('must be a non-negative integer');
  return BigInt(s);
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return '';
  }
}

export default function LiquidityScreen({ onNavigate }: Props): JSX.Element {
  const [phase, setPhase] = useState<Phase>('loading');
  const [vaults, setVaults] = useState<AmmVaultSummary[]>([]);
  const [error, setError] = useState<string>('');
  const [toast, setToast] = useState<string>('');
  const [showCreate, setShowCreate] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const [tokenA, setTokenA] = useState('');
  const [tokenB, setTokenB] = useState('');
  const [reserveA, setReserveA] = useState('');
  const [reserveB, setReserveB] = useState('');
  const [feeBps, setFeeBps] = useState('30');
  const [policyAnchor, setPolicyAnchor] = useState('');

  const refresh = useCallback(async () => {
    setPhase('loading');
    setError('');
    const r = await listOwnedAmmVaults();
    if (r.success) {
      setVaults(r.vaults ?? []);
      setPhase('idle');
    } else {
      setError(r.error || 'listOwnedAmmVaults failed');
      setPhase('error');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const formValid = useMemo(() => {
    if (!tokenA.trim() || !tokenB.trim()) return false;
    if (!reserveA.trim() || !reserveB.trim()) return false;
    if (!policyAnchor.trim()) return false;
    return true;
  }, [tokenA, tokenB, reserveA, reserveB, policyAnchor]);

  const handleCreate = useCallback(async () => {
    setError('');
    setToast('');
    try {
      setPhase('creating');
      let aBytes = new TextEncoder().encode(tokenA.trim());
      let bBytes = new TextEncoder().encode(tokenB.trim());
      let rA = bigIntFromString(reserveA);
      let rB = bigIntFromString(reserveB);

      // Canonical pair ordering — Rust enforces lex-lower-first; swap
      // here if the user typed them backwards so reserves stay aligned.
      if (compareBytes(aBytes, bBytes) > 0) {
        [aBytes, bBytes] = [bBytes, aBytes];
        [rA, rB] = [rB, rA];
      }

      const fee = Number(feeBps);
      if (!Number.isInteger(fee) || fee < 0 || fee >= 10_000) {
        throw new Error('fee_bps must be an integer in [0, 9999]');
      }

      const policyBytes = decodeBase32Crockford(policyAnchor.trim());
      if (policyBytes.length !== 32) {
        throw new Error(`policy anchor must decode to 32 bytes (got ${policyBytes.length})`);
      }

      const r = await createAmmVault({
        tokenA: aBytes,
        tokenB: bBytes,
        reserveA: rA,
        reserveB: rB,
        feeBps: fee,
        policyDigest: policyBytes,
      });
      if (!r.success || !r.vaultIdBase32) {
        throw new Error(r.error || 'createAmmVault failed');
      }
      setPhase('created');
      setToast(`Vault created. id=${r.vaultIdBase32.slice(0, 12)}…`);
      setShowCreate(false);
      setTokenA('');
      setTokenB('');
      setReserveA('');
      setReserveB('');
      setPolicyAnchor('');
      await refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'create failed';
      setError(msg);
      setPhase('error');
    }
  }, [tokenA, tokenB, reserveA, reserveB, feeBps, policyAnchor, refresh]);

  return (
    <div className="enhanced-wallet-screen" style={{ position: 'relative' }}>
      <div className="wallet-header">
        <h2>Liquidity</h2>
        <div className="header-buttons" style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            onClick={() => onNavigate?.('home')}
            className="cancel-button"
            style={{ fontSize: 11, padding: '4px 10px' }}
          >
            Back
          </button>
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={phase === 'loading' || phase === 'creating'}
            className="refresh-icon"
            aria-label="Refresh"
            title="Refresh"
            style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', padding: 6, border: '1px solid var(--border)', borderRadius: 4, background: 'transparent' }}
          >
            <img src="images/icons/icon_refresh.svg" alt="Refresh" style={{ width: 16, height: 16, imageRendering: 'pixelated' }} />
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner" style={{ padding: '8px 12px', marginBottom: 8, background: 'rgba(255,0,0,0.08)', border: '2px dashed var(--border)', fontSize: 12 }}>
          {error}
        </div>
      )}

      {toast && (
        <div className="warning-banner" style={{ padding: '8px 12px', marginBottom: 8, background: 'rgba(var(--text-rgb),0.08)', border: '1px solid var(--border)', fontSize: 12 }} role="status" aria-live="polite">
          {toast}
        </div>
      )}

      <div className="tab-content">
        <h4 style={{ fontSize: 12, marginBottom: 8 }}>My vaults ({vaults.length})</h4>
        {phase === 'loading' && <div style={{ fontSize: 11, opacity: 0.7 }}>Loading…</div>}
        {phase !== 'loading' && vaults.length === 0 && (
          <div className="empty-state">
            <p>No AMM vaults owned by this wallet.</p>
            <p style={{ fontSize: 10, opacity: 0.7 }}>Create one below to start earning fees on swaps.</p>
          </div>
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {vaults.map((v) => (
            <div key={v.vaultIdBase32} className="balance-card" style={{ padding: '8px 12px' }}>
              <div className="balance-info">
                <span className="token-symbol">
                  {decodeUtf8(v.tokenA)} / {decodeUtf8(v.tokenB)}
                </span>
                <span className="balance-amount">fee {v.feeBps} bps</span>
              </div>
              <div style={{ fontSize: 10, opacity: 0.85, marginTop: 4 }}>
                reserves: {v.reserveA.toString()} / {v.reserveB.toString()}
              </div>
              <div style={{ fontSize: 10, opacity: 0.7, marginTop: 2 }}>
                vault {v.vaultIdBase32.slice(0, 16)}… · {v.routingAdvertised ? `ad: ✓ seq=${v.advertisedStateNumber.toString()}` : 'ad: ✗ not published'}
              </div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 16 }}>
          {!showCreate && (
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="send-button button-brick"
              disabled={phase === 'creating'}
            >
              + Create vault
            </button>
          )}
        </div>

        {showCreate && (
          <div className="balance-section" style={{ marginTop: 16 }}>
            <h4 style={{ fontSize: 12, marginBottom: 8 }}>New AMM vault</h4>
            <div className="form-group">
              <label htmlFor="liq-token-a">Token A</label>
              <input id="liq-token-a" className="form-input" value={tokenA} onChange={(e) => setTokenA(e.target.value)} placeholder="e.g. DEMO_AAA" />
            </div>
            <div className="form-group">
              <label htmlFor="liq-token-b">Token B</label>
              <input id="liq-token-b" className="form-input" value={tokenB} onChange={(e) => setTokenB(e.target.value)} placeholder="e.g. DEMO_BBB" />
            </div>
            <div className="form-group">
              <label htmlFor="liq-reserve-a">Reserve A</label>
              <input id="liq-reserve-a" type="number" min="0" className="form-input" value={reserveA} onChange={(e) => setReserveA(e.target.value)} placeholder="0" />
            </div>
            <div className="form-group">
              <label htmlFor="liq-reserve-b">Reserve B</label>
              <input id="liq-reserve-b" type="number" min="0" className="form-input" value={reserveB} onChange={(e) => setReserveB(e.target.value)} placeholder="0" />
            </div>
            <div className="form-group">
              <label htmlFor="liq-fee">Fee (bps)</label>
              <input id="liq-fee" type="number" min="0" max="9999" className="form-input" value={feeBps} onChange={(e) => setFeeBps(e.target.value)} />
            </div>
            <div className="form-group">
              <label htmlFor="liq-policy">Policy anchor (Base32 Crockford, 32 bytes)</label>
              <textarea id="liq-policy" className="form-input" value={policyAnchor} onChange={(e) => setPolicyAnchor(e.target.value)} placeholder="paste 52-char Base32" rows={2} />
            </div>
            <div className="form-actions">
              <button type="button" className="cancel-button" onClick={() => setShowCreate(false)} disabled={phase === 'creating'}>Cancel</button>
              <button
                type="button"
                className="send-button button-brick"
                onClick={() => setShowConfirm(true)}
                disabled={!formValid || phase === 'creating'}
              >
                {phase === 'creating' ? 'Creating…' : 'Create'}
              </button>
            </div>
          </div>
        )}
      </div>

      <ConfirmModal
        visible={showConfirm}
        title="Create AMM vault"
        message={`Create vault ${tokenA} / ${tokenB} with reserves ${reserveA} / ${reserveB} at ${feeBps} bps fee?`}
        onConfirm={() => { setShowConfirm(false); void handleCreate(); }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}
