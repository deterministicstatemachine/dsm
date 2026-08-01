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
import { publishRoutingAdvertisement } from '../../dsm/route_commit';
import { decodeBase32Crockford } from '../../utils/textId';
import { getAllBalances } from '../../dsm/wallet';
import type { TokenBalanceView } from '../../dsm/types';
import ConfirmModal from '../ConfirmModal';
import '../../styles/EnhancedWallet.css';

type Phase = 'idle' | 'loading' | 'creating' | 'publishing' | 'republishing' | 'created' | 'error';

interface Props {
  onNavigate?: (screen: string) => void;
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

  // The pair is chosen from assets this device actually HOLDS, and each choice
  // carries the token's 32-byte CPTA anchor. Free text used to be sent as the
  // pair identity, which made a ticker the asset's name AND its identity — and
  // a ticker is not an identity: two distinct RIGB tokens have existed here.
  const [holdings, setHoldings] = useState<TokenBalanceView[]>([]);
  const [tokenA, setTokenA] = useState('');
  const [tokenB, setTokenB] = useState('');
  const [reserveA, setReserveA] = useState('');
  const [reserveB, setReserveB] = useState('');
  const [feeBps, setFeeBps] = useState('30');
  const [policyAnchor, setPolicyAnchor] = useState('');
  const [pendingPublishId, setPendingPublishId] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setPhase('loading');
    setError('');
    try {
      // Only assets carrying a CPTA anchor can name a pair. One without an
      // anchor has no identity to send, so it is not offered rather than
      // offered and rejected later.
      const bal = await getAllBalances();
      setHoldings(bal.filter((b) => (b.policyAnchorB32 ?? '').length > 0));
    } catch {
      setHoldings([]);
    }
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

  const handleRepublish = useCallback(async (v: AmmVaultSummary) => {
    setError('');
    setToast('');
    setPendingPublishId(v.vaultIdBase32);
    setPhase('republishing');
    try {
      const vaultIdBytes = decodeBase32Crockford(v.vaultIdBase32);
      if (vaultIdBytes.length !== 32) {
        throw new Error(`vault_id Base32 must decode to 32 bytes (got ${vaultIdBytes.length})`);
      }
      // Phase 13 follow-up: pass the REAL `unlock_spec_digest` +
      // `unlock_spec_key` that Rust persisted in DLV state at create
      // time and exposes on `AmmVaultSummaryV1`.  The pre-fix path
      // stamped 32 zero bytes here (under a comment claiming Rust
      // treated zeros as an "advertisement-only" sentinel) — the
      // claim was false; the route handler stored zeros verbatim and
      // corrupted the advertisement so traders on other devices
      // failed unlock-spec verification.  This guard refuses to fire
      // for legacy vaults (no persisted digest) — the Publish button
      // is suppressed for those vaults in the row render below.
      if (!v.unlockSpecDigest || v.unlockSpecDigest.length !== 32 || !v.unlockSpecKey) {
        throw new Error(
          'vault has no persisted unlock-spec digest (legacy vault created before Phase 13); ' +
            're-create the vault to enable Publish-retry',
        );
      }
      // Re-derive canonical pair ordering (Rust enforces lex-lower-first).
      // listOwnedAmmVaults returns tokenA/tokenB already canonicalised by
      // dlv.create, so the bytes here are good to forward verbatim.
      const publishR = await publishRoutingAdvertisement({
        vaultId: vaultIdBytes,
        tokenA: v.tokenA,
        tokenB: v.tokenB,
        reserveA: v.reserveA,
        reserveB: v.reserveB,
        feeBps: v.feeBps,
        unlockSpecDigest: v.unlockSpecDigest,
        unlockSpecKey: v.unlockSpecKey,
      });
      if (!publishR.success) {
        throw new Error(publishR.error || 'publishRoutingAdvertisement failed');
      }
      setToast(`Advertisement published. id=${v.vaultIdBase32.slice(0, 12)}…`);
      await refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'publish failed';
      setError(msg);
      setPhase('error');
    } finally {
      setPendingPublishId(null);
    }
  }, [refresh]);

  /// Display name for a selected anchor. Names are for the human reading the
  /// card; the anchor is what is sent.
  const tickerFor = useCallback(
    (anchor: string) => holdings.find((h) => h.policyAnchorB32 === anchor)?.ticker ?? anchor,
    [holdings],
  );

  const formValid = useMemo(() => {
    if (!tokenA.trim() || !tokenB.trim()) return false;
    if (tokenA === tokenB) return false;
    if (!reserveA.trim() || !reserveB.trim()) return false;
    if (!policyAnchor.trim()) return false;
    return true;
  }, [tokenA, tokenB, reserveA, reserveB, policyAnchor]);

  const handleCreate = useCallback(async () => {
    setError('');
    setToast('');
    try {
      setPhase('creating');
      // 32-byte CPTA policy commits, taken from the selected holdings. Identity
      // comes from the picker; nothing here derives it from a name.
      const aBytes = decodeBase32Crockford(tokenA);
      const bBytes = decodeBase32Crockford(tokenB);
      if (aBytes.length !== 32 || bBytes.length !== 32) {
        throw new Error('each side of the pair must be a 32-byte policy commit');
      }
      const rA = bigIntFromString(reserveA);
      const rB = bigIntFromString(reserveB);

      // Ordering is NOT done here. Rust owns canonicalisation: it sorts the pair
      // over the commits and aligns the funding legs to that order, so there is
      // one implementation of "which side is A" rather than a render-layer copy
      // that can disagree with it.

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

      // Chain `publishRoutingAdvertisement` so the vault is
      // discoverable by traders on OTHER devices via
      // `route.syncVaultsForPair`.  Without this step the vault
      // lives only in the local DLVManager and the cross-device
      // SoFi flow we proved on real hardware can't fire from the UI.
      //
      // `vaultProtoBytes` is left empty — Rust derives the canonical
      // VaultPostProto from the local DLVManager (the authoritative
      // source).
      setPhase('publishing');
      const vaultIdBytes = decodeBase32Crockford(r.vaultIdBase32);
      if (vaultIdBytes.length !== 32) {
        throw new Error(`vault_id Base32 must decode to 32 bytes (got ${vaultIdBytes.length})`);
      }
      const publishR = await publishRoutingAdvertisement({
        vaultId: vaultIdBytes,
        tokenA: aBytes,
        tokenB: bBytes,
        reserveA: rA,
        reserveB: rB,
        feeBps: fee,
        // The policy anchor doubles as a stable 32-byte unlock-spec
        // identifier for the v1 SoFi UI flow.  Traders read the
        // digest verbatim from the published advertisement; the
        // protocol doesn't require it to differ from policyDigest.
        unlockSpecDigest: policyBytes,
        unlockSpecKey: `defi/spec/amm/${r.vaultIdBase32.slice(0, 16)}`,
        // No vaultProtoBytes — Rust derives.  No ownerPublicKey —
        // Rust stamps the wallet pk.
      });
      if (!publishR.success) {
        // Vault was created locally; only the advertisement publish
        // failed.  Surface the error but don't roll back the vault —
        // the owner can refresh + retry from the list view in a
        // future polish step.
        throw new Error(`Vault created, but advertisement publish failed: ${publishR.error}`);
      }

      setPhase('created');
      setToast(`Vault created + published. id=${r.vaultIdBase32.slice(0, 12)}…`);
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
            disabled={phase === 'loading' || phase === 'creating' || phase === 'publishing' || phase === 'republishing'}
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
        <div className="error-banner" style={{ padding: '8px 12px', marginBottom: 8, background: 'rgba(var(--text-rgb), 0.12)', border: '2px dashed var(--border)', fontSize: 12 }}>
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
          {vaults.map((v) => {
            const isPublishing =
              phase === 'republishing' && pendingPublishId === v.vaultIdBase32;
            return (
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
                <div style={{ fontSize: 10, opacity: 0.7, marginTop: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                  <span>
                    vault {v.vaultIdBase32.slice(0, 16)}… · {v.routingAdvertised ? `ad: ✓ seq=${v.advertisedStateNumber.toString()}` : 'ad: ✗ not published'}
                  </span>
                  {!v.routingAdvertised && v.unlockSpecDigest && v.unlockSpecKey && (
                    // Phase 13 follow-up: hide the button for legacy
                    // vaults whose persisted policy_digest is absent.
                    // Republishing them would require stamping a zero
                    // digest (the pre-fix bug); refuse instead so the
                    // owner can re-create with a fresh CPTA anchor
                    // rather than silently corrupting the ad.
                    <button
                      type="button"
                      onClick={() => void handleRepublish(v)}
                      disabled={phase === 'creating' || phase === 'publishing' || phase === 'republishing'}
                      className="cancel-button"
                      style={{ fontSize: 10, padding: '2px 8px' }}
                      title="Republish routing advertisement so traders on other devices can discover this vault"
                    >
                      {isPublishing ? 'Publishing…' : 'Publish'}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ marginTop: 16 }}>
          {!showCreate && (
            <button
              type="button"
              onClick={() => setShowCreate(true)}
              className="send-button button-brick"
              disabled={phase === 'creating' || phase === 'publishing' || phase === 'republishing'}
            >
              + Create vault
            </button>
          )}
        </div>

        {showCreate && (
          <div className="balance-section" style={{ marginTop: 16 }}>
            <h4 style={{ fontSize: 12, marginBottom: 8 }}>New AMM vault</h4>
            {/* The pair is SELECTED, never typed. The option's value is the
                token's CPTA anchor — its identity — while the label is the
                ticker, which is display only. Free text made the two the same
                thing, and a ticker can name more than one token. */}
            <div className="form-group">
              <label htmlFor="liq-token-a">Token A</label>
              <select id="liq-token-a" className="form-input" value={tokenA} onChange={(e) => setTokenA(e.target.value)}>
                <option value="">select a held asset…</option>
                {holdings.map((h) => (
                  <option key={h.policyAnchorB32} value={h.policyAnchorB32}>
                    {h.ticker} · {h.anchorFingerprint}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label htmlFor="liq-token-b">Token B</label>
              <select id="liq-token-b" className="form-input" value={tokenB} onChange={(e) => setTokenB(e.target.value)}>
                <option value="">select a held asset…</option>
                {holdings
                  .filter((h) => h.policyAnchorB32 !== tokenA)
                  .map((h) => (
                    <option key={h.policyAnchorB32} value={h.policyAnchorB32}>
                      {h.ticker} · {h.anchorFingerprint}
                    </option>
                  ))}
              </select>
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
              <button type="button" className="cancel-button" onClick={() => setShowCreate(false)} disabled={phase === 'creating' || phase === 'publishing'}>Cancel</button>
              <button
                type="button"
                className="send-button button-brick"
                onClick={() => setShowConfirm(true)}
                disabled={!formValid || phase === 'creating' || phase === 'publishing'}
              >
                {phase === 'creating' ? 'Creating…' : phase === 'publishing' ? 'Publishing…' : 'Create'}
              </button>
            </div>
          </div>
        )}
      </div>

      <ConfirmModal
        visible={showConfirm}
        title="Create AMM vault"
        message={`Create vault ${tickerFor(tokenA)} / ${tickerFor(tokenB)} with reserves ${reserveA} / ${reserveB} at ${feeBps} bps fee?`}
        onConfirm={() => { setShowConfirm(false); void handleCreate(); }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}
