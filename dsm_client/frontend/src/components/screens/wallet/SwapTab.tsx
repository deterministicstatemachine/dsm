// SPDX-License-Identifier: Apache-2.0
// Swap tab — AMM constant-product trade flow inside the wallet.
//
// Free-form symmetric token inputs: any token id pair is valid as long
// as some vault advertises liquidity for it.  Slippage tolerance is
// captured client-side and used to compute a min-out floor that the
// trader can verify before signing; backend route-fallback within the
// envelope (alternate paths when primary moves) is Tier 2 work
// (intent-bounds on RouteCommitHopV1) and is not yet wired through —
// the UI surface is built so the wiring is additive when that lands.

import React, { useCallback, useMemo, useState } from 'react';
import {
  listAdvertisementsForPair,
  syncVaultsForPair,
  findAndBindBestPath,
  signRouteCommit,
  computeExternalCommitment,
  publishExternalCommitment,
  unlockVaultRouted,
  type RoutingAdvertisementSummary,
} from '../../../dsm/route_commit';
import { decodeBase32Crockford } from '../../../utils/textId';
import ConfirmModal from '../../ConfirmModal';
import type { Balance } from './helpers';

type Phase =
  | 'idle'
  | 'discovering'
  | 'quoted'
  | 'signing'
  | 'publishing'
  | 'settling'
  | 'settled'
  | 'error';

type QuotedRoute = {
  unsignedBytes: Uint8Array;
  vaults: RoutingAdvertisementSummary[];
  inputAmountBytes: Uint8Array;
  inputToken: Uint8Array;
  outputToken: Uint8Array;
  primaryVaultId: Uint8Array;
  expectedOut: bigint;
};

type Props = {
  /** Available local balances; used purely as input-token suggestions
   *  for autocomplete, not as a hard restriction.  Any token id with
   *  advertised liquidity is swappable. */
  balances: Balance[];
  deviceB32: string;
  onCancel: () => void;
  onSwapComplete: () => void;
  loadWalletData: () => Promise<void>;
  setError: (err: string | null) => void;
};

const DEFAULT_SLIPPAGE_PCT = '0.5';
const MAX_SLIPPAGE_PCT = 50;

function phaseLabel(phase: Phase): string {
  switch (phase) {
    case 'discovering': return 'Discovering route…';
    case 'quoted': return 'Route ready';
    case 'signing': return 'Signing route commit…';
    case 'publishing': return 'Publishing anchor…';
    case 'settling': return 'Settling on vault…';
    case 'settled': return 'Trade settled';
    case 'error': return 'Failed';
    default: return '';
  }
}

function generateNonce(): Uint8Array {
  const out = new Uint8Array(32);
  crypto.getRandomValues(out);
  return out;
}

function bigIntFromString(s: string): bigint {
  if (!/^[0-9]+$/.test(s)) throw new Error('amount must be a non-negative integer');
  return BigInt(s);
}

function u128BigEndian(n: bigint): Uint8Array {
  if (n < 0n) throw new Error('amount must be non-negative');
  const out = new Uint8Array(16);
  let v = n;
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('amount exceeds u128');
  return out;
}

/** Apply slippage tolerance (percent) to a quoted output, returning
 *  the floor the trader is willing to accept.  Slippage is treated as
 *  basis points internally to stay in integer math. */
function applySlippageFloor(quoted: bigint, slippagePct: number): bigint {
  if (slippagePct <= 0) return quoted;
  if (slippagePct >= 100) return 0n;
  const bps = Math.round(slippagePct * 100); // 0.5% → 50 bps
  return (quoted * BigInt(10_000 - bps)) / 10_000n;
}

function SwapTabInner({
  balances,
  deviceB32,
  onCancel,
  onSwapComplete,
  loadWalletData,
  setError,
}: Props): JSX.Element {
  const [inputToken, setInputToken] = useState('');
  const [outputToken, setOutputToken] = useState('');
  const [amount, setAmount] = useState('');
  const [slippagePct, setSlippagePct] = useState(DEFAULT_SLIPPAGE_PCT);
  const [phase, setPhase] = useState<Phase>('idle');
  const [phaseDetail, setPhaseDetail] = useState<string>('');
  const [quoted, setQuoted] = useState<QuotedRoute | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  /** Datalist suggestions: union of locally-held tokens (your balances)
   *  to ease typing. Type any token id — even one you don't hold — and
   *  Quote will succeed if a vault advertises liquidity for the pair. */
  const tokenSuggestions = useMemo(() => {
    if (!Array.isArray(balances)) return [];
    return Array.from(new Set(balances.map((b) => b.tokenId).filter(Boolean)));
  }, [balances]);

  const slippageNum = useMemo(() => {
    const n = Number(slippagePct);
    if (!Number.isFinite(n)) return Number(DEFAULT_SLIPPAGE_PCT);
    return Math.min(MAX_SLIPPAGE_PCT, Math.max(0, n));
  }, [slippagePct]);

  const canQuote =
    inputToken.trim().length > 0 &&
    outputToken.trim().length > 0 &&
    inputToken.trim() !== outputToken.trim() &&
    amount.trim().length > 0;
  const busy =
    phase === 'discovering' ||
    phase === 'signing' ||
    phase === 'publishing' ||
    phase === 'settling';

  const minOut = useMemo(() => {
    if (!quoted) return 0n;
    return applySlippageFloor(quoted.expectedOut, slippageNum);
  }, [quoted, slippageNum]);

  const handleQuote = useCallback(async () => {
    setError(null);
    setQuoted(null);
    setPhaseDetail('');
    try {
      setPhase('discovering');
      const inputTokenBytes = new TextEncoder().encode(inputToken.trim());
      const outputTokenBytes = new TextEncoder().encode(outputToken.trim());
      const amountBig = bigIntFromString(amount);

      // Sync first so the path search runs against fresh vault state.
      const syncRes = await syncVaultsForPair({
        tokenA: inputTokenBytes,
        tokenB: outputTokenBytes,
      });
      if (!syncRes.success) {
        throw new Error(syncRes.error || 'syncVaultsForPair failed');
      }

      const listRes = await listAdvertisementsForPair({
        tokenA: inputTokenBytes,
        tokenB: outputTokenBytes,
      });
      if (!listRes.success) {
        throw new Error(listRes.error || 'listAdvertisementsForPair failed');
      }
      const vaults = listRes.advertisements ?? [];
      if (vaults.length === 0) {
        throw new Error(`No liquidity advertised for ${inputToken.trim()} ↔ ${outputToken.trim()}`);
      }

      const bindRes = await findAndBindBestPath({
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        inputAmount: amountBig,
        nonce: generateNonce(),
      });
      if (!bindRes.success || !bindRes.unsignedRouteCommitBytes) {
        throw new Error(bindRes.error || 'findAndBindBestPath failed');
      }

      // Compute the expected output from the canonical pair ordering
      // the Rust handler returned in the advertisement.  We compare
      // both directions because a vault advertised under (B, A) lex
      // ordering swaps reserveIn / reserveOut in our local view.
      const v = vaults[0];
      const ad_token_a = new TextDecoder().decode(v.tokenA);
      const reserveIn = ad_token_a === inputToken.trim() ? v.reserveA : v.reserveB;
      const reserveOut = ad_token_a === inputToken.trim() ? v.reserveB : v.reserveA;
      const fee = BigInt(10_000 - v.feeBps);
      const inEffective = (amountBig * fee) / 10_000n;
      const expectedOut =
        reserveIn + inEffective === 0n
          ? 0n
          : (reserveOut * inEffective) / (reserveIn + inEffective);

      const primaryVaultBytes = decodeBase32Crockford(vaults[0].vaultIdBase32);
      setQuoted({
        unsignedBytes: bindRes.unsignedRouteCommitBytes,
        vaults,
        inputAmountBytes: u128BigEndian(amountBig),
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        primaryVaultId: primaryVaultBytes,
        expectedOut,
      });
      setPhase('quoted');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'quote failed';
      setError(msg);
      setPhase('error');
      setPhaseDetail(msg);
    }
  }, [inputToken, outputToken, amount, setError]);

  const handleExecute = useCallback(async () => {
    if (!quoted) return;
    setError(null);
    setPhaseDetail('');

    // Slippage check (client-side floor).  Backend intent-bounds gate
    // is Tier 2 work; until that lands the trader's protection is the
    // chunks #7 reserves-value gate (rejects on reserve drift) plus
    // this client refusal to sign if the quote already violates the
    // slippage envelope.
    if (quoted.expectedOut < minOut) {
      const msg = `Quoted output ${quoted.expectedOut} below your slippage floor ${minOut}`;
      setError(msg);
      setPhase('error');
      setPhaseDetail(msg);
      return;
    }

    try {
      setPhase('signing');
      const signed = await signRouteCommit(quoted.unsignedBytes);
      if (!signed.success || !signed.signedRouteCommitBase32) {
        throw new Error(signed.error || 'signRouteCommit failed');
      }
      const signedBytes = decodeBase32Crockford(signed.signedRouteCommitBase32);

      const xRes = await computeExternalCommitment(signedBytes);
      if (!xRes.success || !xRes.xBase32) {
        throw new Error(xRes.error || 'computeExternalCommitment failed');
      }

      setPhase('publishing');
      const publish = await publishExternalCommitment({
        x: decodeBase32Crockford(xRes.xBase32),
      });
      if (!publish.success) {
        throw new Error(publish.error || 'publishExternalCommitment failed');
      }

      setPhase('settling');
      if (!deviceB32) {
        throw new Error('wallet device id unavailable');
      }
      const deviceBytes = decodeBase32Crockford(deviceB32);
      const unlock = await unlockVaultRouted({
        vaultId: quoted.primaryVaultId,
        deviceId: deviceBytes,
        routeCommitBytes: signedBytes,
      });
      if (!unlock.success) {
        throw new Error(unlock.error || 'unlockVaultRouted failed');
      }

      setPhase('settled');
      await loadWalletData();
      onSwapComplete();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'execute failed';
      setError(msg);
      setPhase('error');
      setPhaseDetail(msg);
    }
  }, [quoted, minOut, deviceB32, loadWalletData, onSwapComplete, setError]);

  return (
    <div>
      <datalist id="swap-token-suggestions">
        {tokenSuggestions.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>

      <div className="form-group">
        <label htmlFor="swap-from">From</label>
        <div className="amount-input-group">
          <input
            id="swap-amount"
            type="number"
            min="0"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0"
            className="form-input"
            aria-label="Input amount"
          />
          <input
            id="swap-from"
            type="text"
            value={inputToken}
            onChange={(e) => setInputToken(e.target.value)}
            placeholder="From token"
            list="swap-token-suggestions"
            autoCapitalize="characters"
            autoComplete="off"
            className="form-input"
            style={{ flex: 1, marginLeft: 8 }}
            aria-label="Input token id"
          />
        </div>
      </div>

      <div className="form-group">
        <label htmlFor="swap-to">To</label>
        <input
          id="swap-to"
          type="text"
          value={outputToken}
          onChange={(e) => setOutputToken(e.target.value)}
          placeholder="To token"
          list="swap-token-suggestions"
          autoCapitalize="characters"
          autoComplete="off"
          className="form-input"
          aria-label="Output token id"
        />
      </div>

      <div className="form-group">
        <label htmlFor="swap-slippage">
          Slippage tolerance (%)
        </label>
        <input
          id="swap-slippage"
          type="number"
          min="0"
          max={MAX_SLIPPAGE_PCT}
          step="0.1"
          value={slippagePct}
          onChange={(e) => setSlippagePct(e.target.value)}
          className="form-input"
          aria-label="Slippage tolerance percent"
        />
        <div style={{ fontSize: 10, opacity: 0.65, marginTop: 4 }}>
          Refuses to sign if the quoted output falls below your floor.
          Backend route-fallback within tolerance lands with intent-bounds (Tier 2).
        </div>
      </div>

      {quoted && (
        <div className="balance-section" style={{ marginBottom: 12 }}>
          <h4 style={{ fontSize: 12, marginBottom: 8 }}>Route</h4>
          <div className="balance-card" style={{ padding: '8px 12px' }}>
            <div className="balance-info">
              <span className="token-symbol">
                {quoted.vaults.length} vault{quoted.vaults.length === 1 ? '' : 's'} discovered
              </span>
              <span className="balance-amount">
                ~{quoted.expectedOut.toString()} {outputToken.trim()}
              </span>
            </div>
            <div style={{ fontSize: 10, opacity: 0.85, marginTop: 4 }}>
              min out @ {slippageNum}%: <strong>{minOut.toString()}</strong> {outputToken.trim()}
            </div>
            <div style={{ fontSize: 10, opacity: 0.65, marginTop: 2 }}>
              fee {quoted.vaults[0]?.feeBps} bps · vault {quoted.vaults[0]?.vaultIdBase32.slice(0, 12)}…
            </div>
          </div>
        </div>
      )}

      {phase !== 'idle' && phase !== 'quoted' && (
        <div
          className="warning-banner"
          style={{
            padding: '8px 12px',
            marginBottom: 12,
            fontSize: 11,
            border: '1px solid var(--border)',
            background: phase === 'error' ? 'rgba(255,0,0,0.08)' : 'rgba(var(--text-rgb),0.08)',
          }}
          role="status"
          aria-live="polite"
        >
          <strong>{phaseLabel(phase)}</strong>
          {phaseDetail && <div style={{ marginTop: 4, opacity: 0.85 }}>{phaseDetail}</div>}
        </div>
      )}

      <div className="form-actions">
        <button type="button" onClick={onCancel} className="cancel-button" disabled={busy}>
          Cancel
        </button>
        {!quoted && (
          <button
            type="button"
            onClick={() => void handleQuote()}
            className="send-button button-brick"
            disabled={!canQuote || busy}
          >
            {phase === 'discovering' ? 'Quoting…' : 'Quote'}
          </button>
        )}
        {quoted && (
          <button
            type="button"
            onClick={() => setShowConfirm(true)}
            className="send-button button-brick"
            disabled={busy}
          >
            {busy ? 'Settling…' : 'Swap'}
          </button>
        )}
      </div>

      <ConfirmModal
        visible={showConfirm}
        title="Confirm swap"
        message={`Swap ${amount} ${inputToken.trim()} for ~${quoted?.expectedOut.toString() ?? 0} ${outputToken.trim()} (min ${minOut.toString()} @ ${slippageNum}% slippage) via ${quoted?.vaults.length ?? 0} vault${(quoted?.vaults.length ?? 0) === 1 ? '' : 's'}?`}
        onConfirm={() => { setShowConfirm(false); void handleExecute(); }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}

const SwapTab = React.memo(SwapTabInner);
export default SwapTab;
