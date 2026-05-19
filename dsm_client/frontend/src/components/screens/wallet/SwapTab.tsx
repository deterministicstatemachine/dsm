// SPDX-License-Identifier: Apache-2.0
// Swap tab — AMM constant-product trade flow inside the wallet.
//
// Free-form symmetric token inputs: any token id pair is valid as long
// as some vault advertises liquidity for it.  Slippage tolerance is
// captured as a bps value in the UI and handed verbatim to the Rust
// `findAndBindBestPath` route, which stamps both the per-hop
// `min_output_amount_u128` floor and the envelope-level
// `floor_final_output_amount_u128`. The frontend NEVER re-runs the
// constant-product AMM math, never computes a slippage floor in JS,
// and never gates on it — those are all `route_commit_sdk`'s job.
// The wallet just decodes the returned RouteCommitV1, reads
// `expected_final_output_amount_u128` and `floor_final_output_amount_u128`
// for display, and presents the trade for the user to confirm or
// cancel before triggering `signRouteCommit` / `publishExternalCommitment`
// / `unlockVaultRouted`.
//
// Tier 2 backend route-fallback within the envelope (alternate paths
// when primary state moves between quote and unlock) is wired through
// the Rust SDK: when `maxPaths > 1` the binder enumerates N-best
// candidates and stamps the runner-ups into `RouteCommitV1.fallbacks`
// under the same signed X commitment so the wallet can retry without
// re-signing.

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
  /** Rust-computed expected final output (decoded from RouteCommitV1
   *  proto returned by `route.findAndBindBestPath`). The frontend
   *  NEVER recomputes this. */
  expectedOut: bigint;
  /** Rust-stamped envelope-level slippage floor (decoded from
   *  RouteCommitV1.floor_final_output_amount_u128). */
  floorOut: bigint;
  /** Count of fallback hop groups in the envelope (0 = primary-only). */
  fallbackGroupCount: number;
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

/** Convert the user's percent-tolerance slider value to basis points
 *  for the Rust binder. Pure unit conversion, no AMM math. */
function slippagePctToBps(slippagePct: number): number {
  if (slippagePct <= 0) return 0;
  if (slippagePct >= 100) return 10_000;
  return Math.round(slippagePct * 100); // 0.5% → 50 bps
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

  // Rust-stamped floor decoded from the RouteCommitV1 envelope on
  // quote. The frontend NEVER recomputes this — it just surfaces what
  // the binder produced so the trader can confirm or cancel.
  const minOut = useMemo(() => quoted?.floorOut ?? 0n, [quoted]);

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

      const slippageBps = slippagePctToBps(slippageNum);
      const bindRes = await findAndBindBestPath({
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        inputAmount: amountBig,
        nonce: generateNonce(),
        // Tier 2: ask Rust for an envelope-bound RouteCommit. The
        // binder stamps the per-hop and envelope floors from these
        // bps values and (if maxPaths > 1) attaches N-best fallback
        // groups under one signature. Set maxPaths=3 to opt in to
        // fallback semantics; primary still resolves first.
        maxPaths: 3,
        slippageBps,
        floorBps: slippageBps,
      });
      if (
        !bindRes.success ||
        !bindRes.unsignedRouteCommitBytes ||
        !bindRes.quote
      ) {
        throw new Error(bindRes.error || 'findAndBindBestPath failed');
      }

      // expectedOut + floorOut come straight from the Rust-stamped
      // RouteCommitV1 proto. No JS AMM math, no JS slippage math —
      // the wallet is a thin viewer over the binder's output.
      const primaryVaultBytes = decodeBase32Crockford(vaults[0].vaultIdBase32);
      setQuoted({
        unsignedBytes: bindRes.unsignedRouteCommitBytes,
        vaults,
        inputAmountBytes: u128BigEndian(amountBig),
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        primaryVaultId: primaryVaultBytes,
        expectedOut: bindRes.quote.expectedFinalOutput,
        floorOut: bindRes.quote.floorFinalOutput,
        fallbackGroupCount: bindRes.quote.fallbackGroupCount,
      });
      setPhase('quoted');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'quote failed';
      setError(msg);
      setPhase('error');
      setPhaseDetail(msg);
    }
  }, [inputToken, outputToken, amount, slippageNum, setError]);

  const handleExecute = useCallback(async () => {
    if (!quoted) return;
    setError(null);
    setPhaseDetail('');

    // No pre-sign slippage gate in JS — the Rust binder stamped the
    // floors into RouteCommitV1 and the unlock-time
    // `verify_amm_swap_against_reserves` gate enforces them. If the
    // returned quote already failed to clear the floor the binder
    // would have returned an error; we wouldn't have a `quoted` here.

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
  }, [quoted, deviceB32, loadWalletData, onSwapComplete, setError]);

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
            {quoted.fallbackGroupCount > 0 && (
              <div style={{ fontSize: 10, opacity: 0.75, marginTop: 2 }}>
                +{quoted.fallbackGroupCount} fallback route{quoted.fallbackGroupCount === 1 ? '' : 's'} in envelope
              </div>
            )}
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
