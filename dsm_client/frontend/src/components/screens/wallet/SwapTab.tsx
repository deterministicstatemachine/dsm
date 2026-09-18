// SPDX-License-Identifier: Apache-2.0
// Swap tab — AMM constant-product trade flow inside the wallet.
//
// Free-form symmetric token inputs: any token id pair is valid as long
// as some vault advertises liquidity for it. A route binds ONE best path
// to ONE anchored vault state producing ONE exact output under ONE
// signature — there is no slippage tolerance and no pre-signed fallback.
// The frontend NEVER re-runs the constant-product AMM math; it just
// decodes the returned RouteCommitV1, reads
// `expected_final_output_amount_u128` for display, and presents the exact
// trade for the user to confirm or cancel before triggering
// `signRouteCommit` / `publishExternalCommitment` / `unlockVaultRouted`.
//
// If the vault moves between quote and unlock, the unlock-time gate
// rejects (exact-output re-simulation) and the trader simply re-quotes
// and re-signs against fresh state.

import React, { useCallback, useMemo, useRef, useState } from 'react';
import {
  findAndBindBestPath,
  signRouteCommit,
  computeExternalCommitment,
  publishExternalCommitment,
  isExternalCommitmentVisible,
  unlockVaultRouted,
} from '../../../dsm/route_commit';
import { decodeBase32Crockford, encodeBase32Crockford } from '../../../utils/textId';
import ConfirmModal from '../../ConfirmModal';
import { InfoTip } from '../../common/InfoTip';
import { useFx } from '../../fx/FxProvider';
import { fxAmountLabel } from '../../fx/fxEngine';
import type { Balance } from './helpers';

type Phase =
  | 'idle'
  | 'discovering'
  | 'quoted'
  | 'signing'
  | 'publishing'
  | 'confirming-propagation'
  | 'settling'
  | 'settled'
  | 'error';

type QuotedRoute = {
  unsignedBytes: Uint8Array;
  inputAmountBytes: Uint8Array;
  inputToken: Uint8Array;
  outputToken: Uint8Array;
  /** The hops the Rust binder committed into the RouteCommitV1, in
   *  order — display only.  The vault(s) that settle are read from the
   *  signed route by Rust at unlock time; the frontend never picks one. */
  hops: Array<{ vaultIdBase32: string }>;
  /** Rust-computed expected final output (decoded from RouteCommitV1
   *  proto returned by `route.findAndBindBestPath`). This is the exact
   *  output the trade produces against the anchored state; the frontend
   *  NEVER recomputes it. */
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

function phaseLabel(phase: Phase): string {
  switch (phase) {
    case 'discovering': return 'Discovering route…';
    case 'quoted': return 'Route ready';
    case 'signing': return 'Signing route commit…';
    case 'publishing': return 'Publishing anchor…';
    case 'confirming-propagation': return 'Confirming storage propagation…';
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

/// A pair side, as its 32-byte policy commit.
///
/// Base32 Crockford in, 32 bytes out, or a refusal naming the field. There is
/// deliberately no ticker path: a ticker is not an identity — two distinct
/// tokens have shared one in this repo — so resolving a label here could name
/// a different asset than the trader meant while every signature downstream
/// still verified.
function decodePolicyCommit(value: string, field: string): Uint8Array {
  const bytes = decodeBase32Crockford(value.trim());
  if (bytes.length !== 32) {
    throw new Error(
      `${field} token must be a 32-byte CPTA policy anchor (Base32 Crockford); ` +
        `got ${bytes.length} bytes. Copy it from the token's detail card.`,
    );
  }
  return bytes;
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
  const fx = useFx();
  // nameFor is redefined on every render; the executor reads the latest through a ref.
  const nameForRef = useRef<(anchor: string) => string>((a) => a);
  const [phase, setPhase] = useState<Phase>('idle');
  const [phaseDetail, setPhaseDetail] = useState<string>('');
  const [quoted, setQuoted] = useState<QuotedRoute | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  /** Datalist suggestions: the CPTA anchors of tokens this wallet holds,
   *  labelled with their ticker. The VALUE is the anchor because the anchor is
   *  what the field means; the ticker is shown only so a human can tell them
   *  apart. Suggesting tickers here would have invited exactly the input the
   *  pair identity cannot accept. An anchor you do not hold can still be
   *  pasted — you do not hold what you are buying. */
  const tokenSuggestions = useMemo(() => {
    if (!Array.isArray(balances)) return [];
    const seen = new Map<string, string>();
    for (const b of balances) {
      const anchor = b.policyAnchorB32 ?? '';
      if (anchor.length > 0 && !seen.has(anchor)) seen.set(anchor, b.tokenId ?? '');
    }
    return Array.from(seen, ([anchor, ticker]) => ({ anchor, ticker }));
  }, [balances]);

  const canQuote =
    inputToken.trim().length > 0 &&
    outputToken.trim().length > 0 &&
    inputToken.trim() !== outputToken.trim() &&
    amount.trim().length > 0;
  const busy =
    phase === 'discovering' ||
    phase === 'signing' ||
    phase === 'publishing' ||
    phase === 'confirming-propagation' ||
    phase === 'settling';

  const handleQuote = useCallback(async () => {
    setError(null);
    setQuoted(null);
    setPhaseDetail('');
    try {
      setPhase('discovering');
      // The pair is named by 32-byte CPTA policy commits — the same identity
      // the vault was funded under. This used to send `TextEncoder().encode()`
      // of whatever was typed, so the trader asked for a pair named by the
      // UTF-8 bytes of a label. A vault's pair is commits, so the two could
      // never match and no advertised liquidity was ever discoverable from
      // this screen. LiquidityScreen was fixed for exactly this; this side was
      // missed, and it is the trader's half of the same pair identity.
      const inputTokenBytes = decodePolicyCommit(inputToken, 'From');
      const outputTokenBytes = decodePolicyCommit(outputToken, 'To');
      const amountBig = bigIntFromString(amount);

      // Discovery is the binder's: it searches no deeper than the beta
      // profile can settle, mirrors each hop's vault for the unlock, and
      // says NoPath itself. Nothing here
      // lists or syncs a pair on its behalf.
      const bindRes = await findAndBindBestPath({
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        inputAmount: amountBig,
        nonce: generateNonce(),
      });
      if (
        !bindRes.success ||
        !bindRes.unsignedRouteCommitBytes ||
        !bindRes.quote
      ) {
        throw new Error(bindRes.error || 'findAndBindBestPath failed');
      }

      // expectedOut and the hops come straight from the Rust-stamped
      // RouteCommitV1 proto — the exact output bound to the anchored
      // state and the vault(s) it binds. No JS AMM math and no vault
      // choice; the wallet is a thin viewer over the binder's output.
      setQuoted({
        unsignedBytes: bindRes.unsignedRouteCommitBytes,
        inputAmountBytes: u128BigEndian(amountBig),
        inputToken: inputTokenBytes,
        outputToken: outputTokenBytes,
        hops: bindRes.quote.hops.map((h) => ({
          vaultIdBase32: encodeBase32Crockford(h.vaultId),
        })),
        expectedOut: bindRes.quote.expectedFinalOutput,
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

    // No JS gate — the RouteCommit is bound to the exact anchored vault
    // state, and the unlock-time `verify_amm_swap_against_reserves` gate
    // re-simulates for an EXACT output match, rejecting if the vault
    // moved. On rejection the trader re-quotes and re-signs.

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
      const xBytes = decodeBase32Crockford(xRes.xBase32);
      const publish = await publishExternalCommitment({ x: xBytes });
      if (!publish.success) {
        throw new Error(publish.error || 'publishExternalCommitment failed');
      }

      // Confirm storage propagation before unlocking.  The PUT
      // returned success after writing to the local-region GCP node,
      // but unlock-routed will read from a rotated set of nodes; if
      // we race ahead of replication the unlock fails with an
      // `ExternalCommitmentNotVisible` rejection that's less
      // actionable than a clear "still propagating" UX.  Bounded
      // poll: 5 × ~1s.  Operational transport behaviour only — no
      // protocol semantics (see DSM clockless-rule exception for
      // network retry pacing).
      setPhase('confirming-propagation');
      let propagated = false;
      for (let i = 0; i < 5; i++) {
        const visRes = await isExternalCommitmentVisible(xBytes);
        if (visRes.success && visRes.visible) {
          propagated = true;
          break;
        }
        if (i < 4) {
          await new Promise<void>((resolve) => setTimeout(resolve, 1000));
        }
      }
      if (!propagated) {
        throw new Error(
          'External commitment did not propagate to storage within 5 attempts. Retry the swap.',
        );
      }

      setPhase('settling');
      if (!deviceB32) {
        throw new Error('wallet device id unavailable');
      }
      const deviceBytes = decodeBase32Crockford(deviceB32);
      // No vaultId: Rust settles the hop the signed route names, and
      // refuses a route deeper than the beta profile before any binding.
      // The wallet submits the route and renders the outcome.
      const unlock = await unlockVaultRouted({
        deviceId: deviceBytes,
        routeCommitBytes: signedBytes,
      });
      if (!unlock.success) {
        throw new Error(unlock.error || 'unlockVaultRouted failed');
      }

      setPhase('settled');
      const got = `${quoted.expectedOut.toString()} ${nameForRef.current(outputToken)}`;
      fx.play({ anim: 'confirm', title: 'Swapped', caption: `You received ${got}`, amount: fxAmountLabel(got, '+') });
      await loadWalletData();
      onSwapComplete();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'execute failed';
      setError(msg);
      setPhase('error');
      setPhaseDetail(msg);
      fx.play({ anim: 'fail', title: 'Swap refused', caption: msg, tone: 'bad', okLabel: 'Back' });
    }
  }, [quoted, deviceB32, outputToken, loadWalletData, onSwapComplete, setError, fx]);

  /** A held token's ticker for an anchor, or the anchor's first characters. Display only. */
  const nameFor = (anchor: string): string => {
    const hit = tokenSuggestions.find((t) => t.anchor === anchor.trim());
    if (hit && hit.ticker) return hit.ticker;
    const a = anchor.trim();
    return a.length > 12 ? `${a.slice(0, 8)}\u2026` : a || '?';
  };
  // The executor reads the current naming without taking it as a dependency.
  nameForRef.current = nameFor;

  return (
    <div className="swap-tab">
      <datalist id="swap-token-suggestions">
        {tokenSuggestions.map((t) => (
          <option key={t.anchor} value={t.anchor} label={t.ticker} />
        ))}
      </datalist>

      <div className="sb-titlebar">
        <h3 className="sb-section-title">Swap</h3>
        <InfoTip title="Swap" label="About swapping">
          <p>Trades one token for another through an AMM vault. Quote first: you see the exact amount you will get before you confirm. If the vault moves before the trade lands, it is refused and you simply quote again.</p>
          <p>Tokens are named by their <b>anchor</b>, not their ticker, because two tokens can share a ticker. Pick one you hold from the suggestions, or paste the anchor from the token&apos;s card under Tokens.</p>
        </InfoTip>
      </div>

      <div className="sb-field">
        <label htmlFor="swap-amount">You pay</label>
        <input
          id="swap-amount"
          type="number"
          min="0"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          placeholder="0"
          className="sb-input sb-input--mono"
          aria-label="Input amount"
        />
        <input
          id="swap-from"
          type="text"
          value={inputToken}
          onChange={(e) => setInputToken(e.target.value)}
          placeholder="Token anchor — pick one you hold"
          list="swap-token-suggestions"
          autoCapitalize="characters"
          autoComplete="off"
          className="sb-input sb-input--mono"
          style={{ marginTop: 6 }}
          aria-label="Input token id"
        />
      </div>

      <div className="sb-field">
        <label htmlFor="swap-to">You get</label>
        <input
          id="swap-to"
          type="text"
          value={outputToken}
          onChange={(e) => setOutputToken(e.target.value)}
          placeholder="Token anchor"
          list="swap-token-suggestions"
          autoCapitalize="characters"
          autoComplete="off"
          className="sb-input sb-input--mono"
          aria-label="Output token id"
        />
      </div>

      {quoted && (
        <div className="sb-card sb-card--hero">
          <div className="sb-hero__label">You get exactly</div>
          <div className="sb-hero__value" style={{ fontSize: 15 }}>
            {quoted.expectedOut.toString()} {outputToken.trim()}
          </div>
          <div className="sb-hero__sub">
            {nameFor(inputToken)} {'\u2192'} {nameFor(outputToken)} {'\u00B7'} exact output {'\u2014'} bound to current vault state
          </div>
          <div className="sb-hero__row">
            <span>{quoted.hops.length} hop{quoted.hops.length === 1 ? '' : 's'} bound</span>
            <b className="sb-mono" style={{ fontSize: 9 }}>
              {quoted.hops.map((h) => `${h.vaultIdBase32.slice(0, 10)}\u2026`).join(' \u2192 ')}
            </b>
          </div>
        </div>
      )}

      {phase !== 'idle' && phase !== 'quoted' && (
        <div
          className={`sb-notice${phase === 'error' ? ' sb-notice--error' : ''}`}
          role="status"
          aria-live="polite"
        >
          <span>
            <strong>{phaseLabel(phase)}</strong>
            {phaseDetail && <div style={{ marginTop: 4, opacity: 0.85 }}>{phaseDetail}</div>}
          </span>
        </div>
      )}

      <div className="sb-actions">
        <button type="button" onClick={onCancel} className="sb-btn" disabled={busy}>
          Cancel
        </button>
        {!quoted && (
          <button
            type="button"
            onClick={() => void handleQuote()}
            className="sb-btn sb-btn--primary"
            disabled={!canQuote || busy}
          >
            {phase === 'discovering' ? 'Quoting\u2026' : 'Quote'}
          </button>
        )}
        {quoted && (
          <button
            type="button"
            onClick={() => setShowConfirm(true)}
            className="sb-btn sb-btn--primary"
            disabled={busy}
          >
            {busy ? 'Settling\u2026' : 'Swap'}
          </button>
        )}
      </div>

      <ConfirmModal
        visible={showConfirm}
        title="Confirm swap"
        message={`Swap ${amount} ${nameFor(inputToken)} for exactly ${quoted?.expectedOut.toString() ?? 0} ${nameFor(outputToken)} via ${quoted?.hops.length ?? 0} hop${(quoted?.hops.length ?? 0) === 1 ? '' : 's'}?`}
        onConfirm={() => { setShowConfirm(false); void handleExecute(); }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}

const SwapTab = React.memo(SwapTabInner);
export default SwapTab;
