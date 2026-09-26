// SPDX-License-Identifier: MIT OR Apache-2.0

import React, { useCallback, useEffect, useRef, useState } from 'react';
import './TokenCreationDialog.css';
import { TokenCoin } from './TokenCoin';
import { encodeCoinSource, silhouetteFromRgba } from '../utils/coinArtwork';
import { readImageRgba } from '../utils/imageRgba';
import { createToken } from '@/dsm/policies';
import { getTokenCreationFeeEra } from '@/dsm/policies';

/** The creation fee as Rust reported it, the failure of asking, or not asked yet. */
type CreationFee = { era: bigint } | { error: string } | undefined;

// ── Types ────────────────────────────────────────────────────────────────────
// Fungible is the only token kind the protocol enforces. NFT/SBT would need
// a per-item ownership primitive that does not exist, and the Rust policy
// parser rejects their discriminant outright — so they are not offered.
type TokenKind = 'FUNGIBLE';
type AllowlistKind = 'NONE' | 'INLINE';

interface WizardState {
  kind: TokenKind;
  ticker: string;
  alias: string;
  description: string;
  iconUrl: string;
  /** Cut out the image's background instead of its logo. */
  artworkInvert: boolean;
  decimals: number;
  /** The whole supply, in base units; fixed at creation and released to the creator. */
  genesisSupply: string;
  /** Whether holders may burn their own units. */
  burnEnabled: boolean;
  allowlistKind: AllowlistKind;
  allowlistData: string;
}

const DEFAULT: WizardState = {
  kind: 'FUNGIBLE',
  ticker: '',
  alias: '',
  description: '',
  iconUrl: '',
  artworkInvert: false,
  decimals: 2,
  genesisSupply: '1000000',
  burnEnabled: false,
  allowlistKind: 'NONE',
  allowlistData: '',
};

// ── Validation ───────────────────────────────────────────────────────────────
function validateStep1(s: WizardState): string | null {
  const t = s.ticker.trim().toUpperCase();
  if (!t || t.length < 2 || t.length > 8) return 'Ticker must be 2–8 letters';
  if (!/^[A-Z0-9]+$/.test(t)) return 'Ticker: letters and digits only';
  if (!s.alias.trim()) return 'Display name is required';
  return null;
}

function validateStep2(s: WizardState): string | null {
  const raw = s.genesisSupply.trim();
  if (!/^[0-9]+$/.test(raw) || /^0+$/.test(raw)) return 'Total supply must be a positive integer';
  return null;
}

// ── Sub-component: ProgressBar ───────────────────────────────────────────────
const STEP_LABELS = ['Identity', 'Supply & Rules', 'Access & Review'];

function ProgressBar({ step }: { step: number }) {
  return (
    <>
      <div className="tcd-progress">
        {STEP_LABELS.map((_, i) => (
          <div
            key={i}
            className={`tcd-progress-seg${i + 1 < step ? ' tcd-progress-seg--done' : i + 1 === step ? ' tcd-progress-seg--active' : ''}`}
          />
        ))}
      </div>
      <div className="tcd-progress-label">{STEP_LABELS[step - 1]} — Step {step} of 3</div>
    </>
  );
}

// ── Sub-component: Toggle ────────────────────────────────────────────────────
function Toggle({ checked, onChange, id }: { checked: boolean; onChange: (v: boolean) => void; id: string }) {
  return (
    <label className="tcd-toggle-switch" htmlFor={id}>
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
      />
      <span className="tcd-toggle-track" />
      <span className="tcd-toggle-thumb" />
    </label>
  );
}

// ── Sub-component: Step 1 — Token Identity ───────────────────────────────────
const KIND_META: { kind: TokenKind; icon: string; name: string; desc: string }[] = [
  { kind: 'FUNGIBLE', icon: 'F', name: 'FUNGIBLE', desc: 'Interchangeable units' },
];

// ── Sub-component: coin artwork ─────────────────────────────────────────────
const PREVIEW_COIN_SIZE = 160;

function useSettled<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const handle = setTimeout(() => setSettled(value), delayMs);
    return () => clearTimeout(handle);
  }, [value, delayMs]);
  return settled;
}

function CoinArtworkField({ state, set }: { state: WizardState; set: (p: Partial<WizardState>) => void }) {
  const [image, setImage] = useState<{ rgba: Uint8ClampedArray; width: number; height: number } | null>(null);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reads = useRef(0);
  const ticker = useSettled(state.ticker || 'TOKEN', 400);

  const cutOut = (source: { rgba: Uint8ClampedArray; width: number; height: number }, invert: boolean) => {
    try {
      set({ iconUrl: encodeCoinSource(silhouetteFromRgba(source.rgba, source.width, source.height, { invert })), artworkInvert: invert });
      setError(null);
    } catch (e) {
      set({ iconUrl: '', artworkInvert: invert });
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const upload = async (file: File) => {
    const read = ++reads.current;
    setReading(true);
    setError(null);
    try {
      const source = await readImageRgba(file);
      if (read !== reads.current) return;
      setImage(source);
      cutOut(source, state.artworkInvert);
    } catch (e) {
      if (read !== reads.current) return;
      setImage(null);
      set({ iconUrl: '' });
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (read === reads.current) setReading(false);
    }
  };

  return (
    <div className="tcd-field">
      <label className="tcd-label" htmlFor="tcd-coin-art">
        Coin artwork <span className="tcd-optional">(optional)</span>
      </label>
      <div className="tcd-coin-preview">
        <TokenCoin iconUrl={state.iconUrl} ticker={ticker} size={PREVIEW_COIN_SIZE} className="tcd-coin-img" alt="Your token's coin" />
      </div>
      <input
        id="tcd-coin-art"
        type="file"
        accept="image/png,image/jpeg,image/webp"
        disabled={reading}
        onChange={e => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file) void upload(file);
        }}
      />
      {state.iconUrl && (
        <div className="tcd-coin-actions">
          {image && (
            <label className="tcd-label">
              <input type="checkbox" checked={state.artworkInvert} onChange={e => cutOut(image, e.target.checked)} />{' '}
              Cut out the background instead
            </label>
          )}
          <button
            type="button"
            className="tcd-btn tcd-btn--sec"
            onClick={() => {
              reads.current++;
              setImage(null);
              setReading(false);
              setError(null);
              set({ iconUrl: '', artworkInvert: false });
            }}
          >
            Use the ticker instead
          </button>
        </div>
      )}
      <span className="tcd-hint">
        Your logo is cut through the coin the way ERA&apos;s lettering is, in every screen colour. Without an image the
        ticker is used. The artwork is part of the policy and cannot be changed after creation.
      </span>
      {reading && <span className="tcd-hint" role="status">Reading image…</span>}
      {error && <span className="tcd-hint" role="alert">{error}</span>}
    </div>
  );
}

function Step1({ state, set }: { state: WizardState; set: (p: Partial<WizardState>) => void }) {
  return (
    <div>
      <div className="tcd-hint" style={{ marginBottom: 12, padding: '8px 10px', border: '1px solid var(--border)', borderRadius: 6, background: 'rgba(var(--text-dark-rgb),0.08)', lineHeight: 1.5 }}>
        Tokens require a <strong>CPTA policy</strong>. This wizard defines the policy parameters,
        publishes it on-chain, then creates a token bound to that policy anchor.
        Policy settings are immutable after creation.
      </div>
      <div className="tcd-section-title">Token Type</div>
      <div className="tcd-kind-grid">
        {KIND_META.map(m => (
          <button
            key={m.kind}
            type="button"
            className={`tcd-kind-btn${state.kind === m.kind ? ' tcd-kind-btn--active' : ''}`}
            aria-pressed={state.kind === m.kind}
            onClick={() => {
              const patch: Partial<WizardState> = { kind: m.kind };
              if (m.kind !== 'FUNGIBLE') patch.decimals = 0;
              set(patch);
            }}
          >
            <span className="tcd-kind-icon">{m.icon}</span>
            <span className="tcd-kind-name">{m.name}</span>
            <span className="tcd-kind-desc">{m.desc}</span>
          </button>
        ))}
      </div>

      <div className="tcd-section-title">Identity</div>

      <div className="tcd-field">
        <label className="tcd-label" htmlFor="tcd-ticker">Ticker</label>
        <input
          id="tcd-ticker"
          className="tcd-input"
          placeholder="e.g. GOLD"
          maxLength={8}
          value={state.ticker}
          onChange={e => set({ ticker: e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '') })}
        />
        <span className="tcd-hint">2–8 uppercase letters / digits. Cannot be changed after creation.</span>
      </div>

      <div className="tcd-field">
        <label className="tcd-label" htmlFor="tcd-alias">Display Name</label>
        <input
          id="tcd-alias"
          className="tcd-input"
          placeholder="e.g. Gold Coin"
          value={state.alias}
          onChange={e => set({ alias: e.target.value })}
        />
      </div>

      <div className="tcd-section-title">Optional Details</div>

      <div className="tcd-field">
        <label className="tcd-label" htmlFor="tcd-desc">
          Description <span className="tcd-optional">(optional)</span>
        </label>
        <textarea
          id="tcd-desc"
          className="tcd-textarea"
          placeholder="What is this token for?"
          maxLength={200}
          rows={3}
          value={state.description}
          onChange={e => set({ description: e.target.value })}
        />
        <span className="tcd-char-count">{state.description.length} / 200</span>
      </div>

      <CoinArtworkField state={state} set={set} />
    </div>
  );
}

// ── Sub-component: Step 2 — Supply & Rules ───────────────────────────────────
function Step2({
  state, set, effectiveDecimals,
}: {
  state: WizardState;
  set: (p: Partial<WizardState>) => void;
  effectiveDecimals: number;
}) {
  return (
    <div>
      <div className="tcd-section-title">Precision</div>

      <div className="tcd-field">
        <label className="tcd-label">Decimals</label>
        <div className="tcd-slider-row">
          <input
            type="range"
            className="tcd-slider"
            min={0}
            max={18}
            value={effectiveDecimals}
            onChange={e => set({ decimals: Number(e.target.value) })}
          />
          <span className="tcd-slider-val">{effectiveDecimals}</span>
        </div>
      </div>

      <div className="tcd-section-title">Supply</div>

      <div className="tcd-field">
        <label className="tcd-label" htmlFor="tcd-supply">Total Supply</label>
        <input
          id="tcd-supply"
          className="tcd-input"
          placeholder="1000000"
          value={state.genesisSupply}
          onChange={e => set({ genesisSupply: e.target.value.replace(/[^0-9]/g, '') })}
        />
        <span className="tcd-hint">The whole supply, fixed at creation. All of it is released to your wallet; no more can ever be issued.</span>
      </div>

      <div className="tcd-section-title">Permissions</div>

      <div className="tcd-toggle-row">
        <div className="tcd-toggle-info">
          <span className="tcd-toggle-name">Burn</span>
          <span className="tcd-toggle-sub">Allow holders to destroy their own units</span>
        </div>
        <Toggle id="tcd-burn" checked={state.burnEnabled} onChange={v => set({ burnEnabled: v })} />
      </div>

    </div>
  );
}

// ── Sub-component: Step 3 — Access + Review ──────────────────────────────────
function Step3({
  state, set, effectiveDecimals, effectiveTransferable, creationFee,
}: {
  state: WizardState;
  set: (p: Partial<WizardState>) => void;
  effectiveDecimals: number;
  effectiveTransferable: boolean;
  /** The fee from Rust; `undefined` until the query returns. */
  creationFee: CreationFee;
}) {
  const supplyLine = state.genesisSupply ? BigInt(state.genesisSupply).toLocaleString() : '—';

  return (
    <div>
      <div className="tcd-section-title">Allowlist</div>
      <div className="tcd-radio-group">
        <label className="tcd-radio-label">
          <input
            type="radio"
            name="tcd-al"
            value="NONE"
            checked={state.allowlistKind === 'NONE'}
            onChange={() => set({ allowlistKind: 'NONE', allowlistData: '' })}
          />
          Open — anyone can hold this token
        </label>
        <label className="tcd-radio-label">
          <input
            type="radio"
            name="tcd-al"
            value="INLINE"
            checked={state.allowlistKind === 'INLINE'}
            onChange={() => set({ allowlistKind: 'INLINE' })}
          />
          Restricted — only allowlisted genesis IDs
        </label>
        <span className="tcd-radio-sub">Allowlisted wallets are committed into the policy at creation time.</span>
      </div>

      <div className={`tcd-al-expand${state.allowlistKind === 'INLINE' ? ' tcd-al-expand--open' : ''}`}>
        <div className="tcd-field">
          <label className="tcd-label" htmlFor="tcd-al-data">
            Genesis IDs <span className="tcd-optional">(one per line)</span>
          </label>
          <textarea
            id="tcd-al-data"
            className="tcd-textarea"
            placeholder={'GENESIS1ABC...\nGENESIS2DEF...'}
            rows={4}
            value={state.allowlistData}
            onChange={e => set({ allowlistData: e.target.value })}
          />
        </div>
      </div>

      <div className="tcd-section-title">Review</div>
      <div className="tcd-review-card">
        <div className="tcd-review-row">
          <span className="tcd-review-key">Kind</span>
          <span className="tcd-review-val">
            <span className={`tcd-badge tcd-badge--${state.kind}`}>{state.kind}</span>
          </span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Ticker</span>
          <span className="tcd-review-val">{state.ticker.toUpperCase()}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Name</span>
          <span className="tcd-review-val">{state.alias}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Decimals</span>
          <span className="tcd-review-val">{effectiveDecimals}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Total Supply</span>
          <span className="tcd-review-val">{supplyLine}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Burn</span>
          <span className="tcd-review-val">{state.burnEnabled ? 'Enabled' : 'Disabled'}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Transferable</span>
          <span className="tcd-review-val">{effectiveTransferable ? 'Yes' : 'No'}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Allowlist</span>
          <span className="tcd-review-val">
            {state.allowlistKind === 'NONE'
              ? 'Open'
              : `Restricted (${state.allowlistData.trim().split('\n').filter(Boolean).length} entries)`}
          </span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Creation fee</span>
          <span className="tcd-review-val">
            {creationFee === undefined
              ? '…'
              : 'era' in creationFee
                ? `${creationFee.era} ERA (burned)`
                : `not available: ${creationFee.error}`}
          </span>
        </div>
        {state.description.trim() && (
          <div className="tcd-review-row">
            <span className="tcd-review-key">Desc</span>
            <span className="tcd-review-val" style={{ fontSize: 10 }}>{state.description.trim()}</span>
          </div>
        )}
        <div className="tcd-review-row">
          <span className="tcd-review-key">Coin</span>
          <span className="tcd-review-val">
            <TokenCoin iconUrl={state.iconUrl} ticker={state.ticker} size={PREVIEW_COIN_SIZE} className="tcd-coin-img tcd-coin-img--review" />
          </span>
        </div>
      </div>
      <div className="tcd-hint" style={{ marginTop: 8, padding: '6px 8px', border: '1px solid var(--border)', borderRadius: 6, background: 'rgba(var(--text-dark-rgb),0.06)', lineHeight: 1.5 }}>
        A CPTA policy will be published first (content-addressed, immutable).
        The token is then created bound to that policy anchor.
        These settings cannot be changed afterwards.
      </div>
    </div>
  );
}

// ── Sub-component: Success screen ────────────────────────────────────────────
function SuccessScreen({
  created, state, onClose,
}: {
  created: { tokenId?: string; anchorBase32?: string };
  state: WizardState;
  onClose: () => void;
}) {
  return (
    <div className="tcd-card">
      <div className="tcd-success">
        <TokenCoin iconUrl={state.iconUrl} ticker={state.ticker} size={PREVIEW_COIN_SIZE} className="tcd-coin-img" />
        <div className="tcd-success-icon">OK</div>
        <div className="tcd-success-title">Policy Published &amp; Token Created</div>
        <div className="tcd-success-detail">
          <strong>Kind</strong>
          <span className={`tcd-badge tcd-badge--${state.kind}`}>{state.kind}</span>
          <strong>Ticker</strong>
          {state.ticker.toUpperCase()}
          <strong>Name</strong>
          {state.alias}
          {created.tokenId && (
            <>
              <strong>Token ID</strong>
              {created.tokenId}
            </>
          )}
          {created.anchorBase32 && (
            <>
              <strong>Policy Anchor (CPTA)</strong>
              {created.anchorBase32}
            </>
          )}
        </div>
        <button className="tcd-btn tcd-btn--pri" style={{ width: '100%' }} onClick={onClose}>
          Done
        </button>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export const TokenCreationDialog: React.FC<{ onClose: () => void; onSuccess?: () => void }> = ({
  onClose, onSuccess,
}) => {
  const [step, setStep]       = useState(1);
  const [dir,  setDir]        = useState<'fwd' | 'bck'>('fwd');
  const [animKey, setAnimKey] = useState(0);
  const [state, _setState]    = useState<WizardState>(DEFAULT);
  const [creating, setCreating] = useState(false);
  /// Set while an ambiguous outcome is being settled against canonical state,
  /// so the button says what is happening rather than implying a fresh attempt.
  const [resolving, setResolving] = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [created,  setCreated]  = useState<{ tokenId?: string; anchorBase32?: string } | null>(null);
  // Authoritative creation fee, fetched from Rust. Never hardcoded here — the
  // conservation guard validates the charged fee against a core constant, and a
  // number invented in the UI could silently disagree with what is burned.
  const [creationFee, setCreationFee] = useState<CreationFee>(undefined);
  const stateRef = useRef(state);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const era = await getTokenCreationFeeEra();
        if (!cancelled) setCreationFee({ era });
      } catch (e) {
        if (!cancelled) setCreationFee({ error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const set = useCallback((patch: Partial<WizardState>) => {
    _setState(prev => {
      const next = { ...prev, ...patch };
      stateRef.current = next;
      return next;
    });
  }, []);

  // Derived helpers. Only fungible tokens exist, so decimals are whatever the
  // user chose and the token is transferable.
  const effectiveDecimals     = state.decimals;
  const effectiveTransferable = true;

  const navigate = useCallback((to: number) => {
    setDir(to > step ? 'fwd' : 'bck');
    setAnimKey(k => k + 1);
    setStep(to);
    setError(null);
  }, [step]);

  const handleNext = useCallback(() => {
    if (step === 1) {
      const e = validateStep1(stateRef.current);
      if (e) { setError(e); return; }
    }
    if (step === 2) {
      const e = validateStep2(stateRef.current);
      if (e) { setError(e); return; }
    }
    navigate(step + 1);
  }, [step, navigate]);

  const handleCreate = useCallback(async () => {
    setError(null);
    setCreating(true);
    try {
      const s = stateRef.current;
      const res = await createToken({
        ticker:             s.ticker.trim().toUpperCase(),
        alias:              s.alias.trim(),
        decimals:           effectiveDecimals,
        genesisSupply:      s.genesisSupply,
        burnEnabled:        s.burnEnabled,
        // The policy's signer set is this device alone (Rust fills it in),
        // so 1-of-1 is the only threshold it can satisfy.
        threshold:          1,
        description:        s.description.trim() || undefined,
        iconUrl:            s.iconUrl.trim()      || undefined,
        transferable:       effectiveTransferable,
        allowlistKind:      s.allowlistKind,
        allowlistData:      s.allowlistKind === 'INLINE' ? s.allowlistData : undefined,
      });
      const ok = typeof res === 'boolean'
        ? res
        : (typeof res === 'object' && res !== null && 'success' in res)
          ? Boolean((res as { success?: boolean }).success)
          : false;
      if (ok) {
        // `createToken` returns a FLAT result. The old code reached for a
        // `.result` wrapper that only the (now deleted, unreachable) DsmClient
        // method produced, so `created` was always {} and the success screen
        // rendered neither the token id nor the anchor.
        const r = (typeof res === 'object' && res !== null)
          ? (res as { tokenId?: string; anchorBase32?: string })
          : {};
        setCreated({ tokenId: r.tokenId, anchorBase32: r.anchorBase32 });
        if (onSuccess) onSuccess();
      } else {
        const msg = (typeof res === 'object' && res !== null && 'error' in res)
          ? String((res as { error?: unknown }).error)
          : 'Token creation failed';
        setError(msg);
        setCreating(false);
      }
    } catch (e) {
      // An error HERE means the call did not come back — a timeout, a dropped
      // bridge, a malformed reply. It does NOT mean the creation failed. On
      // device the transition committed (fee burned, supply credited) while
      // this path ran, and reporting failure sent the user to retry an
      // operation that had already succeeded.
      //
      // So ask once more instead of guessing. `token.create` is keyed by the
      // creation commitment — token_id is derived from the policy anchor and
      // ticker — so resubmitting the identical request is answered from
      // canonical state: success if this exact creation already exists (no
      // second advance, no second fee), a conflict if the ticker is held by a
      // different creation, a retryable error if nothing was committed. The
      // verdict is Rust's; this only renders it.
      setResolving(true);
      try {
        const s = stateRef.current;
        const again = await createToken({
          ticker:             s.ticker.trim().toUpperCase(),
          alias:              s.alias.trim(),
          decimals:           effectiveDecimals,
          genesisSupply:      s.genesisSupply,
          burnEnabled:        s.burnEnabled,
          // The policy's signer set is this device alone (Rust fills it in),
          // so 1-of-1 is the only threshold it can satisfy.
          threshold:          1,
          description:        s.description.trim() || undefined,
          iconUrl:            s.iconUrl.trim()      || undefined,
          transferable:       effectiveTransferable,
          allowlistKind:      s.allowlistKind,
          allowlistData:      s.allowlistKind === 'INLINE' ? s.allowlistData : undefined,
        });
        const r = (typeof again === 'object' && again !== null)
          ? (again as { success?: boolean; tokenId?: string; anchorBase32?: string; error?: unknown })
          : {};
        if (r.success) {
          setCreated({ tokenId: r.tokenId, anchorBase32: r.anchorBase32 });
          if (onSuccess) onSuccess();
        } else {
          setError(r.error ? String(r.error) : String(e));
          setCreating(false);
        }
      } catch (e2) {
        // Still no answer. Say so honestly — this is unresolved, not failed,
        // and the token may exist.
        setError(
          `Could not confirm the outcome (${String(e2)}). If the token was created it will ` +
          `appear in your token list; creating it again will not charge a second fee.`,
        );
        setCreating(false);
      } finally {
        setResolving(false);
      }
    }
  }, [effectiveDecimals, effectiveTransferable, onSuccess]);

  // ── Success screen ───────────────────────────────────────────────────────
  if (created) {
    return (
      <div className="tcd-overlay">
        <SuccessScreen created={created} state={state} onClose={onClose} />
      </div>
    );
  }

  // ── Wizard shell ─────────────────────────────────────────────────────────
  return (
    <div className="tcd-overlay">
      <div className="tcd-card">
        {/* Header */}
        <div className="tcd-header">
          <span className="tcd-header-title">Create Token Policy (CPTA)</span>
          <button className="tcd-close" onClick={onClose} aria-label="Close">X</button>
        </div>

        <ProgressBar step={step} />

        {/* Step body */}
        <div
          key={animKey}
          className={`tcd-step-body tcd-step-body--${dir}`}
        >
          {step === 1 && <Step1 state={state} set={set} />}
          {step === 2 && (
            <Step2
              state={state}
              set={set}
              effectiveDecimals={effectiveDecimals}
            />
          )}
          {step === 3 && (
            <Step3
              state={state}
              set={set}
              effectiveDecimals={effectiveDecimals}
              effectiveTransferable={effectiveTransferable}
              creationFee={creationFee}
            />
          )}
        </div>

        {/* Error bar */}
        {error && <div className="tcd-error-bar">{error}</div>}

        {/* Nav */}
        <div className="tcd-nav">
          {step > 1 ? (
            <button className="tcd-btn tcd-btn--sec" onClick={() => navigate(step - 1)}>
              ← Back
            </button>
          ) : (
            <button className="tcd-btn tcd-btn--sec" onClick={onClose}>
              Cancel
            </button>
          )}
          {step < 3 ? (
            <button className="tcd-btn tcd-btn--pri" onClick={handleNext}>
              Continue →
            </button>
          ) : (
            <button
              className="tcd-btn tcd-btn--create"
              onClick={handleCreate}
              disabled={creating}
            >
              {resolving ? 'Confirming outcome\u2026' : creating ? 'Publishing policy\u2026' : 'Publish'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
