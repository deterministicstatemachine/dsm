// SPDX-License-Identifier: MIT OR Apache-2.0
// The token-creation wizard, as a StateBoy popover: identity, supply and
// rules, access and review; then the policy is published and the token
// created bound to its anchor. Rust reports the fee and the outcome.

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { TokenCoin } from './TokenCoin';
import { encodeCoinSource, silhouetteFromRgba } from '../utils/coinArtwork';
import { readImageRgba } from '../utils/imageRgba';
import { checkToken, createToken, getTokenCreationFee, type TokenCreateDetails, type TokenCreationFee } from '@/dsm/policies';
import { useBackButton } from '../hooks/useBackButton';

/** The creation fee and this device's standing as Rust reported them, the failure of asking, or not asked yet. */
type CreationFee = TokenCreationFee | { error: string } | undefined;

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

// ── Checking ─────────────────────────────────────────────────────────────────
// Rust checks every field (token.check, as token.create checks them). A step
// moves on once Rust refuses none of the fields it asks for, named as the
// request names them.
const STEP_FIELDS: Record<number, readonly string[]> = {
  1: ['ticker', 'alias'],
  2: ['decimals', 'genesis_supply_entered'],
};

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ── Sub-component: the step strip ────────────────────────────────────────────
const STEP_LABELS = ['Identity', 'Supply', 'Review'];

function StepStrip({ step }: { step: number }) {
  return (
    <div className="sb-steps" aria-label={`Step ${step} of ${STEP_LABELS.length}`}>
      {STEP_LABELS.map((label, i) => {
        const done = i + 1 < step;
        const active = i + 1 === step;
        return (
          <div
            key={label}
            className={`sb-steps__step${done ? ' is-done' : ''}${active ? ' is-active' : ''}`}
            aria-current={active ? 'step' : undefined}
          >
            <span className="sb-steps__mark" aria-hidden="true">{done ? '✓' : i + 1}</span>
            {label}
          </div>
        );
      })}
    </div>
  );
}

// ── Sub-component: a two-way choice ─────────────────────────────────────────
function Seg<T extends string>({
  label, value, options, onChange,
}: {
  label: string;
  value: T;
  options: ReadonlyArray<{ id: T; label: string }>;
  onChange: (v: T) => void;
}) {
  return (
    <div className="sb-seg sb-seg--block" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          className={`sb-seg__opt${o.id === value ? ' active' : ''}`}
          aria-pressed={o.id === value}
          onClick={() => onChange(o.id)}
        >
          {o.label}
        </button>
      ))}
    </div>
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
    <div className="sb-field">
      <label htmlFor="tcd-coin-art">Coin artwork (optional)</label>
      <div style={{ display: 'flex', justifyContent: 'center', margin: '4px 0 8px' }}>
        <span className="sb-coin-tile">
          <TokenCoin iconUrl={state.iconUrl} ticker={ticker} size={PREVIEW_COIN_SIZE} className="sb-coin sb-coin--xl" alt="Your token's coin" />
        </span>
      </div>
      {/* The native file control cannot be drawn in the frame's look, so it is
          kept off screen and the brick beside it is its label: tapping the
          brick opens the same picker. */}
      <input
        id="tcd-coin-art"
        type="file"
        className="sb-file"
        accept="image/png,image/jpeg,image/webp"
        disabled={reading}
        onChange={e => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file) void upload(file);
        }}
      />
      <label htmlFor="tcd-coin-art" className={`sb-btn sb-btn--block${reading ? ' is-disabled' : ''}`} aria-hidden="true">
        {reading ? 'Reading image…' : state.iconUrl ? 'Choose another image' : 'Choose an image'}
      </label>
      {state.iconUrl && (
        <div style={{ display: 'grid', gap: 6, marginTop: 6 }}>
          {image && (
            <label className="sb-hint sb-hint--tight" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <input type="checkbox" checked={state.artworkInvert} onChange={e => cutOut(image, e.target.checked)} />
              Cut out the background instead
            </label>
          )}
          <button
            type="button"
            className="sb-btn sb-btn--small sb-btn--block"
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
      <p className="sb-hint sb-hint--tight">
        Your logo is cut through the coin the way ERA&apos;s lettering is, in every screen colour. Without an image the
        ticker is used. The artwork is part of the policy and cannot be changed after creation.
      </p>
      {reading && <p className="sb-hint sb-hint--tight" role="status">Reading image…</p>}
      {error && <p className="sb-hint sb-hint--tight" role="alert">{error}</p>}
    </div>
  );
}

function Step1({ state, set }: { state: WizardState; set: (p: Partial<WizardState>) => void }) {
  return (
    <div>
      <p className="sb-hint">
        Tokens require a <b>CPTA policy</b>. This wizard defines the policy, publishes it, then creates a token bound to that policy anchor. Policy settings are immutable after creation.
      </p>
      <h3 className="sb-section-title">Token type</h3>
      <div className="sb-menu" style={{ marginBottom: 10 }}>
        {KIND_META.map(m => (
          <button
            key={m.kind}
            type="button"
            className={`sb-menu__item${state.kind === m.kind ? ' focused' : ''}`}
            aria-pressed={state.kind === m.kind}
            onClick={() => {
              const patch: Partial<WizardState> = { kind: m.kind };
              if (m.kind !== 'FUNGIBLE') patch.decimals = 0;
              set(patch);
            }}
          >
            <span className="sb-menu__glyph">{m.icon}</span>
            <span className="sb-menu__text">
              <span className="sb-menu__label">{m.name}</span>
              <span className="sb-menu__desc">{m.desc}</span>
            </span>
          </button>
        ))}
      </div>

      <h3 className="sb-section-title">Identity</h3>

      <div className="sb-field">
        <label htmlFor="tcd-ticker">Ticker</label>
        <input
          id="tcd-ticker"
          className="sb-input sb-input--mono"
          placeholder="e.g. GOLD"
          maxLength={8}
          value={state.ticker}
          onChange={e => set({ ticker: e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '') })}
        />
        <p className="sb-hint sb-hint--tight">2–8 uppercase letters or digits. Cannot be changed after creation.</p>
      </div>

      <div className="sb-field">
        <label htmlFor="tcd-alias">Display Name</label>
        <input
          id="tcd-alias"
          className="sb-input"
          placeholder="e.g. Gold Coin"
          value={state.alias}
          onChange={e => set({ alias: e.target.value })}
        />
      </div>

      <div className="sb-field">
        <label htmlFor="tcd-desc">Description (optional)</label>
        <textarea
          id="tcd-desc"
          className="sb-input"
          placeholder="What is this token for?"
          maxLength={200}
          rows={3}
          value={state.description}
          onChange={e => set({ description: e.target.value })}
        />
        <p className="sb-hint sb-hint--tight" style={{ textAlign: 'right' }}>{state.description.length} / 200</p>
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
      <h3 className="sb-section-title">Precision</h3>

      <div className="sb-field">
        <label htmlFor="tcd-decimals">Decimals: {effectiveDecimals}</label>
        <input
          id="tcd-decimals"
          type="range"
          className="sb-range"
          min={0}
          max={18}
          value={effectiveDecimals}
          onChange={e => set({ decimals: Number(e.target.value) })}
        />
      </div>

      <h3 className="sb-section-title">Supply</h3>

      <div className="sb-field">
        <label htmlFor="tcd-supply">Total Supply</label>
        <input
          id="tcd-supply"
          className="sb-input sb-input--mono"
          inputMode="numeric"
          placeholder="1000000"
          value={state.genesisSupply}
          onChange={e => set({ genesisSupply: e.target.value.replace(/[^0-9]/g, '') })}
        />
        <p className="sb-hint sb-hint--tight">The whole supply, fixed at creation. All of it is released to your wallet; no more can ever be issued.</p>
      </div>

      <h3 className="sb-section-title">Permissions</h3>

      <div className="sb-field">
        <span className="sb-label">Burn</span>
        <Seg
          label="Burn"
          value={state.burnEnabled ? 'on' : 'off'}
          options={[{ id: 'off', label: 'Off' }, { id: 'on', label: 'On' }] as const}
          onChange={(v) => set({ burnEnabled: v === 'on' })}
        />
        <p className="sb-hint sb-hint--tight">Allow holders to destroy their own units.</p>
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
  /** The fee and this device's standing from Rust; `undefined` until the query returns. */
  creationFee: CreationFee;
}) {
  const supplyLine = state.genesisSupply ? BigInt(state.genesisSupply).toLocaleString() : '—';

  return (
    <div>
      <h3 className="sb-section-title">Allowlist</h3>
      <div className="sb-field">
        <Seg
          label="Allowlist"
          value={state.allowlistKind}
          options={[{ id: 'NONE', label: 'Open' }, { id: 'INLINE', label: 'Restricted' }] as const}
          onChange={(v) => set(v === 'NONE' ? { allowlistKind: 'NONE', allowlistData: '' } : { allowlistKind: 'INLINE' })}
        />
        <p className="sb-hint sb-hint--tight">
          {state.allowlistKind === 'NONE'
            ? 'Anyone can hold this token.'
            : 'Only allowlisted genesis IDs can hold it. They are committed into the policy at creation.'}
        </p>
      </div>

      {state.allowlistKind === 'INLINE' && (
        <div className="sb-field">
          <label htmlFor="tcd-al-data">Genesis IDs (one per line)</label>
          <textarea
            id="tcd-al-data"
            className="sb-input sb-input--mono"
            placeholder={'GENESIS1ABC...\nGENESIS2DEF...'}
            rows={4}
            value={state.allowlistData}
            onChange={e => set({ allowlistData: e.target.value })}
            spellCheck={false}
          />
        </div>
      )}

      <h3 className="sb-section-title">Review</h3>
      <div className="sb-kv">
        <span className="sb-kv__k">Kind</span>
        <span className="sb-kv__v"><span className="sb-tag">{state.kind}</span></span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Ticker</span>
        <span className="sb-kv__v">{state.ticker.toUpperCase()}</span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Name</span>
        <span className="sb-kv__v">{state.alias}</span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Decimals</span>
        <span className="sb-kv__v">{effectiveDecimals}</span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Total Supply</span>
        <span className="sb-kv__v">{supplyLine}</span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Burn</span>
        <span className="sb-kv__v">{state.burnEnabled ? 'Enabled' : 'Disabled'}</span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Transferable</span>
        <span className="sb-kv__v">{effectiveTransferable ? 'Yes' : 'No'}</span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Allowlist</span>
        <span className="sb-kv__v">
          {state.allowlistKind === 'NONE'
            ? 'Open'
            : `Restricted (${state.allowlistData.trim().split('\n').filter(Boolean).length} entries)`}
        </span>
      </div>
      <div className="sb-kv">
        <span className="sb-kv__k">Creation fee</span>
        <span className="sb-kv__v">
          {creationFee === undefined
            ? '…'
            : 'feeEra' in creationFee
              ? `${creationFee.feeDisplay} ERA (burned)`
              : `not available: ${creationFee.error}`}
        </span>
      </div>
      {creationFee !== undefined && 'feeEra' in creationFee && (
        <div className="sb-kv">
          <span className="sb-kv__k">Your ERA</span>
          <span className="sb-kv__v">{`${creationFee.heldDisplay} ERA`}</span>
        </div>
      )}
      {creationFee !== undefined && 'feeEra' in creationFee && !creationFee.feeCovered && (
        <div className="sb-notice" role="status" style={{ marginTop: 8 }}>
          <span>
            {`This burns ${creationFee.feeDisplay} ERA and you hold ${creationFee.heldDisplay}. Get ERA from the Faucet tab first.`}
          </span>
        </div>
      )}
      {state.description.trim() && (
        <div className="sb-kv">
          <span className="sb-kv__k">Desc</span>
          <span className="sb-kv__v">{state.description.trim()}</span>
        </div>
      )}
      <div className="sb-kv" style={{ alignItems: 'center' }}>
        <span className="sb-kv__k">Coin</span>
        <span className="sb-kv__v">
          <span className="sb-coin-tile sb-coin-tile--sm">
            <TokenCoin iconUrl={state.iconUrl} ticker={state.ticker} size={PREVIEW_COIN_SIZE} className="sb-coin sb-coin--lg" />
          </span>
        </span>
      </div>
      <p className="sb-hint" style={{ marginTop: 8 }}>
        A CPTA policy is published first, content-addressed and immutable. The token is then created bound to that policy anchor. These settings cannot be changed afterwards.
      </p>
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
    <div className="sb-popover sb-card--dark" role="dialog" aria-modal="true" aria-label="Token created">
      <div className="sb-popover__head">
        <h3 className="sb-popover__title">Token created</h3>
        <button type="button" className="sb-popover__close" onClick={onClose} aria-label="Close">{'×'}</button>
      </div>
      <div className="sb-popover__body">
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 8 }}>
          <span className="sb-coin-tile">
            <TokenCoin iconUrl={state.iconUrl} ticker={state.ticker} size={PREVIEW_COIN_SIZE} className="sb-coin sb-coin--xl" />
          </span>
        </div>
        <p className="sb-hint" style={{ textAlign: 'center' }}>Policy published and token created.</p>
        <div className="sb-kv">
          <span className="sb-kv__k">Kind</span>
          <span className="sb-kv__v"><span className="sb-tag">{state.kind}</span></span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">Ticker</span>
          <span className="sb-kv__v">{state.ticker.toUpperCase()}</span>
        </div>
        <div className="sb-kv">
          <span className="sb-kv__k">Name</span>
          <span className="sb-kv__v">{state.alias}</span>
        </div>
        {created.tokenId && (
          <div className="sb-kv">
            <span className="sb-kv__k">Token ID</span>
            <span className="sb-kv__v sb-kv__v--mono">{created.tokenId}</span>
          </div>
        )}
        {created.anchorBase32 && (
          <div className="sb-kv">
            <span className="sb-kv__k">Policy Anchor (CPTA)</span>
            <span className="sb-kv__v sb-kv__v--mono">{created.anchorBase32}</span>
          </div>
        )}
      </div>
      <button type="button" className="sb-btn sb-btn--primary sb-btn--block sb-popover__ok" onClick={onClose}>
        Done
      </button>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export const TokenCreationDialog: React.FC<{ onClose: () => void; onSuccess?: () => void }> = ({
  onClose, onSuccess,
}) => {
  const [step, setStep]       = useState(1);
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
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const loadFee = useCallback(async () => {
    try {
      const fee = await getTokenCreationFee();
      if (mountedRef.current) setCreationFee(fee);
    } catch (e) {
      if (mountedRef.current) setCreationFee({ error: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  // The device's standing against the fee is read where it is shown, each
  // time the review is reached: ERA may have arrived or left since.
  useEffect(() => {
    if (step === 3) void loadFee();
  }, [step, loadFee]);


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
    setStep(to);
    setError(null);
    if (bodyRef.current) bodyRef.current.scrollTop = 0;
  }, []);

  // B steps back through the wizard, and closes it from the first step. While
  // Rust is working the press is ignored: the outcome is on its way.
  useBackButton(!created, () => {
    if (creating || resolving) return;
    if (step > 1) navigate(step - 1);
    else onClose();
  });

  /** What the user entered, as entered: Rust trims, capitalises and checks it. */
  const details = useCallback((): TokenCreateDetails => {
    const s = stateRef.current;
    return {
      ticker:             s.ticker,
      alias:              s.alias,
      decimals:           effectiveDecimals,
      genesisSupply:      s.genesisSupply,
      burnEnabled:        s.burnEnabled,
      // The policy's signer set is this device alone (Rust fills it in),
      // so 1-of-1 is the only threshold it can satisfy.
      threshold:          1,
      description:        s.description,
      iconUrl:            s.iconUrl,
      transferable:       effectiveTransferable,
      allowlistKind:      s.allowlistKind,
      allowlistData:      s.allowlistKind === 'INLINE' ? s.allowlistData : undefined,
    };
  }, [effectiveDecimals, effectiveTransferable]);

  const [checking, setChecking] = useState<number | null>(null);

  const handleNext = useCallback(async () => {
    const fields = STEP_FIELDS[step];
    if (fields !== undefined) {
      setChecking(step);
      setError(null);
      try {
        const refused = (await checkToken(details())).filter((r) => fields.includes(r.field));
        if (refused.length > 0) {
          setError(refused.map((r) => r.reason).join('; '));
          return;
        }
      } catch (e) {
        setError(messageOf(e));
        return;
      } finally {
        setChecking(null);
      }
    }
    navigate(step + 1);
  }, [step, navigate, details]);

  const handleCreate = useCallback(async () => {
    setError(null);
    setCreating(true);
    try {
      const res = await createToken(details());
      if (res.success) {
        setCreated({ tokenId: res.tokenId, anchorBase32: res.anchorBase32 });
        if (onSuccess) onSuccess();
      } else {
        // Rust's reason, as it gave it.
        setError(res.message ?? 'token.create gave no reason');
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
        const again = await createToken(details());
        if (again.success) {
          setCreated({ tokenId: again.tokenId, anchorBase32: again.anchorBase32 });
          if (onSuccess) onSuccess();
        } else {
          setError(again.message ?? String(e));
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
  }, [details, onSuccess]);

  // ── Success screen ───────────────────────────────────────────────────────
  if (created) {
    return (
      <div className="sb-popover-backdrop" onClick={(e) => e.stopPropagation()}>
        <SuccessScreen created={created} state={state} onClose={onClose} />
      </div>
    );
  }

  // ── Wizard shell ─────────────────────────────────────────────────────────
  return (
    <div className="sb-popover-backdrop" onClick={(e) => e.stopPropagation()}>
      <div className="sb-popover sb-card--dark token-wizard" role="dialog" aria-modal="true" aria-labelledby="tcd-title">
        <div className="sb-popover__head">
          <h3 id="tcd-title" className="sb-popover__title">Create Token</h3>
          <button type="button" className="sb-popover__close" onClick={onClose} aria-label="Close">{'×'}</button>
        </div>

        <StepStrip step={step} />

        <div className="sb-popover__body" ref={bodyRef}>
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

        {error && (
          <div className="sb-notice sb-notice--error" role="alert" style={{ margin: 0 }}>
            <span>{error}</span>
          </div>
        )}

        <div className="sb-actions" style={{ margin: 0 }}>
          {step > 1 ? (
            <button type="button" className="sb-btn" onClick={() => navigate(step - 1)} disabled={creating}>
              Back
            </button>
          ) : (
            <button type="button" className="sb-btn" onClick={onClose}>
              Cancel
            </button>
          )}
          {step < 3 ? (
            <button type="button" className="sb-btn sb-btn--primary" onClick={handleNext} disabled={checking !== null}>
              {checking !== null ? 'Checking' : 'Continue'}
            </button>
          ) : (
            <button
              type="button"
              className="sb-btn sb-btn--primary"
              onClick={handleCreate}
              disabled={creating}
            >
              {resolving ? 'Confirming token' : creating ? 'Publishing token' : 'Burn ERA'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
