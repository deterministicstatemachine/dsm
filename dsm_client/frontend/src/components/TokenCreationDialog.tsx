import React, { useState, useCallback, useRef } from 'react';
import './TokenCreationDialog.css';
import { dsmClient } from '@/services/dsmClient';

// ── Types ────────────────────────────────────────────────────────────────────
type TokenKind = 'FUNGIBLE' | 'NFT' | 'SBT';
type AllowlistKind = 'NONE' | 'INLINE';

interface WizardState {
  kind: TokenKind;
  ticker: string;
  alias: string;
  description: string;
  iconUrl: string;
  decimals: number;
  unlimitedSupply: boolean;
  maxSupply: string;
  initialAlloc: string;
  mintBurnEnabled: boolean;
  mintBurnThreshold: number;
  allowlistKind: AllowlistKind;
  allowlistData: string;
}

const DEFAULT: WizardState = {
  kind: 'FUNGIBLE',
  ticker: '',
  alias: '',
  description: '',
  iconUrl: '',
  decimals: 2,
  unlimitedSupply: false,
  maxSupply: '1000000',
  initialAlloc: '0',
  mintBurnEnabled: false,
  mintBurnThreshold: 1,
  allowlistKind: 'NONE',
  allowlistData: '',
};

function isTransferableKind(kind: TokenKind): boolean {
  return kind !== 'SBT';
}

// ── Validation ───────────────────────────────────────────────────────────────
function validateStep1(s: WizardState): string | null {
  const t = s.ticker.trim().toUpperCase();
  if (!t || t.length < 2 || t.length > 8) return 'Ticker must be 2–8 letters';
  if (!/^[A-Z0-9]+$/.test(t)) return 'Ticker: letters and digits only';
  if (!s.alias.trim()) return 'Display name is required';
  return null;
}

function validateStep2(s: WizardState): string | null {
  if (!s.unlimitedSupply) {
    const raw = s.maxSupply.trim();
    if (!/^[0-9]+$/.test(raw) || raw === '0') return 'Max supply must be a positive integer';
    try {
      const supply = BigInt(raw);
      const allocRaw = s.initialAlloc.trim() || '0';
      if (!/^[0-9]*$/.test(allocRaw)) return 'Initial allocation must be a non-negative integer';
      const alloc = BigInt(allocRaw || '0');
      if (alloc > supply) return 'Initial allocation cannot exceed max supply';
    } catch {
      return 'Max supply must be a valid integer';
    }
  }
  if (s.mintBurnEnabled && (s.mintBurnThreshold < 1 || s.mintBurnThreshold > 255))
    return 'Threshold must be 1–255';
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
  { kind: 'NFT',      icon: 'N', name: 'NFT',      desc: 'Unique collectible' },
  { kind: 'SBT',      icon: 'S', name: 'SBT',      desc: 'Soul-bound credential' },
];

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

      <div className="tcd-field">
        <label className="tcd-label" htmlFor="tcd-icon">
          Icon URL <span className="tcd-optional">(optional)</span>
        </label>
        <input
          id="tcd-icon"
          className="tcd-input"
          placeholder="https://…/icon.png"
          value={state.iconUrl}
          onChange={e => set({ iconUrl: e.target.value })}
        />
      </div>
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
  const notFungible = state.kind !== 'FUNGIBLE';

  return (
    <div>
      <div className="tcd-section-title">Precision</div>

      <div className="tcd-field">
        <label className="tcd-label">
          Decimals
          {notFungible && (
            <span className="tcd-hint" style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>
              {' '}— locked to 0 for {state.kind}
            </span>
          )}
        </label>
        <div className="tcd-slider-row">
          <input
            type="range"
            className="tcd-slider"
            min={0}
            max={18}
            value={effectiveDecimals}
            disabled={notFungible}
            onChange={e => !notFungible && set({ decimals: Number(e.target.value) })}
          />
          <span className="tcd-slider-val">{effectiveDecimals}</span>
        </div>
      </div>

      <div className="tcd-section-title">Supply</div>

      <div className="tcd-toggle-row">
        <div className="tcd-toggle-info">
          <span className="tcd-toggle-name">Unlimited Supply</span>
          <span className="tcd-toggle-sub">No hard cap — tokens can always be issued if mint is enabled</span>
        </div>
        <Toggle id="tcd-unlimited" checked={state.unlimitedSupply} onChange={v => set({ unlimitedSupply: v })} />
      </div>

      {!state.unlimitedSupply && (
        <>
          <div className="tcd-field">
            <label className="tcd-label" htmlFor="tcd-supply">Max Supply</label>
            <input
              id="tcd-supply"
              className="tcd-input"
              placeholder="1000000"
              value={state.maxSupply}
              onChange={e => set({ maxSupply: e.target.value.replace(/[^0-9]/g, '') })}
            />
          </div>

          <div className="tcd-field">
            <label className="tcd-label" htmlFor="tcd-alloc">
              Initial Allocation <span className="tcd-optional">(optional)</span>
            </label>
            <input
              id="tcd-alloc"
              className="tcd-input"
              placeholder="0"
              value={state.initialAlloc}
              onChange={e => set({ initialAlloc: e.target.value.replace(/[^0-9]/g, '') })}
            />
            <span className="tcd-hint">Tokens minted immediately to your wallet. Must be ≤ max supply.</span>
          </div>
        </>
      )}

      <div className="tcd-section-title">Permissions</div>

      <div className="tcd-toggle-row">
        <div className="tcd-toggle-info">
          <span className="tcd-toggle-name">Mint / Burn Authority</span>
          <span className="tcd-toggle-sub">Allow authorised signers to issue or destroy tokens post-launch</span>
        </div>
        <Toggle id="tcd-mintburn" checked={state.mintBurnEnabled} onChange={v => set({ mintBurnEnabled: v })} />
      </div>

      {state.mintBurnEnabled && (
        <div className="tcd-subpanel">
          <div className="tcd-field" style={{ marginBottom: 0 }}>
            <label className="tcd-label" htmlFor="tcd-threshold">Signatures Required</label>
            <div className="tcd-slider-row">
              <input
                id="tcd-threshold"
                type="range"
                className="tcd-slider"
                min={1}
                max={10}
                value={state.mintBurnThreshold}
                onChange={e => set({ mintBurnThreshold: Number(e.target.value) })}
              />
              <span className="tcd-slider-val">{state.mintBurnThreshold}</span>
            </div>
            <span className="tcd-hint">{state.mintBurnThreshold}-of-N authority must co-sign any mint or burn.</span>
          </div>
        </div>
      )}

    </div>
  );
}

// ── Sub-component: Step 3 — Access + Review ──────────────────────────────────
function Step3({
  state, set, effectiveDecimals, effectiveTransferable,
}: {
  state: WizardState;
  set: (p: Partial<WizardState>) => void;
  effectiveDecimals: number;
  effectiveTransferable: boolean;
}) {
  const supplyLine = state.unlimitedSupply ? 'Unlimited' : Number(state.maxSupply || '0').toLocaleString();
  const allocLine  = state.unlimitedSupply ? '—' : Number(state.initialAlloc || '0').toLocaleString();

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
          <span className="tcd-review-key">Max Supply</span>
          <span className="tcd-review-val">{supplyLine}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Initial Alloc</span>
          <span className="tcd-review-val">{allocLine}</span>
        </div>
        <div className="tcd-review-row">
          <span className="tcd-review-key">Mint / Burn</span>
          <span className="tcd-review-val">
            {state.mintBurnEnabled ? `Enabled (threshold ${state.mintBurnThreshold})` : 'Disabled'}
          </span>
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
        {state.description.trim() && (
          <div className="tcd-review-row">
            <span className="tcd-review-key">Desc</span>
            <span className="tcd-review-val" style={{ fontSize: 10 }}>{state.description.trim()}</span>
          </div>
        )}
        {state.iconUrl.trim() && (
          <div className="tcd-review-row">
            <span className="tcd-review-key">Icon</span>
            <span className="tcd-review-val" style={{ fontSize: 9 }}>{state.iconUrl.trim()}</span>
          </div>
        )}
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
  const [error,    setError]    = useState<string | null>(null);
  const [created,  setCreated]  = useState<{ tokenId?: string; anchorBase32?: string } | null>(null);
  const stateRef = useRef(state);

  const set = useCallback((patch: Partial<WizardState>) => {
    _setState(prev => {
      const next = { ...prev, ...patch };
      stateRef.current = next;
      return next;
    });
  }, []);

  // Derived helpers
  const effectiveDecimals     = state.kind !== 'FUNGIBLE' ? 0 : state.decimals;
  const effectiveTransferable = isTransferableKind(state.kind);

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
      const res = await dsmClient.createToken({
        ticker:             s.ticker.trim().toUpperCase(),
        alias:              s.alias.trim(),
        decimals:           effectiveDecimals,
        maxSupply:          s.unlimitedSupply ? '0' : s.maxSupply,
        kind:               s.kind,
        description:        s.description.trim() || undefined,
        iconUrl:            s.iconUrl.trim()      || undefined,
        unlimitedSupply:    s.unlimitedSupply,
        initialAlloc:       s.initialAlloc || '0',
        mintBurnEnabled:    s.mintBurnEnabled,
        mintBurnThreshold:  s.mintBurnThreshold,
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
        const r = (typeof res === 'object' && res !== null && 'result' in res)
          ? (res as { result?: { tokenId?: string; anchorBase32?: string } }).result
          : undefined;
        setCreated(r ?? {});
        if (onSuccess) onSuccess();
      } else {
        const msg = (typeof res === 'object' && res !== null && 'error' in res)
          ? String((res as { error?: unknown }).error)
          : 'Token creation failed';
        setError(msg);
        setCreating(false);
      }
    } catch (e) {
      setError(String(e));
      setCreating(false);
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
              {creating ? 'Publishing policy\u2026' : 'Publish'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
