// SPDX-License-Identifier: Apache-2.0
/**
 * LockSetupScreen — configure wallet lock method.
 * Step 1: Choose method (PIN / COMBO)
 * Step 2: Setup flow (enter twice to confirm)
 * Step 3: Timeout picker
 * Step 4: Save + confirm
 */

import React, { useState, memo, useMemo } from 'react';
import type { ScreenType } from '../../types/app';
import PinInput from '../lock/PinInput';
import StateboyComboInput, { type ComboButton } from '../lock/StateboyComboInput';
import {
  hashPin, hashCombo, saveLockPrefs, disableLock, getLockPrefs,
  type LockMethod,
} from '../../services/lock/lockService';
import { useDpadNav } from '../../hooks/useDpadNav';
import { Notice, ScreenFrame } from '../common/ScreenFrame';

interface Props {
  onNavigate?: (screen: ScreenType) => void;
}

type Step = 'method' | 'setup_entry1' | 'setup_entry2' | 'timeout' | 'done' | 'disable_confirm';

const TIMEOUTS: { label: string; ms: number }[] = [
  { label: '1 minute',  ms: 60_000 },
  { label: '5 minutes', ms: 5 * 60_000 },
  { label: '15 minutes', ms: 15 * 60_000 },
  { label: '30 minutes', ms: 30 * 60_000 },
  { label: 'Never',     ms: 0 },
];

const METHODS: ReadonlyArray<{ id: LockMethod; glyph: string; label: string; desc: string }> = [
  { id: 'pin', glyph: '#', label: 'PIN code', desc: '4 to 8 digits on the keypad.' },
  { id: 'combo', glyph: 'AB', label: 'Button combo', desc: "8 presses of the shell's own buttons." },
];

function LockSetupScreen({ onNavigate }: Props) {
  const [step, setStep] = useState<Step>('method');
  const [method, setMethod] = useState<LockMethod>('pin');
  const [entry1, setEntry1] = useState<string | ComboButton[]>('');
  const [timeoutMs, setTimeoutMs] = useState(5 * 60_000);
  const [lockOnPause, setLockOnPause] = useState(true);
  const [mismatch, setMismatch] = useState(false);
  const [saving, setSaving] = useState(false);
  const [existingEnabled, setExistingEnabled] = useState<boolean | null>(null);

  // Load existing config once on mount
  React.useEffect(() => {
    getLockPrefs().then((p) => {
      setExistingEnabled(p.enabled);
      setTimeoutMs(p.timeoutMs);
      setLockOnPause(p.lockOnPause);
    }).catch(() => {});
  }, []);

  const back = () => onNavigate?.('settings');

  // Auto-exit to settings after save completes — no button press needed
  React.useEffect(() => {
    if (step !== 'done') return;
    const timer = setTimeout(() => back(), 1200);
    return () => clearTimeout(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  // ---- Step 1: Method picker ----
  const pickMethod = (m: LockMethod) => {
    setMethod(m);
    setEntry1('');
    setMismatch(false);
    setStep('setup_entry1');
  };

  // ---- Step 2: First entry ----
  const handleEntry1Pin = (pin: string) => {
    setEntry1(pin);
    setStep('setup_entry2');
  };

  const handleEntry1Combo = (combo: ComboButton[]) => {
    setEntry1(combo);
    setStep('setup_entry2');
  };

  // ---- Step 3: Confirm entry ----
  const handleEntry2Pin = async (pin: string) => {
    if (pin !== entry1) { setMismatch(true); return; }
    setMismatch(false);
    setStep('timeout');
  };

  const handleEntry2Combo = async (combo: ComboButton[]) => {
    const s1 = (entry1 as ComboButton[]).join(',');
    const s2 = combo.join(',');
    if (s1 !== s2) { setMismatch(true); return; }
    setMismatch(false);
    setStep('timeout');
  };

  // ---- Step 4: Save ----
  const save = async (ms: number) => {
    setSaving(true);
    try {
      let pinHash = '';
      let comboHash = '';
      if (method === 'pin') {
        pinHash = await hashPin(entry1 as string);
      } else if (method === 'combo') {
        comboHash = await hashCombo(entry1 as ComboButton[]);
      }
      await saveLockPrefs({ enabled: true, method, pinHash, comboHash, timeoutMs: ms, lockOnPause });
      setTimeoutMs(ms);
      setStep('done');
    } finally {
      setSaving(false);
    }
  };

  const handleDisable = async () => {
    setSaving(true);
    await disableLock().catch(() => {});
    setSaving(false);
    back();
  };

  // --- D-pad navigation ---
  // The shell's B button (and the header chevron) go back; the list holds the
  // rest of what the step offers, in the order it is drawn.
  const navActions = useMemo(() => {
    const actions: Array<() => void> = [];
    if (step === 'method') {
      if (existingEnabled) actions.push(() => setStep('disable_confirm'));
      for (const m of METHODS) actions.push(() => pickMethod(m.id));
    } else if (step === 'disable_confirm') {
      actions.push(handleDisable);
      actions.push(() => setStep('method'));
    } else if (step === 'timeout') {
      actions.push(() => setLockOnPause((value) => !value));
      for (const t of TIMEOUTS) {
        actions.push(() => void save(t.ms));
      }
    }
    // setup_entry1 / setup_entry2: the keypad or the shell buttons take the
    // presses; done: nothing to pick, the screen returns by itself.
    return actions;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, method, existingEnabled, saving, lockOnPause]);

  const { focusedIndex } = useDpadNav({
    itemCount: navActions.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');
  const methodOffset = existingEnabled ? 1 : 0;

  const onBack = step === 'done'
    ? undefined
    : step === 'method'
      ? back
      : () => setStep('method');

  // ---- Render ----
  return (
    <ScreenFrame title="Wallet Lock" onBack={onBack} className="lock-setup-screen">
      {/* ---- STEP: method picker ---- */}
      {step === 'method' && (
        <>
          {existingEnabled && (
            <section className="sb-card sb-card--dark">
              <div className="sb-kv">
                <span className="sb-kv__k">Lock</span>
                <span className="sb-kv__v"><span className="sb-tag sb-tag--solid">On</span></span>
              </div>
              <button
                type="button"
                className={`sb-btn sb-btn--block${fc(0)}`}
                style={{ marginTop: 8 }}
                onClick={() => setStep('disable_confirm')}
              >
                Disable lock
              </button>
            </section>
          )}

          <h3 className="sb-section-title">Unlock method</h3>
          <div className="sb-menu">
            {METHODS.map((m, mIdx) => (
              <button
                key={m.id}
                type="button"
                className={`sb-menu__item${fc(methodOffset + mIdx)}`}
                onClick={() => pickMethod(m.id)}
              >
                <span className="sb-menu__glyph">{m.glyph}</span>
                <span className="sb-menu__text">
                  <span className="sb-menu__label">{m.label}</span>
                  <span className="sb-menu__desc">{m.desc}</span>
                </span>
                <span className="sb-menu__chev" aria-hidden="true">{'›'}</span>
              </button>
            ))}
          </div>
        </>
      )}

      {/* ---- STEP: disable confirm ---- */}
      {step === 'disable_confirm' && (
        <section className="sb-card">
          <div className="sb-card__title">Disable wallet lock?</div>
          <p className="sb-hint">Your wallet will open without a PIN or combo.</p>
          <div className="sb-actions" style={{ margin: 0 }}>
            <button
              type="button"
              className={`sb-btn${fc(1)}`}
              onClick={() => setStep('method')}
            >
              Cancel
            </button>
            <button
              type="button"
              className={`sb-btn sb-btn--primary${fc(0)}`}
              onClick={handleDisable}
              disabled={saving}
            >
              {saving ? 'Disabling…' : 'Confirm disable'}
            </button>
          </div>
        </section>
      )}

      {/* ---- STEP: setup_entry1 (first entry) ---- */}
      {step === 'setup_entry1' && (
        <section className="sb-card">
          {method === 'pin'
            ? <PinInput onComplete={handleEntry1Pin} label="Choose a PIN (4-8 digits)" />
            : <StateboyComboInput onComplete={handleEntry1Combo} label="Choose your 8-button combo" />}
        </section>
      )}

      {/* ---- STEP: setup_entry2 (confirm entry) ---- */}
      {step === 'setup_entry2' && (
        <>
          {mismatch && (
            <Notice kind="error">
              {method === 'pin' ? 'PINs do not match. Try again.' : 'Combos do not match. Try again.'}
            </Notice>
          )}
          <section className="sb-card">
            {method === 'pin'
              ? <PinInput onComplete={handleEntry2Pin} label="Confirm PIN: enter it again" />
              : <StateboyComboInput onComplete={handleEntry2Combo} label="Confirm combo: enter it again" />}
          </section>
        </>
      )}

      {/* ---- STEP: timeout picker ---- */}
      {step === 'timeout' && (
        <>
          <section className="sb-card">
            <div className="sb-kv" style={{ alignItems: 'center' }}>
              <span className="sb-kv__k">Lock on exit</span>
              <div className={`sb-seg${fc(0)}`} role="group" aria-label="Lock on exit">
                <button
                  type="button"
                  className={`sb-seg__opt${lockOnPause ? ' active' : ''}`}
                  aria-pressed={lockOnPause}
                  onClick={() => setLockOnPause(true)}
                >
                  On
                </button>
                <button
                  type="button"
                  className={`sb-seg__opt${lockOnPause ? '' : ' active'}`}
                  aria-pressed={!lockOnPause}
                  onClick={() => setLockOnPause(false)}
                >
                  Off
                </button>
              </div>
            </div>
          </section>

          <h3 className="sb-section-title">Auto-lock after inactivity</h3>
          <div style={{ display: 'grid', gap: 8 }}>
            {TIMEOUTS.map((t, tIdx) => (
              <button
                key={t.label}
                type="button"
                className={`sb-btn sb-btn--block${t.ms === timeoutMs ? ' sb-btn--primary' : ''}${fc(tIdx + 1)}`}
                onClick={() => void save(t.ms)}
                disabled={saving}
              >
                {t.label}
              </button>
            ))}
          </div>
        </>
      )}

      {/* ---- STEP: done ---- */}
      {step === 'done' && (
        <section className="sb-card sb-card--dark sb-card--hero">
          <div className="sb-hero__label">Lock enabled</div>
          <div className="sb-hero__value">[LOCKED]</div>
          <div className="sb-hero__row"><span>Method</span><b>{method.toUpperCase()}</b></div>
          <div className="sb-hero__row"><span>Auto-lock</span><b>{TIMEOUTS.find(t => t.ms === timeoutMs)?.label ?? 'Custom'}</b></div>
          <div className="sb-hero__row"><span>Exit lock</span><b>{lockOnPause ? 'On' : 'Off'}</b></div>
          <div className="sb-hero__sub">Returning…</div>
        </section>
      )}
    </ScreenFrame>
  );
}

export default memo(LockSetupScreen);
