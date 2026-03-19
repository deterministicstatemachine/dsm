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
import './SettingsScreen.css';

interface Props {
  onNavigate?: (screen: ScreenType) => void;
}

type Step = 'method' | 'setup_entry1' | 'setup_entry2' | 'timeout' | 'done' | 'disable_confirm';

const TIMEOUTS: { label: string; ms: number }[] = [
  { label: '1 MINUTE',  ms: 60_000 },
  { label: '5 MINUTES', ms: 5 * 60_000 },
  { label: '15 MINUTES', ms: 15 * 60_000 },
  { label: '30 MINUTES', ms: 30 * 60_000 },
  { label: 'NEVER',     ms: 0 },
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
  // Build flat list of navigable items based on current step
  const navActions = useMemo(() => {
    const actions: Array<() => void> = [];
    if (step === 'method') {
      // BACK button
      actions.push(back);
      // DISABLE LOCK (only when enabled)
      if (existingEnabled) actions.push(() => setStep('disable_confirm'));
      // PIN, COMBO
      actions.push(() => pickMethod('pin'));
      actions.push(() => pickMethod('combo'));
    } else if (step === 'disable_confirm') {
      actions.push(handleDisable);
      actions.push(() => setStep('method'));
    } else if (step === 'timeout') {
      // BACK button
      actions.push(() => setStep('method'));
      actions.push(() => setLockOnPause((value) => !value));
      // Timeout options
      for (const t of TIMEOUTS) {
        actions.push(() => void save(t.ms));
      }
    } else if (step === 'done') {
      actions.push(back);
    } else {
      // setup_entry1/entry2 with PIN/COMBO — custom input handles keys
      // Just the back button
      actions.push(() => setStep('method'));
    }
    return actions;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, method, existingEnabled, saving, lockOnPause]);

  const { focusedIndex } = useDpadNav({
    itemCount: navActions.length,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  // ---- Render ----
  return (
    <div className="settings-shell settings-shell--lock">
      <div className="settings-shell__title">
        WALLET LOCK SETUP
      </div>

      {/* BACK button */}
      {step !== 'done' && (
        <button
          className={`settings-shell__button${fc(0)}`}
          onClick={step === 'method' ? back : () => setStep('method')}
          style={{ marginBottom: '12px', fontSize: '8px', width: 'auto', alignSelf: 'flex-start', padding: '4px 10px' }}
        >
          ← BACK
        </button>
      )}

      {/* ---- STEP: method picker ---- */}
      {step === 'method' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%' }}>
          {existingEnabled && (
            <button
              className={`settings-shell__button${fc(1)}`}
              onClick={() => setStep('disable_confirm')}
              style={{ fontSize: '9px', borderColor: 'var(--text-dark)', marginBottom: '6px' }}
            >
              DISABLE LOCK (CURRENTLY ON)
            </button>
          )}

          <div style={{ fontSize: '9px', letterSpacing: '1px', color: 'var(--text-dark)', marginBottom: '4px' }}>
            SELECT UNLOCK METHOD:
          </div>

          {(['pin', 'combo'] as LockMethod[]).map((m, mIdx) => (
            <button
              key={m}
              className={`settings-shell__button${fc((existingEnabled ? 2 : 1) + mIdx)}`}
              onClick={() => pickMethod(m)}
              style={{ fontSize: '10px', fontWeight: 'bold' }}
            >
              {m === 'pin' ? 'PIN CODE' : 'BUTTON COMBO'}
            </button>
          ))}
        </div>
      )}

      {/* ---- STEP: disable confirm ---- */}
      {step === 'disable_confirm' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', alignItems: 'center' }}>
          <div style={{ fontSize: '9px', letterSpacing: '1px', textAlign: 'center', lineHeight: '1.5' }}>
            DISABLE WALLET LOCK?<br />YOUR WALLET WILL BE UNPROTECTED.
          </div>
          <button
            className={`settings-shell__button${fc(0)}`}
            onClick={handleDisable}
            disabled={saving}
            style={{ fontSize: '10px', fontWeight: 'bold' }}
          >
            {saving ? 'DISABLING…' : 'CONFIRM DISABLE'}
          </button>
          <button
            className={`settings-shell__button${fc(1)}`}
            onClick={() => setStep('method')}
            style={{ fontSize: '9px' }}
          >
            CANCEL
          </button>
        </div>
      )}

      {/* ---- STEP: setup_entry1 (first entry) ---- */}
      {step === 'setup_entry1' && method === 'pin' && (
        <PinInput onComplete={handleEntry1Pin} label="CHOOSE A PIN (4-8 DIGITS)" />
      )}
      {step === 'setup_entry1' && method === 'combo' && (
        <StateboyComboInput onComplete={handleEntry1Combo} label="CHOOSE YOUR 8-BUTTON COMBO" />
      )}
      {/* ---- STEP: setup_entry2 (confirm entry) ---- */}
      {step === 'setup_entry2' && method === 'pin' && (
        <>
          {mismatch && (
            <div style={{ fontSize: '8px', color: 'var(--text-dark)', fontWeight: 'bold',
              letterSpacing: '1px', marginBottom: '8px', textAlign: 'center' }}>
              ✗ PINS DO NOT MATCH — TRY AGAIN
            </div>
          )}
          <PinInput onComplete={handleEntry2Pin} label="CONFIRM PIN — ENTER AGAIN" />
        </>
      )}
      {step === 'setup_entry2' && method === 'combo' && (
        <>
          {mismatch && (
            <div style={{ fontSize: '8px', color: 'var(--text-dark)', fontWeight: 'bold',
              letterSpacing: '1px', marginBottom: '8px', textAlign: 'center' }}>
              ✗ COMBOS DO NOT MATCH — TRY AGAIN
            </div>
          )}
          <StateboyComboInput onComplete={handleEntry2Combo} label="CONFIRM COMBO — ENTER AGAIN" />
        </>
      )}

      {/* ---- STEP: timeout picker ---- */}
      {step === 'timeout' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
          <div style={{ fontSize: '9px', letterSpacing: '1px', marginBottom: '4px' }}>
            AUTO-LOCK AFTER INACTIVITY:
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 0', gap: '8px' }}>
            <span style={{ fontSize: '9px', letterSpacing: '1px' }}>LOCK ON EXIT</span>
            <button
              className={`settings-shell__button${fc(1)}`}
              onClick={() => setLockOnPause((value) => !value)}
              style={{ fontSize: '9px', width: 'auto', minWidth: '44px', padding: '4px 10px', flexShrink: 0 }}
            >
              {lockOnPause ? 'ON' : 'OFF'}
            </button>
          </div>
          {TIMEOUTS.map((t, tIdx) => (
            <button
              key={t.label}
              className={`settings-shell__button${fc(tIdx + 2)}`}
              onClick={() => void save(t.ms)}
              disabled={saving}
              style={{ fontSize: '10px' }}
            >
              {t.label}
            </button>
          ))}
        </div>
      )}

      {/* ---- STEP: done ---- */}
      {step === 'done' && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
          <div style={{ fontSize: '14px', fontWeight: 'bold', letterSpacing: '2px', fontFamily: "'Martian Mono', monospace" }}>[LOCKED]</div>
          <div style={{ fontSize: '11px', fontWeight: 'bold', letterSpacing: '2px', textAlign: 'center' }}>
            LOCK ENABLED
          </div>
          <div style={{ fontSize: '8px', letterSpacing: '1px', opacity: 0.7, textAlign: 'center', lineHeight: '1.5' }}>
            METHOD: {method.toUpperCase()}<br />
            AUTO-LOCK: {TIMEOUTS.find(t => t.ms === timeoutMs)?.label ?? 'CUSTOM'}<br />
            EXIT LOCK: {lockOnPause ? 'ON' : 'OFF'}
          </div>
          <div style={{ fontSize: '8px', letterSpacing: '1px', opacity: 0.5, marginTop: '4px' }}>RETURNING…</div>
        </div>
      )}
    </div>
  );
}

export default memo(LockSetupScreen);
