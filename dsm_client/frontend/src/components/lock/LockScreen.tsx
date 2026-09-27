// SPDX-License-Identifier: Apache-2.0
/**
 * LockScreen — full-viewport lock overlay.
 * Reads lock_method pref and shows the appropriate unlock UI.
 * Wrong attempt: shake + flash.
 * MAX_ATTEMPTS wrong = LOCK_COOLDOWN_MS cooldown, persisted across app restarts
 * so killing and relaunching the app cannot reset the counter.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import PinInput from './PinInput';
import StateboyComboInput, { type ComboButton } from './StateboyComboInput';
import {
  getLockPrefs, verifyPin, verifyCombo,
  getFailedAttemptState, recordFailedAttempt, clearFailedAttempts,
  LOCK_MAX_ATTEMPTS, LOCK_COOLDOWN_MS,
} from '../../services/lock/lockService';
import type { LockMethod } from '../../services/lock/lockService';
import { Notice } from '../common/ScreenFrame';
import './LockScreen.css';

interface Props {
  onUnlock: () => void;
}

const COOLDOWN_SECS = Math.ceil(LOCK_COOLDOWN_MS / 1000);
const POW_WORDS = ['POW!', 'ZAP!', 'BAM!', 'BOOM!', '✓ OPEN'];
const pickPow = () => POW_WORDS[Math.floor(Math.random() * (POW_WORDS.length - 1))];

export default function LockScreen({ onUnlock }: Props) {
  const [method, setMethod] = useState<LockMethod>('pin');
  const [pinHash, setPinHash] = useState('');
  const [comboHash, setComboHash] = useState('');
  const [shake, setShake] = useState(false);
  const [flash, setFlash] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [cooldown, setCooldown] = useState(0);
  const cooldownRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [unlocking, setUnlocking] = useState(false);
  const powWord = useRef(pickPow());

  // Load prefs + restore persisted failed-attempt state on mount
  useEffect(() => {
    getLockPrefs().then((p) => {
      setMethod(p.method);
      setPinHash(p.pinHash);
      setComboHash(p.comboHash);
    }).catch(() => {});

    getFailedAttemptState().then(({ count, lockedUntilMs }) => {
      setAttempts(count);
      if (lockedUntilMs > 0) {
        const remainingMs = lockedUntilMs - Date.now();
        if (remainingMs > 0) {
          // Clamp to LOCK_COOLDOWN_MS to prevent clock-manipulation abuse
          // (setting clock backward would create an artificially large remaining time).
          const clampedMs = Math.min(remainingMs, LOCK_COOLDOWN_MS);
          setCooldown(Math.ceil(clampedMs / 1000));
        } else {
          // Cooldown elapsed while app was closed — leave attempts count as-is
          // so user still sees remaining-attempt count, just no longer blocked.
          setCooldown(0);
        }
      }
    }).catch(() => {});
  }, []);

  // Cooldown ticker
  useEffect(() => {
    if (cooldown <= 0) {
      if (cooldownRef.current) clearInterval(cooldownRef.current);
      return;
    }
    cooldownRef.current = setInterval(() => {
      setCooldown((c) => {
        if (c <= 1) {
          if (cooldownRef.current) clearInterval(cooldownRef.current);
          setAttempts(0);
          return 0;
        }
        return c - 1;
      });
    }, 1000);
    return () => { if (cooldownRef.current) clearInterval(cooldownRef.current); };
  }, [cooldown]);

  const triggerWrong = useCallback(async () => {
    setShake(true);
    setFlash(true);
    setTimeout(() => setShake(false), 600);
    setTimeout(() => setFlash(false), 800);
    try {
      const { count, lockedUntilMs } = await recordFailedAttempt();
      setAttempts(count);
      if (lockedUntilMs > 0) {
        setCooldown(COOLDOWN_SECS);
      }
    } catch {
      // Preferences write failed — fall back to in-memory only
      setAttempts((n) => {
        const next = n + 1;
        if (next >= LOCK_MAX_ATTEMPTS) setCooldown(COOLDOWN_SECS);
        return next;
      });
    }
  }, []);

  const triggerUnlock = useCallback(() => {
    setUnlocking(true);
    clearFailedAttempts().catch(() => {});
    setTimeout(() => onUnlock(), 780);
  }, [onUnlock]);

  const handlePinComplete = useCallback(async (pin: string) => {
    if (cooldown > 0 || verifying) return;
    setVerifying(true);
    try {
      const ok = await verifyPin(pin, pinHash);
      if (ok) { triggerUnlock(); } else { await triggerWrong(); }
    } finally {
      setVerifying(false);
    }
  }, [pinHash, cooldown, verifying, triggerUnlock, triggerWrong]);

  const handleComboComplete = useCallback(async (combo: ComboButton[]) => {
    if (cooldown > 0 || verifying) return;
    setVerifying(true);
    try {
      const ok = await verifyCombo(combo, comboHash);
      if (ok) { triggerUnlock(); } else { await triggerWrong(); }
    } finally {
      setVerifying(false);
    }
  }, [comboHash, cooldown, verifying, triggerUnlock, triggerWrong]);

  const blocked = cooldown > 0;

  return (
    <div className={`lock-screen sb-screen${shake ? ' lock-screen--shake' : ''}${flash ? ' lock-screen--flash' : ''}`}>

      {unlocking && (
        <div className="lock-pow-overlay">
          <div className="pow-star pow-star--bg" />
          <div className="pow-star pow-star--fg" />
          <div className="pow-text">{powWord.current}</div>
        </div>
      )}

      <div className="sb-screen__body lock-screen__body">
        <section className="sb-card sb-card--dark sb-card--hero lock-header">
          <div className="sb-hero__label lock-subtitle">AUTHENTICATION REQUIRED</div>
          <div className="sb-hero__value lock-icon">[LOCKED]</div>
        </section>

        {blocked && (
          <Notice kind="error" role="status">
            TOO MANY ATTEMPTS — WAIT {cooldown}s
          </Notice>
        )}

        {verifying && !blocked && (
          <Notice>VERIFYING…</Notice>
        )}

        {!blocked && !verifying && (
          <section className="sb-card lock-body">
            {method === 'pin' && (
              <PinInput onComplete={handlePinComplete} label="ENTER PIN" />
            )}

            {method === 'combo' && (
              <StateboyComboInput onComplete={handleComboComplete} label="ENTER BUTTON COMBO" />
            )}
          </section>
        )}

        {attempts > 0 && !blocked && (
          <Notice kind="error">
            ✗ INCORRECT — {LOCK_MAX_ATTEMPTS - attempts} ATTEMPTS REMAINING
          </Notice>
        )}
      </div>
    </div>
  );
}
