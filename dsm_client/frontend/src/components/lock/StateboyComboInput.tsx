// SPDX-License-Identifier: Apache-2.0
/**
 * StateboyComboInput — 8-button combo entry via the physical StateBoy shell buttons.
 *
 * Input sources (NO on-screen buttons rendered — use the actual shell):
 *   1. 'sb-btn' CustomEvent dispatched by public/index.html when a physical
 *      shell button is tapped (detail: 'up'|'down'|'left'|'right'|'a'|'b'|'start'|'select')
 *   2. Keyboard fallback for dev/desktop: Arrow keys, Z=A, X=B, Enter=START, Shift=SELECT
 *
 * Security: dots show count only (● / ○) — no indication of which buttons pressed.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';

export type ComboButton = 'up' | 'down' | 'left' | 'right' | 'a' | 'b' | 'start' | 'select';

const COMBO_LENGTH = 8;

const VALID_BUTTONS = new Set<string>(['up', 'down', 'left', 'right', 'a', 'b', 'start', 'select']);

const KEY_MAP: Record<string, ComboButton | '__back'> = {
  ArrowUp: 'up',
  ArrowDown: 'down',
  ArrowLeft: 'left',
  ArrowRight: 'right',
  z: 'a', Z: 'a',
  x: 'b', X: 'b',
  Enter: 'start',
  Shift: 'select',
  Backspace: '__back',
};

interface Props {
  onComplete: (combo: ComboButton[]) => void;
  label?: string;
}

type ComboWindow = Window & { __dsmComboEntryActive?: boolean };

export default function StateboyComboInput({ onComplete, label }: Props) {
  const [count, setCount] = useState(0);
  // Ref holds live combo so event handlers always see current value (no stale closure)
  const comboRef = useRef<ComboButton[]>([]);
  const onCompleteRef = useRef(onComplete);

  useEffect(() => {
    onCompleteRef.current = onComplete;
  }, [onComplete]);

  const press = useCallback((btn: ComboButton) => {
    const next = [...comboRef.current, btn];
    if (next.length === COMBO_LENGTH) {
      comboRef.current = [];
      setCount(0);
      setTimeout(() => onCompleteRef.current(next), 0);
    } else {
      comboRef.current = next;
      setCount(next.length);
    }
  }, []);

  const backspace = useCallback(() => {
    const next = comboRef.current.slice(0, -1);
    comboRef.current = next;
    setCount(next.length);
  }, []);

  // Suppress global B-button back navigation while combo entry is active
  useEffect(() => {
    const comboWindow = window as ComboWindow;
    comboWindow.__dsmComboEntryActive = true;
    return () => { comboWindow.__dsmComboEntryActive = false; };
  }, []);

  // Physical StateBoy shell buttons (dispatch from public/index.html)
  useEffect(() => {
    const handler = (e: Event) => {
      const btn = (e as CustomEvent<string>).detail;
      if (VALID_BUTTONS.has(btn)) press(btn as ComboButton);
    };
    window.addEventListener('sb-btn', handler);
    return () => window.removeEventListener('sb-btn', handler);
  }, [press]);

  // Keyboard fallback — dev/desktop only
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const action = KEY_MAP[e.key];
      if (!action) return;
      e.preventDefault();
      if (action === '__back') { backspace(); return; }
      press(action);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [press, backspace]);

  return (
    <div className="combo-input">
      {label && <div className="combo-label">{label}</div>}

      {/* Count-only dots — no button labels for security */}
      <div className="combo-dots" aria-label={`${count} of ${COMBO_LENGTH} buttons pressed`}>
        {Array.from({ length: COMBO_LENGTH }).map((_, i) => (
          <span key={i} className={`combo-dot${i < count ? ' combo-dot--filled' : ''}`}>
            {i < count ? '●' : '○'}
          </span>
        ))}
      </div>

      <div className="combo-hint">
        {count === 0 && 'PRESS CONTROLLER BUTTONS'}
        {count > 0 && count < COMBO_LENGTH && `${COMBO_LENGTH - count} MORE`}
      </div>

      {count > 0 && (
        <button className="combo-back-btn" onClick={backspace} aria-label="Undo last button">⌫</button>
      )}
    </div>
  );
}
