// SPDX-License-Identifier: Apache-2.0
/**
 * PinInput — numeric PIN keypad with dot display.
 * Layout: 1–9, *, 0, # (3×4 grid)
 *  * = backspace  # = confirm
 * Emits onComplete(pin) when the user presses # with ≥4 digits.
 */

import React, { useState } from 'react';

interface Props {
  /** Called when user confirms entry with ≥4 digits */
  onComplete: (pin: string) => void;
  /** Optional: show alternate label (e.g. "CONFIRM PIN") */
  label?: string;
}

const KEYS = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '0', '#'];
const MAX_DIGITS = 8;

export default function PinInput({ onComplete, label }: Props) {
  const [digits, setDigits] = useState('');

  const handleKey = (k: string) => {
    if (k === '*') {
      setDigits((prev) => prev.slice(0, -1));
      return;
    }
    if (k === '#') {
      if (digits.length >= 4) {
        onComplete(digits);
        setDigits('');
      }
      return;
    }
    if (digits.length < MAX_DIGITS) {
      setDigits((prev) => prev + k);
    }
  };

  const hint = digits.length === 0
    ? 'ENTER PIN — PRESS ✓ TO CONFIRM'
    : digits.length < 4
      ? 'MIN 4 DIGITS — PRESS ✓ TO CONFIRM'
      : 'PRESS ✓ TO CONFIRM';

  return (
    <div className="sb-keypad">
      {label && <div className="sb-keypad__label">{label}</div>}
      <div className="sb-keypad__dots" aria-label={`${digits.length} digits entered`}>
        {Array.from({ length: MAX_DIGITS }).map((_, i) => (
          <span key={i} className={`sb-keypad__dot${i < digits.length ? ' is-filled' : ''}`} />
        ))}
      </div>
      <div className={`sb-keypad__hint${digits.length >= 4 ? ' is-ready' : ''}`}>{hint}</div>
      <div className="sb-keypad__grid" role="group" aria-label="PIN keypad">
        {KEYS.map((k) => (
          <button
            key={k}
            type="button"
            className={`sb-keypad__key${k === '#' ? ' sb-keypad__key--confirm' : ''}${k === '*' ? ' sb-keypad__key--back' : ''}`}
            onClick={() => handleKey(k)}
            aria-label={k === '*' ? 'backspace' : k === '#' ? 'confirm' : k}
          >
            {k === '*' ? '⌫' : k === '#' ? '✓' : k}
          </button>
        ))}
      </div>
    </div>
  );
}
