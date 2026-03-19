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
    if (digits.length < 8) {
      setDigits((prev) => prev + k);
    }
  };

  const dots = Array.from({ length: 8 }).map((_, i) =>
    i < digits.length ? '●' : '○'
  );

  return (
    <div className="pin-input">
      {label && <div className="pin-label">{label}</div>}
      <div className="pin-dots" aria-label={`${digits.length} digits entered`}>
        {dots.map((d, i) => (
          <span key={i} className="pin-dot">{d}</span>
        ))}
      </div>
      {digits.length < 4 && digits.length > 0 && (
        <div className="pin-hint">MIN 4 DIGITS — PRESS ✓ TO CONFIRM</div>
      )}
      {digits.length === 0 && (
        <div className="pin-hint">ENTER PIN — PRESS ✓ TO CONFIRM</div>
      )}
      {digits.length >= 4 && (
        <div className="pin-hint pin-hint--ready">PRESS ✓ TO CONFIRM</div>
      )}
      <div className="pin-grid" role="group" aria-label="PIN keypad">
        {KEYS.map((k) => (
          <button
            key={k}
            className={`pin-key${k === '#' ? ' pin-key--confirm' : ''}${k === '*' ? ' pin-key--back' : ''}`}
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
