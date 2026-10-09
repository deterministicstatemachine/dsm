// SPDX-License-Identifier: Apache-2.0
// The first screen of a phone that has not chosen how its wallet looks, on
// the Game Boy (the look every phone starts in): Simple in light or dark, or
// Classic. It is the only thing on the screen; picking one switches the whole
// app to it at once, and Settings changes it after.

import React, { useState } from 'react';
import { useDpadNav } from '../hooks/useDpadNav';
import { chooseScheme, chooseSkin } from '../runtime/skinPreferences';
import type { Scheme, Skin } from '../runtime/appRuntimeStore';

type Option = { label: string; detail: string; skin: Skin; scheme: Scheme };

const OPTIONS: Option[] = [
  { label: 'SIMPLE · LIGHT', detail: 'Send, receive and people, in a light wallet.', skin: 'simple', scheme: 'light' },
  { label: 'SIMPLE · DARK', detail: 'The same, in dark colours.', skin: 'simple', scheme: 'dark' },
  { label: 'CLASSIC', detail: 'This Game Boy, with every DSM feature.', skin: 'classic', scheme: 'light' },
];

export default function SkinChoiceScreen(): React.JSX.Element {
  const [problem, setProblem] = useState<string | null>(null);

  const pick = (index: number): void => {
    const option = OPTIONS[index];
    if (option === undefined) return;
    // The colours first, so the Simple skin's first screen is already in them.
    chooseScheme(option.scheme)
      .then(() => chooseSkin(option.skin))
      .then(
        () => setProblem(null),
        (e: unknown) => setProblem(e instanceof Error ? e.message : String(e)),
      );
  };

  const { focusedIndex } = useDpadNav({ itemCount: OPTIONS.length, onSelect: pick });
  const focused = OPTIONS[focusedIndex];

  return (
    <div className="dsm-content dsm-content--home" aria-label="Choose your wallet">
      <div style={{ marginTop: '56px', marginBottom: '6px', fontSize: '12px', color: 'var(--text-dark)', letterSpacing: '1px', textAlign: 'center' }}>
        CHOOSE YOUR WALLET
      </div>
      <div style={{ marginBottom: '16px', fontSize: '9px', color: 'var(--text-dark)', textAlign: 'center', lineHeight: 1.5, padding: '0 12px' }}>
        {focused !== undefined ? focused.detail : ''}
      </div>
      <div className="dsm-menu" role="menu" aria-label="Wallet looks">
        {OPTIONS.map((option, index) => (
          <div
            key={option.label}
            role="menuitem"
            tabIndex={0}
            className={`dsm-menu-item home-brick ${index === focusedIndex ? 'focused' : ''}`}
            onClick={() => pick(index)}
          >
            {option.label}
          </div>
        ))}
      </div>
      <div style={{ marginTop: '14px', fontSize: '8px', color: 'var(--text-dark)', textAlign: 'center', padding: '0 12px' }}>
        YOU CAN CHANGE THIS ANY TIME IN SETTINGS
      </div>
      {problem !== null ? <div style={{ marginTop: '10px', fontSize: '9px', color: 'var(--text-dark)', textAlign: 'center' }}>{problem}</div> : null}
    </div>
  );
}
