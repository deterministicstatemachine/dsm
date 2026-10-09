// SPDX-License-Identifier: Apache-2.0
// The first screen of a phone that has not chosen how its wallet looks, on
// the Game Boy (the look every phone starts in): Simple in light or dark, or
// Classic. It comes before setup and is the only thing on the screen; picking
// one switches the whole app to it at once, and Settings changes it after.

import React, { useState } from 'react';
import { useDpadNav } from '../hooks/useDpadNav';
import { chooseScheme, chooseSkin } from '../runtime/skinPreferences';
import type { Scheme, Skin } from '../runtime/appRuntimeStore';
import { ScreenFrame } from './common/ScreenFrame';

type Option = { label: string; detail: string; skin: Skin; scheme: Scheme };

const OPTIONS: Option[] = [
  { label: 'Simple · Light', detail: 'A plain wallet: send, receive and people. Light colours.', skin: 'simple', scheme: 'light' },
  { label: 'Simple · Dark', detail: 'The same plain wallet, in dark colours.', skin: 'simple', scheme: 'dark' },
  { label: 'Classic', detail: 'This Game Boy, with every DSM feature.', skin: 'classic', scheme: 'light' },
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

  return (
    <ScreenFrame title="Choose Your Wallet">
      <p className="sb-hint">How should your wallet look? This comes before setup. You can change it any time in Settings.</p>
      <div role="menu" aria-label="Wallet looks">
        {OPTIONS.map((option, index) => (
          <section key={option.label} className="sb-card">
            <button
              type="button"
              role="menuitem"
              className={`sb-btn sb-btn--block${index === 0 ? ' sb-btn--primary' : ''}${index === focusedIndex ? ' focused' : ''}`}
              onClick={() => pick(index)}
            >
              {option.label}
            </button>
            <p className="sb-hint sb-hint--tight">{option.detail}</p>
          </section>
        ))}
      </div>
      {problem !== null ? <p className="sb-hint">{problem}</p> : null}
    </ScreenFrame>
  );
}
