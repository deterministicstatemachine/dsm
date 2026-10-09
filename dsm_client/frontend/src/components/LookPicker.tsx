// SPDX-License-Identifier: Apache-2.0
// The first thing a phone that has not chosen its look sees, before setup: a
// small plain box in the middle of the screen that stays the same whatever is
// picked, while the app behind it changes to the look picked, so each can be
// seen before it is kept. Modern or DGen (the Game Boy); dark mode and Simple
// mode, both Modern's; OK keeps it. Settings changes it after.

import React, { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { useDpadNav } from '../hooks/useDpadNav';
import { keepLook } from '../runtime/skinPreferences';
import { appRuntimeStore, type Look } from '../runtime/appRuntimeStore';
import '../styles/lookPicker.css';

/** What a phone sees first, before anything is picked: the Game Boy it starts in. */
const FIRST: Look = { skin: 'dgen', scheme: 'light', simpleMode: 'off' };

export default function LookPicker(): React.JSX.Element {
  const [look, setLook] = useState<Look>(() => appRuntimeStore.getSnapshot().lookPreview ?? FIRST);
  const [keeping, setKeeping] = useState<'idle' | 'keeping'>('idle');
  const [problem, setProblem] = useState<string | null>(null);

  // The app behind the box follows the look picked.
  useEffect(() => {
    appRuntimeStore.setLookPreview(look);
  }, [look]);

  const ok = (): void => {
    setKeeping('keeping');
    keepLook(look).then(
      () => setProblem(null),
      (e: unknown) => {
        setKeeping('idle');
        setProblem(e instanceof Error ? e.message : String(e));
      },
    );
  };

  const actions: (() => void)[] = [
    () => setLook({ ...look, skin: 'modern' }),
    () => setLook({ ...look, skin: 'dgen' }),
    () => setLook({ ...look, scheme: look.scheme === 'dark' ? 'light' : 'dark' }),
    () => setLook({ ...look, simpleMode: look.simpleMode === 'on' ? 'off' : 'on' }),
    ok,
  ];
  const { focusedIndex } = useDpadNav({ itemCount: actions.length, onSelect: (i) => actions[i]?.() });
  const focus = (i: number): string => (i === focusedIndex ? ' lp-focused' : '');

  return createPortal(
    <div className="lp-backdrop">
      <div className="lp-box" role="dialog" aria-labelledby="lp-title">
        <h2 id="lp-title" className="lp-title">Choose your look</h2>
        <div className="lp-pair" role="radiogroup" aria-label="Look">
          <button type="button" role="radio" aria-checked={look.skin === 'modern'} className={`lp-btn${focus(0)}`} onClick={actions[0]}>
            Modern
          </button>
          <button type="button" role="radio" aria-checked={look.skin === 'dgen'} className={`lp-btn${focus(1)}`} onClick={actions[1]}>
            DGen
          </button>
        </div>
        <button type="button" role="switch" aria-checked={look.scheme === 'dark'} className={`lp-switch${focus(2)}`} onClick={actions[2]}>
          <span>Dark mode</span><span className="lp-knob" aria-hidden />
        </button>
        <button type="button" role="switch" aria-checked={look.simpleMode === 'on'} className={`lp-switch${focus(3)}`} onClick={actions[3]}>
          <span>Simple mode</span><span className="lp-knob" aria-hidden />
        </button>
        <p className="lp-note">Dark mode and Simple mode are for Modern. Simple mode hides trading, storage and the Bitcoin bridge.</p>
        <p className="lp-note">DGen: press SELECT to change the screen colour and backlight.</p>
        <button type="button" className={`lp-btn lp-ok${focus(4)}`} disabled={keeping === 'keeping'} onClick={ok}>
          OK
        </button>
        {problem !== null ? <p className="lp-note" role="alert">{problem}</p> : null}
      </div>
    </div>,
    document.body,
  );
}
