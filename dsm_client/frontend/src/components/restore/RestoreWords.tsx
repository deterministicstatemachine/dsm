// SPDX-License-Identifier: Apache-2.0
// Restoring a wallet from its 24 words (owner, 2026-11-19): the words typed in
// order, on a screen no screenshot, recording or keyboard keeps. The wallet
// comes back from the DSM network as the same wallet, at its last online
// balance. Nothing typed here stays on the page once it is sent or left.

import React, { useState } from 'react';
import { ScreenGuard } from '../common/ScreenGuard';
import { Notice } from '../common/ScreenFrame';

const WORDS = 24;

type Props = {
  error: string | null;
  onRestore: (words: string) => Promise<void>;
  onCancel: () => void;
};

/** The words as typed, lower-cased and one space apart. */
function normalized(text: string): string[] {
  const trimmed = text.trim().toLowerCase();
  return trimmed === '' ? [] : trimmed.split(/\s+/);
}

export default function RestoreWords({ error, onRestore, onCancel }: Props): React.JSX.Element {
  const [text, setText] = useState('');
  const [restoring, setRestoring] = useState<'idle' | 'restoring'>('idle');
  const [failed, setFailed] = useState<string | null>(null);
  const words = normalized(text);
  const shown = failed ?? error;

  const restore = (): Promise<void> => {
    setRestoring('restoring');
    setFailed(null);
    const done = (): void => {
      setText('');
      setRestoring('idle');
    };
    return onRestore(words.join(' ')).then(done, (e: unknown) => {
      done();
      setFailed(e instanceof Error ? e.message : String(e));
    });
  };

  return (
    <div className="sb-screen__body restore-words">
      <ScreenGuard kind="secret" />
      <section className="sb-card">
        <div className="sb-hero__label">Restore a wallet</div>
        <p className="sb-hint">
          Type your 24 words in order, a space between each. Your wallet comes back from the DSM
          network as it stood at its last online balance.
        </p>
        <div className="sb-field">
          <label htmlFor="restore-words">Your 24 words</label>
          <textarea
            id="restore-words"
            className="sb-input sb-input--mono"
            rows={6}
            value={text}
            onChange={(e) => setText(e.target.value)}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="none"
            disabled={restoring === 'restoring'}
          />
        </div>
        <p className="sb-hint" aria-live="polite">
          {words.length} of {WORDS} words
        </p>
        {restoring === 'restoring' ? <Notice>RESTORING FROM THE NETWORK…</Notice> : null}
        {shown !== null && restoring === 'idle' ? <Notice kind="error">{shown}</Notice> : null}
        <button
          type="button"
          className="sb-btn sb-btn--primary sb-btn--block"
          onClick={restore}
          disabled={words.length !== WORDS || restoring === 'restoring'}
        >
          Restore
        </button>
        <button
          type="button"
          className="sb-btn sb-btn--block"
          onClick={onCancel}
          disabled={restoring === 'restoring'}
        >
          Back
        </button>
      </section>
    </div>
  );
}
