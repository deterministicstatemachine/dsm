// SPDX-License-Identifier: Apache-2.0
// A new wallet's recovery phrase in the Modern skin: the same steps as the
// Game Boy's (runtime/recoveryPhraseStore): the words a page at a time to
// write down, then a few picked back out before the wallet is created from
// the phrase. The phrase stays in memory and is never logged.

import React from 'react';
import { CHECKED_WORDS, cryptoDraw, pageCount, pageWords, PHRASE_PAGE_SIZE } from '../../onboarding/recoveryPhrase';
import { recoveryPhraseStore, useRecoveryPhraseStore } from '../../runtime/recoveryPhraseStore';
import logger from '../../utils/logger';

const STEPS = ['Write down', 'Check', 'Create'] as const;

function Steps({ at }: { at: number }): React.JSX.Element {
  return (
    <div className="s-seg" role="list" aria-label="Wallet setup" style={{ marginBottom: 14 }}>
      {STEPS.map((label, index) => (
        <span key={label} role="listitem" className="s-step" aria-current={index === at ? 'step' : undefined}>
          {index < at ? '✓ ' : ''}{label}
        </span>
      ))}
    </div>
  );
}

export default function ModernPhrase({ onCancel, onAnswer }: { onCancel: () => void; onAnswer: (word: string) => Promise<void> }): React.JSX.Element {
  const stage = useRecoveryPhraseStore();

  if (stage.status === 'complete' || stage.words.length === 0) {
    return (
      <>
        <h1 className="s-title">Your recovery phrase</h1>
        <Steps at={2} />
        <div className="s-empty" aria-live="polite">Creating your wallet…</div>
      </>
    );
  }

  if (stage.status === 'reading') {
    const pages = pageCount(stage.words);
    const first = stage.page * PHRASE_PAGE_SIZE + 1;
    const shown = pageWords(stage.words, stage.page);
    const last = stage.page >= pages - 1;
    return (
      <>
        <h1 className="s-title">Your recovery phrase</h1>
        <Steps at={0} />
        <p className="s-hint">
          Write these words on paper, in order. They are the only way to get this wallet back if this phone is lost or reset.
          Never share them, photograph them or type them anywhere.
        </p>
        <section className="s-card" aria-label="Recovery phrase">
          <div className="s-row-sub" style={{ marginBottom: 10 }}>
            Words {first}–{first + shown.length - 1} of {stage.words.length} · page {stage.page + 1} of {pages}
          </div>
          <ol className="s-words">
            {shown.map(({ position, word }) => (
              <li key={position}><span>{position + 1}</span>{word}</li>
            ))}
          </ol>
        </section>
        <div className="s-stack">
          {last ? (
            <button type="button" className="s-btn s-btn-primary" onClick={() => recoveryPhraseStore.startChecks(cryptoDraw)}>I wrote them down</button>
          ) : (
            <button type="button" className="s-btn s-btn-primary" onClick={recoveryPhraseStore.nextPage}>Next words</button>
          )}
          {stage.page > 0 ? <button type="button" className="s-btn s-btn-quiet" onClick={recoveryPhraseStore.previousPage}>Previous</button> : null}
          <button type="button" className="s-btn s-btn-quiet" onClick={onCancel}>Cancel setup</button>
        </div>
      </>
    );
  }

  const check = stage.checks[stage.checkIndex];

  if (stage.status === 'missed') {
    return (
      <>
        <h1 className="s-title">Check your phrase</h1>
        <Steps at={1} />
        <div className="s-notice s-error">That is not word #{check.position + 1}. Read your phrase again and correct what you wrote down.</div>
        <div className="s-stack">
          <button type="button" className="s-btn s-btn-primary" onClick={recoveryPhraseStore.showAgain}>Show my phrase again</button>
          <button type="button" className="s-btn s-btn-quiet" onClick={onCancel}>Cancel setup</button>
        </div>
      </>
    );
  }

  return (
    <>
      <h1 className="s-title">Check your phrase</h1>
      <Steps at={1} />
      <section className="s-card s-balance" aria-live="polite">
        <div className="s-balance-label">Check {stage.checkIndex + 1} of {stage.checks.length}</div>
        <div className="s-balance-amount" style={{ fontSize: 34 }}>Word #{check.position + 1}</div>
        <div className="s-row-sub">Tap the word you wrote down at #{check.position + 1}. You pick {CHECKED_WORDS} in all.</div>
      </section>
      <div className="s-word-choices">
        {check.choices.map((word) => (
          <button
            key={word}
            type="button"
            className="s-btn s-btn-quiet"
            onClick={() => {
              onAnswer(word).then(
                () => undefined,
                (e: unknown) => logger.warn('[phrase] the answer was not taken:', e),
              );
            }}
          >
            {word}
          </button>
        ))}
      </div>
      <button type="button" className="s-btn s-btn-quiet" style={{ marginTop: 12 }} onClick={recoveryPhraseStore.showAgain}>Show my phrase again</button>
    </>
  );
}
