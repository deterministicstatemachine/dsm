// SPDX-License-Identifier: Apache-2.0
// A new wallet's recovery phrase, on the StateBoy frame: the words a page at a
// time on the dark card for the user to write down, then three of them picked
// back out before the wallet is created from the phrase. The phrase is the
// only way to recover the wallet; it stays in memory and is never logged.
import React, { useEffect, useMemo } from 'react';
import { InfoTip } from '../common/InfoTip';
import { Notice, ScreenFrame } from '../common/ScreenFrame';
import { useDpadNav } from '../../hooks/useDpadNav';
import { useBackButton } from '../../hooks/useBackButton';
import { CHECKED_WORDS, PHRASE_PAGE_SIZE, cryptoDraw, pageCount, pageWords } from '../../onboarding/recoveryPhrase';
import { recoveryPhraseStore, useRecoveryPhraseStore } from '../../runtime/recoveryPhraseStore';

type Props = {
  /** Leave without creating a wallet; the phrase is forgotten. */
  onCancel: () => void;
  /** A word picked for the current check; the last match creates the wallet. */
  onAnswer: (word: string) => Promise<void>;
};

type Control = {
  key: string;
  label: string;
  className: string;
  onPress: () => void;
};

const PHASES = ['Write down', 'Check', 'Create'] as const;

function PhaseStrip({ phase }: { phase: number }): React.JSX.Element {
  return (
    <div className="sb-steps sb-phrase-steps" aria-label="Wallet setup">
      {PHASES.map((label, index) => {
        const done = index < phase;
        const active = index === phase;
        return (
          <div
            key={label}
            className={`sb-steps__step${done ? ' is-done' : ''}${active ? ' is-active' : ''}`}
            aria-current={active ? 'step' : undefined}
          >
            {label}
          </div>
        );
      })}
    </div>
  );
}

export default function RecoveryPhraseScreen({ onCancel, onAnswer }: Props): React.JSX.Element {
  const stage = useRecoveryPhraseStore();
  const pages = pageCount(stage.words);
  const onLastPage = stage.page >= pages - 1;
  const check = stage.checks[stage.checkIndex];
  const firstOnPage = stage.page * PHRASE_PAGE_SIZE + 1;
  const shown = pageWords(stage.words, stage.page);

  const controls = useMemo<Control[]>(() => {
    switch (stage.status) {
      case 'reading':
        return [
          onLastPage
            ? {
                key: 'wrote',
                label: 'I wrote them down',
                className: 'sb-btn sb-btn--primary sb-btn--block',
                onPress: () => recoveryPhraseStore.startChecks(cryptoDraw),
              }
            : {
                key: 'next',
                label: 'Next words',
                className: 'sb-btn sb-btn--primary sb-btn--block',
                onPress: recoveryPhraseStore.nextPage,
              },
          ...(stage.page > 0
            ? [{ key: 'previous', label: 'Previous', className: 'sb-btn', onPress: recoveryPhraseStore.previousPage }]
            : []),
          { key: 'cancel', label: 'Cancel setup', className: 'sb-btn sb-btn--ghost', onPress: onCancel },
        ];
      case 'checking':
        return [
          ...check.choices.map((word) => ({
            key: `choice-${word}`,
            label: word,
            className: 'sb-btn sb-btn--word',
            onPress: () => {
              onAnswer(word);
            },
          })),
          { key: 'again', label: 'Show phrase again', className: 'sb-btn sb-btn--ghost sb-btn--small sb-btn--block', onPress: recoveryPhraseStore.showAgain },
        ];
      case 'missed':
        return [
          { key: 'again', label: 'Show phrase again', className: 'sb-btn sb-btn--primary sb-btn--block', onPress: recoveryPhraseStore.showAgain },
          { key: 'cancel', label: 'Cancel setup', className: 'sb-btn sb-btn--ghost sb-btn--block', onPress: onCancel },
        ];
      case 'complete':
        return [];
    }
  }, [check, onAnswer, onCancel, onLastPage, stage.page, stage.status]);

  const { focusedIndex, setFocusedIndex } = useDpadNav({
    itemCount: controls.length,
    onSelect: (index) => controls[index]?.onPress(),
  });

  // Each page and each check is a new view: the D-pad starts on its first control.
  useEffect(() => {
    setFocusedIndex(0);
  }, [setFocusedIndex, stage.page, stage.status, stage.checkIndex]);

  // Back (the header chevron and the shell's B) steps back through the pages,
  // from a check to the phrase, and from the first page out of the setup.
  const back = (): void => {
    if (stage.status === 'reading' && stage.page > 0) {
      recoveryPhraseStore.previousPage();
    } else if (stage.status === 'checking' || stage.status === 'missed') {
      recoveryPhraseStore.showAgain();
    } else if (stage.status === 'reading') {
      onCancel();
    }
  };
  useBackButton(stage.words.length > 0 && stage.status !== 'complete', back);

  const button = (control: Control, index: number): React.JSX.Element => (
    <button
      key={control.key}
      type="button"
      className={`${control.className}${index === focusedIndex ? ' focused' : ''}`}
      onClick={control.onPress}
    >
      {control.label}
    </button>
  );

  const info = (
    <InfoTip title="Your recovery phrase">
      <p>These words are the only way to recover this wallet if this phone is lost, reset or replaced. Whoever holds them holds the wallet.</p>
      <p>Write them on paper, in order, and keep the paper somewhere safe. Do not photograph them, type them into anything or share them with anyone.</p>
      <p>Before the wallet is created you pick {CHECKED_WORDS} of them back out, so a word written down wrong is found now and not when you need it.</p>
    </InfoTip>
  );

  if (stage.status === 'complete' || stage.words.length === 0) {
    return (
      <ScreenFrame title="Recovery Phrase" className="recovery-phrase-screen" banner={<PhaseStrip phase={2} />}>
        <div className="sb-empty" aria-live="polite">Creating your wallet{'…'}</div>
      </ScreenFrame>
    );
  }

  if (stage.status === 'reading') {
    const [primary, ...rest] = controls;
    return (
      <ScreenFrame
        title="Recovery Phrase"
        className="recovery-phrase-screen"
        onBack={back}
        info={info}
        banner={<PhaseStrip phase={0} />}
      >
        <section className="sb-card sb-card--dark" aria-label="Recovery phrase">
          <div className="sb-card__title">
            <span>Words {firstOnPage}{'–'}{firstOnPage + shown.length - 1} of {stage.words.length}</span>
            <span>{stage.page + 1} / {pages}</span>
          </div>
          <ol className="sb-phrase">
            {shown.map(({ position, word }) => (
              <li key={position} className="sb-phrase__word">
                <span className="sb-phrase__n">{position + 1}</span>
                <span className="sb-phrase__w">{word}</span>
              </li>
            ))}
          </ol>
        </section>
        <p className="sb-hint">
          Write these words on paper, in order. They are the only way to recover this wallet. Never share them or store them on a device.
        </p>
        {button(primary, 0)}
        <div className="sb-actions">{rest.map((control, index) => button(control, index + 1))}</div>
      </ScreenFrame>
    );
  }

  if (stage.status === 'missed') {
    return (
      <ScreenFrame
        title="Check Your Phrase"
        className="recovery-phrase-screen"
        onBack={back}
        info={info}
        banner={<PhaseStrip phase={1} />}
      >
        <Notice kind="error">
          That is not word #{check.position + 1}. Read your phrase again and correct what you wrote down.
        </Notice>
        <div className="sb-phrase-stack">{controls.map(button)}</div>
      </ScreenFrame>
    );
  }

  const choices = controls.slice(0, -1);
  const again = controls[controls.length - 1];
  return (
    <ScreenFrame
      title="Check Your Phrase"
      className="recovery-phrase-screen"
      onBack={back}
      info={info}
      banner={<PhaseStrip phase={1} />}
    >
      <section className="sb-card sb-card--dark sb-card--hero" aria-live="polite">
        <div className="sb-hero__label">Check {stage.checkIndex + 1} of {stage.checks.length}</div>
        <div className="sb-hero__value">Word #{check.position + 1}</div>
        <div className="sb-hero__sub">Pick the word you wrote down at #{check.position + 1}.</div>
      </section>
      <div className="sb-phrase-choices">{choices.map(button)}</div>
      {button(again, controls.length - 1)}
    </ScreenFrame>
  );
}
