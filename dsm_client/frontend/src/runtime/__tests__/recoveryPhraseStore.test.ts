// SPDX-License-Identifier: Apache-2.0

import { recoveryPhraseStore } from '../recoveryPhraseStore';
import { CHECKED_WORDS, phraseWords, type Draw } from '../../onboarding/recoveryPhrase';

const PHRASE = [
  'legal', 'winner', 'thank', 'year', 'wave', 'sausage',
  'worth', 'useful', 'legal', 'winner', 'thank', 'yellow',
  'zoo', 'arch', 'brisk', 'crane', 'dwarf', 'ember',
  'fossil', 'glide', 'harbor', 'ivory', 'jungle', 'kettle',
].join(' ');

const firstDraw: Draw = () => 0;

beforeEach(() => {
  recoveryPhraseStore.clear();
});

describe('recoveryPhraseStore', () => {
  it('starts empty and holds a begun phrase from its first page', () => {
    expect(recoveryPhraseStore.getSnapshot().words).toEqual([]);
    recoveryPhraseStore.begin(PHRASE);
    const stage = recoveryPhraseStore.getSnapshot();
    expect(stage.words).toEqual(phraseWords(PHRASE));
    expect(stage.page).toBe(0);
    expect(stage.status).toBe('reading');
    expect(recoveryPhraseStore.mnemonic()).toBe(PHRASE);
  });

  it('pages stay inside the phrase', () => {
    recoveryPhraseStore.begin(PHRASE);
    recoveryPhraseStore.previousPage();
    expect(recoveryPhraseStore.getSnapshot().page).toBe(0);
    for (let i = 0; i < 10; i += 1) recoveryPhraseStore.nextPage();
    expect(recoveryPhraseStore.getSnapshot().page).toBe(3);
    recoveryPhraseStore.previousPage();
    expect(recoveryPhraseStore.getSnapshot().page).toBe(2);
  });

  it('every checked word matched completes the check', () => {
    recoveryPhraseStore.begin(PHRASE);
    recoveryPhraseStore.startChecks(firstDraw);
    const { checks } = recoveryPhraseStore.getSnapshot();
    expect(checks).toHaveLength(CHECKED_WORDS);

    const outcomes = checks.map((check) => recoveryPhraseStore.answer(check.answer));
    expect(outcomes).toEqual(['next', 'next', 'complete']);
    expect(recoveryPhraseStore.getSnapshot().status).toBe('complete');
  });

  it('a wrong word is a miss, and nothing picked after it counts', () => {
    recoveryPhraseStore.begin(PHRASE);
    recoveryPhraseStore.startChecks(firstDraw);
    const [first] = recoveryPhraseStore.getSnapshot().checks;
    const wrong = first.choices.find((word) => word !== first.answer) as string;

    expect(recoveryPhraseStore.answer(wrong)).toBe('mismatch');
    expect(recoveryPhraseStore.getSnapshot().status).toBe('missed');
    expect(recoveryPhraseStore.answer(first.answer)).toBe('not_checking');
    expect(recoveryPhraseStore.getSnapshot().status).toBe('missed');
  });

  it('a word picked while reading does nothing', () => {
    recoveryPhraseStore.begin(PHRASE);
    expect(recoveryPhraseStore.answer('legal')).toBe('not_checking');
    expect(recoveryPhraseStore.getSnapshot().status).toBe('reading');
  });

  it('show again returns to the first page of the same phrase, with no checks', () => {
    recoveryPhraseStore.begin(PHRASE);
    recoveryPhraseStore.nextPage();
    recoveryPhraseStore.startChecks(firstDraw);
    recoveryPhraseStore.answer('not-a-word');
    recoveryPhraseStore.showAgain();

    const stage = recoveryPhraseStore.getSnapshot();
    expect(stage.words).toEqual(phraseWords(PHRASE));
    expect(stage.page).toBe(0);
    expect(stage.checks).toEqual([]);
    expect(stage.status).toBe('reading');
  });

  it('clear forgets the phrase', () => {
    recoveryPhraseStore.begin(PHRASE);
    recoveryPhraseStore.clear();
    expect(recoveryPhraseStore.getSnapshot().words).toEqual([]);
    expect(recoveryPhraseStore.mnemonic()).toBe('');
  });

  it('tells subscribers of every change, until they leave', () => {
    let seen = 0;
    const leave = recoveryPhraseStore.subscribe(() => {
      seen += 1;
    });
    recoveryPhraseStore.begin(PHRASE);
    recoveryPhraseStore.nextPage();
    leave();
    recoveryPhraseStore.nextPage();
    expect(seen).toBe(2);
  });
});
