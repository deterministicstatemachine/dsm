// SPDX-License-Identifier: Apache-2.0
// The recovery phrase between its generation and the wallet's creation from
// it: held in memory only, never persisted and never logged, and cleared as
// soon as the wallet is created or the backup is cancelled.

import { useSyncExternalStore } from 'react';
import {
  buildChecks,
  pageCount,
  phraseWords,
  type Draw,
  type PhraseStage,
} from '../onboarding/recoveryPhrase';

const EMPTY: PhraseStage = {
  words: [],
  page: 0,
  checks: [],
  checkIndex: 0,
  status: 'reading',
};

/** What picking a word did to the check; outside a check it does nothing. */
export type AnswerOutcome = 'next' | 'complete' | 'mismatch' | 'not_checking';

class RecoveryPhraseStore {
  private stage: PhraseStage = EMPTY;

  private listeners = new Set<() => void>();

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getSnapshot = (): PhraseStage => this.stage;

  /** The phrase as one string, for the wallet's creation. */
  mnemonic = (): string => this.stage.words.join(' ');

  /** A freshly generated phrase, shown from its first page. */
  begin = (mnemonic: string): void => {
    this.set({ ...EMPTY, words: phraseWords(mnemonic) });
  };

  nextPage = (): void => {
    const last = pageCount(this.stage.words) - 1;
    this.set({ ...this.stage, page: Math.min(this.stage.page + 1, last) });
  };

  previousPage = (): void => {
    this.set({ ...this.stage, page: Math.max(this.stage.page - 1, 0) });
  };

  /** The user wrote the phrase down: draw the words to pick back out. */
  startChecks = (draw: Draw): void => {
    this.set({
      ...this.stage,
      checks: buildChecks(this.stage.words, draw),
      checkIndex: 0,
      status: 'checking',
    });
  };

  /** A word picked for the current check. */
  answer = (choice: string): AnswerOutcome => {
    const current = this.stage.checks[this.stage.checkIndex];
    if (this.stage.status !== 'checking' || !current) return 'not_checking';
    if (choice !== current.answer) {
      this.set({ ...this.stage, status: 'missed' });
      return 'mismatch';
    }
    if (this.stage.checkIndex + 1 < this.stage.checks.length) {
      this.set({ ...this.stage, checkIndex: this.stage.checkIndex + 1 });
      return 'next';
    }
    this.set({ ...this.stage, status: 'complete' });
    return 'complete';
  };

  /** Back to the first page, to read the phrase again. */
  showAgain = (): void => {
    this.set({ ...EMPTY, words: this.stage.words });
  };

  /** Forget the phrase. */
  clear = (): void => {
    this.set(EMPTY);
  };

  private set(stage: PhraseStage): void {
    this.stage = stage;
    this.listeners.forEach((listener) => listener());
  }
}

export const recoveryPhraseStore = new RecoveryPhraseStore();

export function useRecoveryPhraseStore(): PhraseStage {
  return useSyncExternalStore(
    recoveryPhraseStore.subscribe,
    recoveryPhraseStore.getSnapshot,
    recoveryPhraseStore.getSnapshot,
  );
}
