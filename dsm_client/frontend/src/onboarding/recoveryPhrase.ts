// SPDX-License-Identifier: Apache-2.0
// The recovery phrase a new wallet is created from (Genesis v2: the BIP39
// mnemonic is the wallet's only root), shown a page at a time for the user to
// write down, and the check that they did, before the wallet is created from
// it. Pure: the words live in memory only, and nothing here logs or stores
// them.

/** Words shown on one page of the screen. */
export const PHRASE_PAGE_SIZE = 6;
/** Words the user is asked to pick back out before the wallet is created. */
export const CHECKED_WORDS = 3;
/** Choices offered for each checked word, the right one among them. */
export const CHOICES_PER_CHECK = 4;

/** One word to pick back out: its position in the phrase and the choices. */
export type PhraseCheck = {
  position: number;
  choices: string[];
  answer: string;
};

/**
 * Where the backup stands: reading the pages, picking words back out, a word
 * picked that does not match, or every word matched (the wallet is being
 * created from the phrase).
 */
export type PhraseStatus = 'reading' | 'checking' | 'missed' | 'complete';

export type PhraseStage = {
  words: readonly string[];
  page: number;
  checks: readonly PhraseCheck[];
  checkIndex: number;
  status: PhraseStatus;
};

/** A uniform draw from `[0, bound)`. */
export type Draw = (bound: number) => number;

/** The phrase's words, as the SDK wrote them, one per entry. */
export function phraseWords(mnemonic: string): string[] {
  return mnemonic.trim().split(/\s+/).filter((word) => word.length > 0);
}

export function pageCount(words: readonly string[]): number {
  return Math.ceil(words.length / PHRASE_PAGE_SIZE);
}

/** The words on `page`, each with its position in the phrase. */
export function pageWords(
  words: readonly string[],
  page: number,
): { position: number; word: string }[] {
  const start = page * PHRASE_PAGE_SIZE;
  return words
    .slice(start, start + PHRASE_PAGE_SIZE)
    .map((word, index) => ({ position: start + index, word }));
}

/**
 * `count` distinct entries of `items`, drawn by a partial Fisher-Yates
 * shuffle: one draw per entry taken, so it ends whatever the draws are.
 */
function drawDistinct<T>(items: readonly T[], count: number, draw: Draw): T[] {
  const pool = [...items];
  const taken = Math.min(count, pool.length);
  for (let i = 0; i < taken; i += 1) {
    const j = i + draw(pool.length - i);
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return pool.slice(0, taken);
}

/**
 * The words to pick back out: `CHECKED_WORDS` distinct positions, in phrase
 * order, each with the right word among decoys drawn from the phrase's other
 * words, at a drawn place.
 */
export function buildChecks(words: readonly string[], draw: Draw): PhraseCheck[] {
  const positions = drawDistinct(words.map((_, index) => index), CHECKED_WORDS, draw);
  positions.sort((a, b) => a - b);
  return positions.map((position) => {
    const answer = words[position];
    const others = Array.from(new Set(words.filter((word) => word !== answer)));
    const choices = drawDistinct(others, CHOICES_PER_CHECK - 1, draw);
    choices.splice(draw(choices.length + 1), 0, answer);
    return { position, choices, answer };
  });
}

/** A uniform draw from the platform's CSPRNG, by rejection sampling. */
export function cryptoDraw(bound: number): number {
  const sample = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / bound) * bound;
  for (;;) {
    globalThis.crypto.getRandomValues(sample);
    if (sample[0] < limit) return sample[0] % bound;
  }
}
