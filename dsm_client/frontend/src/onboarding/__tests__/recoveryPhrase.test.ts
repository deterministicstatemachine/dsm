// SPDX-License-Identifier: Apache-2.0

import {
  CHECKED_WORDS,
  CHOICES_PER_CHECK,
  PHRASE_PAGE_SIZE,
  buildChecks,
  cryptoDraw,
  pageCount,
  pageWords,
  phraseWords,
  type Draw,
} from '../recoveryPhrase';

// 24 distinct BIP39 words: the length the SDK generates (256-bit entropy).
const PHRASE = [
  'legal', 'winner', 'thank', 'year', 'wave', 'sausage',
  'worth', 'useful', 'legal', 'winner', 'thank', 'yellow',
  'zoo', 'arch', 'brisk', 'crane', 'dwarf', 'ember',
  'fossil', 'glide', 'harbor', 'ivory', 'jungle', 'kettle',
].join(' ');

/** A draw that walks a fixed sequence, so a check is reproducible. */
function sequenceDraw(values: number[]): Draw {
  let next = 0;
  return (bound) => {
    const value = values[next % values.length] % bound;
    next += 1;
    return value;
  };
}

describe('recovery phrase pages', () => {
  it('splits the phrase on any whitespace, keeping every word in order', () => {
    expect(phraseWords('  legal\twinner \n thank  ')).toEqual(['legal', 'winner', 'thank']);
    expect(phraseWords(PHRASE)).toHaveLength(24);
  });

  it('shows 24 words on four pages of six, numbered by their place in the phrase', () => {
    const words = phraseWords(PHRASE);
    expect(PHRASE_PAGE_SIZE).toBe(6);
    expect(pageCount(words)).toBe(4);
    expect(pageWords(words, 0).map((w) => w.position)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(pageWords(words, 3)).toEqual([
      { position: 18, word: 'fossil' },
      { position: 19, word: 'glide' },
      { position: 20, word: 'harbor' },
      { position: 21, word: 'ivory' },
      { position: 22, word: 'jungle' },
      { position: 23, word: 'kettle' },
    ]);
  });

  it('every word appears on exactly one page', () => {
    const words = phraseWords(PHRASE);
    const shown = Array.from({ length: pageCount(words) }, (_, page) => pageWords(words, page)).flat();
    expect(shown.map((w) => w.word)).toEqual(words);
  });
});

describe('recovery phrase checks', () => {
  it('asks for distinct positions in phrase order, each with its word among distinct choices', () => {
    const words = phraseWords(PHRASE);
    const checks = buildChecks(words, sequenceDraw([17, 3, 11, 5, 2, 8, 1, 13, 7]));

    expect(checks).toHaveLength(CHECKED_WORDS);
    const positions = checks.map((c) => c.position);
    expect(new Set(positions).size).toBe(CHECKED_WORDS);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
    for (const check of checks) {
      expect(check.answer).toBe(words[check.position]);
      expect(check.choices).toHaveLength(CHOICES_PER_CHECK);
      expect(new Set(check.choices).size).toBe(CHOICES_PER_CHECK);
      expect(check.choices.filter((w) => w === check.answer)).toHaveLength(1);
      for (const decoy of check.choices.filter((w) => w !== check.answer)) {
        expect(words).toContain(decoy);
      }
    }
  });

  it('a word the phrase holds twice is never offered as its own decoy', () => {
    // 'legal' sits at positions 0 and 8: a check on either must not offer it twice.
    const words = phraseWords(PHRASE);
    for (let start = 0; start < 24; start += 1) {
      for (const check of buildChecks(words, sequenceDraw([start, 0, 0, 1, 2, 3]))) {
        expect(check.choices.filter((w) => w === check.answer)).toHaveLength(1);
      }
    }
  });

  it('ends whatever the draws are: one draw per word taken', () => {
    let draws = 0;
    const stuck: Draw = () => {
      draws += 1;
      return 0;
    };
    const checks = buildChecks(phraseWords(PHRASE), stuck);
    expect(checks.map((c) => c.position)).toEqual([0, 1, 2]);
    // CHECKED_WORDS positions, then for each check its decoys and the answer's place.
    expect(draws).toBe(CHECKED_WORDS + CHECKED_WORDS * CHOICES_PER_CHECK);
  });

  it('places the answer wherever the draw puts it', () => {
    const words = phraseWords(PHRASE);
    const places = new Set<number>();
    for (let place = 0; place < CHOICES_PER_CHECK; place += 1) {
      const [first] = buildChecks(words, sequenceDraw([0, 0, 0, 0, 0, 0, place]));
      places.add(first.choices.indexOf(first.answer));
    }
    expect(places.size).toBe(CHOICES_PER_CHECK);
  });

  it('draws from the platform CSPRNG inside the bound', () => {
    for (const bound of [1, 2, 3, 24, 2047]) {
      for (let i = 0; i < 50; i += 1) {
        const value = cryptoDraw(bound);
        expect(Math.floor(value)).toBe(value);
        expect(value).toBeGreaterThanOrEqual(0);
        expect(value).toBeLessThan(bound);
      }
    }
  });
});
