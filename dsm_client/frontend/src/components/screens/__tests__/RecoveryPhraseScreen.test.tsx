// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import RecoveryPhraseScreen from '../RecoveryPhraseScreen';
import { recoveryPhraseStore } from '../../../runtime/recoveryPhraseStore';

const WORDS = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent',
  'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
  'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
  'across', 'act', 'action', 'actor', 'actress', 'actual',
];

type Harness = { picked: string[]; cancelled: number };

function renderScreen(): Harness {
  const harness: Harness = { picked: [], cancelled: 0 };
  render(
    <RecoveryPhraseScreen
      onCancel={() => {
        harness.cancelled += 1;
        recoveryPhraseStore.clear();
      }}
      onAnswer={(word) => {
        harness.picked.push(word);
        recoveryPhraseStore.answer(word);
        return Promise.resolve();
      }}
    />,
  );
  return harness;
}

function phraseCard(): HTMLElement {
  return screen.getByRole('region', { name: 'Recovery phrase' });
}

function wordsShown(): string[] {
  return within(phraseCard())
    .getAllByRole('listitem')
    .map((item) => String(item.textContent));
}

function press(name: string): void {
  fireEvent.click(screen.getByRole('button', { name }));
}

function readToTheEnd(): void {
  press('Next words');
  press('Next words');
  press('Next words');
  press('I wrote them down');
}

beforeEach(() => {
  act(() => {
    recoveryPhraseStore.begin(WORDS.join(' '));
  });
});

afterEach(() => {
  act(() => {
    recoveryPhraseStore.clear();
  });
});

describe('RecoveryPhraseScreen', () => {
  it('shows the phrase six numbered words at a time on the dark card', () => {
    renderScreen();

    expect(screen.getByRole('heading', { name: 'Recovery Phrase' })).toBeTruthy();
    expect(phraseCard().className).toContain('sb-card--dark');
    expect(within(phraseCard()).getByText('Words 1–6 of 24')).toBeTruthy();
    expect(within(phraseCard()).getByText('1 / 4')).toBeTruthy();
    expect(wordsShown()).toEqual(['1abandon', '2ability', '3able', '4about', '5above', '6absent']);
    // Nothing to go back to on the first page.
    expect(screen.queryByRole('button', { name: 'Previous' })).toBeNull();
  });

  it('pages forward and back through all 24 words', () => {
    renderScreen();

    press('Next words');
    expect(wordsShown()[0]).toBe('7absorb');
    press('Previous');
    expect(wordsShown()[0]).toBe('1abandon');

    press('Next words');
    press('Next words');
    press('Next words');
    expect(within(phraseCard()).getByText('Words 19–24 of 24')).toBeTruthy();
    expect(wordsShown()[5]).toBe('24actual');
    expect(screen.queryByRole('button', { name: 'Next words' })).toBeNull();
    expect(screen.getByRole('button', { name: 'I wrote them down' })).toBeTruthy();
  });

  it('asks for the checked words back, and hands each pick to the flow', () => {
    const harness = renderScreen();
    readToTheEnd();

    const { checks } = recoveryPhraseStore.getSnapshot();
    expect(screen.getByRole('heading', { name: 'Check Your Phrase' })).toBeTruthy();
    expect(screen.queryByRole('region', { name: 'Recovery phrase' })).toBeNull();

    checks.forEach((check, index) => {
      expect(screen.getByText(`Check ${index + 1} of ${checks.length}`)).toBeTruthy();
      expect(screen.getByText(`Word #${check.position + 1}`)).toBeTruthy();
      for (const choice of check.choices) {
        expect(screen.getByRole('button', { name: choice })).toBeTruthy();
      }
      press(check.answer);
    });

    expect(harness.picked).toEqual(checks.map((check) => check.answer));
    expect(screen.getByText('Creating your wallet…')).toBeTruthy();
    // The phrase is off the screen while the wallet is created from it.
    expect(screen.queryByText('abandon')).toBeNull();
  });

  it('a wrong pick says so and sends the user back to the phrase', () => {
    renderScreen();
    readToTheEnd();

    const [first] = recoveryPhraseStore.getSnapshot().checks;
    const wrong = first.choices.find((word) => word !== first.answer) as string;
    press(wrong);

    expect(screen.getByRole('alert').textContent).toContain(`That is not word #${first.position + 1}.`);
    press('Show phrase again');
    expect(wordsShown()[0]).toBe('1abandon');
  });

  it('cancel leaves the setup', () => {
    const harness = renderScreen();
    press('Cancel setup');
    expect(harness.cancelled).toBe(1);
  });

  it('the header back steps back a page before it leaves the setup', () => {
    const harness = renderScreen();
    press('Next words');
    press('Back');
    expect(wordsShown()[0]).toBe('1abandon');
    expect(harness.cancelled).toBe(0);
    press('Back');
    expect(harness.cancelled).toBe(1);
  });
});
