// SPDX-License-Identifier: Apache-2.0
// The Modern skin from the first screen: the skin each phase is drawn in, the
// welcome screen of a phone with no wallet, and a new wallet's recovery phrase.

import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import ModernBoot from '../ModernBoot';
import { skinInUse } from '../../../hooks/useSkin';
import { recoveryPhraseStore } from '../../../runtime/recoveryPhraseStore';
import type { AppState } from '../../../types/app';

const WORDS = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent',
  'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
  'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
  'across', 'act', 'action', 'actor', 'actress', 'actual',
];

type Harness = { created: number; picked: string[]; cancelled: number; restoring: number; restored: string[]; leftRestore: number };

function boot(appState: AppState, error: string | null = null): Harness {
  const h: Harness = { created: 0, picked: [], cancelled: 0, restoring: 0, restored: [], leftRestore: 0 };
  render(
    <ModernBoot
      appState={appState}
      error={error}
      securingProgress={40}
      handleGenerateGenesis={() => { h.created += 1; }}
      cancelPhraseBackup={() => {
        h.cancelled += 1;
        recoveryPhraseStore.clear();
      }}
      answerPhraseCheck={(word) => {
        h.picked.push(word);
        recoveryPhraseStore.answer(word);
        return Promise.resolve();
      }}
      restore={{
        begin: () => { h.restoring += 1; },
        cancel: () => { h.leftRestore += 1; },
        submit: (words) => {
          h.restored.push(words);
          return Promise.resolve();
        },
      }}
      eraTokenSrc=""
      btcLogoSrc=""
    />,
  );
  return h;
}

afterEach(() => recoveryPhraseStore.clear());

describe('the skin each phase is drawn in', () => {
  it('is Modern in every phase once chosen, but a combo-locked wallet shows the device', () => {
    const phases: AppState[] = ['loading', 'runtime_loading', 'needs_genesis', 'backup_phrase', 'restore_phrase', 'securing_device', 'publication_pending', 'wallet_ready', 'error'];
    for (const phase of phases) expect(skinInUse('modern', phase, 'none')).toBe('modern');
    expect(skinInUse('modern', 'locked', 'pin')).toBe('modern');
    expect(skinInUse('modern', 'locked', 'combo')).toBe('dgen');
    expect(skinInUse('dgen', 'wallet_ready', 'none')).toBe('dgen');
    expect(skinInUse(null, 'needs_genesis', 'none')).toBe('dgen');
  });
});

describe('a phone with no wallet, in the Modern skin', () => {
  it('welcomes the user and creates the wallet', () => {
    const h = boot('needs_genesis');
    expect(screen.getByRole('heading', { name: 'Welcome to DSM' })).toBeInTheDocument();
    expect(screen.queryByText(/INITIALIZE|GENESIS/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create my wallet' }));
    expect(h.created).toBe(1);
  });

  it('shows securing as progress, in plain words', () => {
    boot('securing_device');
    expect(screen.getByRole('progressbar', { name: 'Securing your phone' })).toHaveAttribute('aria-valuenow', '40');
    expect(screen.getByText(/This only happens once/)).toBeInTheDocument();
  });
});

describe('a new wallet\'s recovery phrase, in the Modern skin', () => {
  it('shows the words a page at a time, then checks them, and a wrong pick is caught', () => {
    recoveryPhraseStore.begin(WORDS.join(' '));
    const h = boot('backup_phrase');
    const card = () => screen.getByRole('region', { name: 'Recovery phrase' });
    expect(within(card()).getAllByRole('listitem')[0]).toHaveTextContent('1abandon');
    for (let page = 0; page < 3; page += 1) fireEvent.click(screen.getByRole('button', { name: 'Next words' }));
    fireEvent.click(screen.getByRole('button', { name: 'I wrote them down' }));

    expect(screen.getByRole('heading', { name: 'Check your phrase' })).toBeInTheDocument();
    const asked = Number(String(screen.getByText(/^Word #\d+$/).textContent).replace('Word #', ''));
    const wrong = WORDS.find((w, i) => i !== asked - 1 && screen.queryByRole('button', { name: w }) !== null);
    expect(wrong).toBeDefined();
    fireEvent.click(screen.getByRole('button', { name: String(wrong) }));
    expect(h.picked).toEqual([wrong]);
    expect(screen.getByText(`That is not word #${asked}. Read your phrase again and correct what you wrote down.`)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel setup' }));
    expect(h.cancelled).toBe(1);
  });
});

describe('restoring a wallet from its 24 words, in the Modern skin', () => {
  it('offers the restore right under creating a wallet', () => {
    const h = boot('needs_genesis');
    const buttons = screen.getAllByRole('button').map((b) => b.textContent);
    expect(buttons.indexOf('Restore my wallet from its 24 words')).toBe(
      buttons.indexOf('Create my wallet') + 1,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Restore my wallet from its 24 words' }));
    expect(h.restoring).toBe(1);
    expect(h.created).toBe(0);
  });

  it('restores only once all 24 words are typed, sent lower-cased one space apart', () => {
    const h = boot('restore_phrase');
    const field = screen.getByLabelText('Your 24 words');
    const restore = screen.getByRole('button', { name: 'Restore' });
    fireEvent.change(field, { target: { value: WORDS.slice(0, 23).join(' ') } });
    expect(screen.getByText('23 of 24 words')).toBeInTheDocument();
    expect(restore).toBeDisabled();
    fireEvent.change(field, { target: { value: `  ${WORDS.join('  \n').toUpperCase()} ` } });
    expect(restore).toBeEnabled();
    fireEvent.click(restore);
    expect(h.restored).toEqual([WORDS.join(' ')]);
  });

  it('shows why a restore was refused, and goes back', () => {
    const h = boot('restore_phrase', 'no wallet made from these words is on the network');
    expect(screen.getByRole('alert')).toHaveTextContent('no wallet made from these words is on the network');
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(h.leftRestore).toBe(1);
  });
});
