// SPDX-License-Identifier: Apache-2.0
// The Modern skin from the first screen: the skin each phase is drawn in, the
// welcome screen of a phone with no wallet, and a new wallet's recovery phrase.

import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import ModernBoot from '../ModernBoot';
import { skinInUse } from '../../../hooks/useSkin';
import { recoveryPhraseStore } from '../../../runtime/recoveryPhraseStore';
import type { AppState, ScreenType } from '../../../types/app';

const WORDS = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent',
  'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
  'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
  'across', 'act', 'action', 'actor', 'actress', 'actual',
];

type Harness = { created: number; went: ScreenType[]; picked: string[]; cancelled: number };

function boot(appState: AppState, currentScreen: ScreenType = 'home'): Harness {
  const h: Harness = { created: 0, went: [], picked: [], cancelled: 0 };
  render(
    <ModernBoot
      appState={appState}
      error={null}
      securingProgress={40}
      currentScreen={currentScreen}
      navigate={(to) => { h.went.push(to); }}
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
      eraTokenSrc=""
      btcLogoSrc=""
    />,
  );
  return h;
}

afterEach(() => recoveryPhraseStore.clear());

describe('the skin each phase is drawn in', () => {
  it('is Modern in every phase once chosen, but a combo-locked wallet shows the device', () => {
    const phases: AppState[] = ['loading', 'runtime_loading', 'needs_genesis', 'backup_phrase', 'securing_device', 'publication_pending', 'wallet_ready', 'error'];
    for (const phase of phases) expect(skinInUse('modern', phase, 'none')).toBe('modern');
    expect(skinInUse('modern', 'locked', 'pin')).toBe('modern');
    expect(skinInUse('modern', 'locked', 'combo')).toBe('dgen');
    expect(skinInUse('dgen', 'wallet_ready', 'none')).toBe('dgen');
    expect(skinInUse(null, 'needs_genesis', 'none')).toBe('dgen');
  });
});

describe('a phone with no wallet, in the Modern skin', () => {
  it('welcomes the user and creates the wallet or opens the restore', () => {
    const h = boot('needs_genesis');
    expect(screen.getByRole('heading', { name: 'Welcome to DSM' })).toBeInTheDocument();
    expect(screen.queryByText(/INITIALIZE|GENESIS/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create my wallet' }));
    expect(h.created).toBe(1);
    fireEvent.click(screen.getByRole('button', { name: 'Restore from my recovery ring' }));
    expect(h.went).toEqual(['recovery']);
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
