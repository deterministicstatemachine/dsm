// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, items 1 and 2: every screen that shows or takes a recovery
// phrase asks the phone for the secret guard while it is up (no screenshot,
// recording or Recents thumbnail, a keyboard that learns nothing) and lets it
// go after; the ring backup offers the words to no clipboard; and a phrase is
// typed into fields that autocomplete, autocorrect and capitalise nothing.

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import NfcRecoveryScreen from '../NfcRecoveryScreen';
import RecoveryScreen from '../RecoveryScreen';
import RecoveryPhraseScreen from '../RecoveryPhraseScreen';
import ModernPhrase from '../../modern/ModernPhrase';
import { recoveryPhraseStore } from '../../../runtime/recoveryPhraseStore';
import { appState, installScriptedPhone, removeScriptedPhone, settle } from '../../../tests/helpers/scriptedPhone';

const WORDS = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent',
  'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
  'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
  'across', 'act', 'action', 'actor', 'actress', 'actual',
];

const SECRET = 1;

// A device with no ring backup: no capsule, and none of the status flags
// (enabled, configured, pending) named, which getNfcBackupStatus reads as off.
const NO_BACKUP = appState('capsule_count=0,last_capsule_index=0');

afterEach(() => {
  recoveryPhraseStore.clear();
  removeScriptedPhone();
});

function expectNonLearning(field: HTMLElement): void {
  expect(field).toHaveAttribute('autocomplete', 'off');
  expect(field).toHaveAttribute('autocorrect', 'off');
  expect(field).toHaveAttribute('autocapitalize', 'none');
}

describe('the ring backup screen', () => {
  it('guards the screen, lists a new mnemonic for paper only, and lets the guard go after', async () => {
    const phone = installScriptedPhone({
      'recovery.status': NO_BACKUP,
      'recovery.capsulePreview': appState('none'),
      'recovery.generateMnemonic': appState(WORDS.join(' ')),
    });
    const { unmount } = render(<NfcRecoveryScreen />);
    await act(settle);
    expect(phone.guards).toEqual([SECRET]);

    fireEvent.click(await screen.findByRole('button', { name: 'Set up' }));
    fireEvent.click(screen.getByRole('button', { name: 'Generate new mnemonic' }));
    const words = await screen.findByRole('list', { name: 'Generated mnemonic' });
    expect(Array.from(words.querySelectorAll('li')).map((li) => li.textContent)).toEqual(
      WORDS.map((word, index) => `${index + 1}${word}`),
    );
    expect(screen.queryByRole('button', { name: /copy/i })).toBeNull();
    expect(screen.queryByRole('textbox', { name: 'Generated mnemonic' })).toBeNull();

    unmount();
    await act(settle);
    expect(phone.guards).toEqual([SECRET, 0]);
  });

  it('takes an existing mnemonic in a field that learns nothing', async () => {
    installScriptedPhone({ 'recovery.status': NO_BACKUP, 'recovery.capsulePreview': appState('none') });
    render(<NfcRecoveryScreen />);
    fireEvent.click(await screen.findByRole('button', { name: 'Set up' }));
    fireEvent.click(screen.getByRole('button', { name: 'Enter existing mnemonic' }));
    expectNonLearning(screen.getByLabelText('Recovery mnemonic'));
  });
});

describe('the ring recovery screen', () => {
  it('guards the screen and takes the mnemonic in a field that learns nothing', async () => {
    const phone = installScriptedPhone({ 'recovery.capsulePreview': appState('none') });
    const { unmount } = render(<RecoveryScreen />);
    await act(settle);
    expect(phone.guards).toEqual([SECRET]);
    expectNonLearning(screen.getByLabelText('The words that encrypted the ring capsule'));
    unmount();
    await act(settle);
    expect(phone.guards).toEqual([SECRET, 0]);
  });
});

describe("a new wallet's phrase", () => {
  it.each([
    ['on the StateBoy frame', () => <RecoveryPhraseScreen onCancel={recoveryPhraseStore.clear} onAnswer={() => Promise.resolve()} />],
    ['in the Modern skin', () => <ModernPhrase onCancel={recoveryPhraseStore.clear} onAnswer={() => Promise.resolve()} />],
  ])('is guarded while it is shown %s', async (_where, draw) => {
    recoveryPhraseStore.begin(WORDS.join(' '));
    const phone = installScriptedPhone({});
    const { unmount } = render(draw());
    await act(settle);
    expect(phone.guards).toEqual([SECRET]);
    unmount();
    await act(settle);
    expect(phone.guards).toEqual([SECRET, 0]);
  });
});
