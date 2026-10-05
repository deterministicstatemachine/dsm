// SPDX-License-Identifier: Apache-2.0
// The lock screen checks nothing: it sends each try to Rust and shows Rust's
// answer. These tests drive the real screen over the bridge, answered from
// Rust's own record of the lock (ingress.rs,
// the_lock_answers_through_the_ingress_as_the_frontend_records_it): a PIN lock
// whose wrong tries Rust counts, and after the third only the recovery phrase.

import React from 'react';
import { join } from 'path';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { answerFromRustRecord } from '../../../tests/helpers/rustIngressRecord';
import type { Arrival } from '../../../tests/helpers/rustIngressRecord';
import { lockSessionViaRouter } from '../../../dsm/WebViewBridge';
import { nativeSessionStore } from '../../../runtime/nativeSessionStore';
import LockScreen from '../LockScreen';

const RECORD = join(__dirname, 'fixtures/session_lock.ingress.bin');
const carried = (arrivals: Arrival[]): string[] => arrivals.map((a) => a.carried);

/** The BIP39 vectors Rust's record holds: this wallet's phrase, and another's. */
const THIS_WALLET = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ANOTHER_WALLET = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

function enterPin(pin: string) {
  for (const digit of pin) fireEvent.click(screen.getByRole('button', { name: digit }));
  fireEvent.click(screen.getByRole('button', { name: 'confirm' }));
}

function enterPhrase(phrase: string) {
  fireEvent.change(screen.getByLabelText('Recovery phrase'), { target: { value: phrase } });
  fireEvent.click(screen.getByRole('button', { name: 'Open' }));
}

describe('LockScreen', () => {
  let arrivals: Arrival[];
  beforeEach(() => {
    arrivals = answerFromRustRecord(RECORD);
  });

  it("shows Rust's answer to each try, and after the third miss takes only the recovery phrase", async () => {
    // The session as Rust locked it: a PIN lock with every try left.
    await act(async () => {
      await lockSessionViaRouter();
    });
    expect(nativeSessionStore.getSnapshot().lock_status.tries).toEqual(
      expect.objectContaining({ misses_left: 3 }),
    );
    render(<LockScreen />);

    enterPin('0000');
    expect(await screen.findByText('✗ INCORRECT — 2 TRIES LEFT')).toBeInTheDocument();
    enterPin('0001');
    expect(await screen.findByText('✗ INCORRECT — 1 TRY LEFT')).toBeInTheDocument();
    enterPin('0002');
    expect(await screen.findByText('✗ INCORRECT — NO TRIES LEFT')).toBeInTheDocument();

    // No PIN pad is offered now: Rust checks no PIN past the third miss.
    expect(screen.queryByRole('group', { name: 'PIN keypad' })).not.toBeInTheDocument();
    expect(screen.getByText(/recovery phrase opens it now/)).toBeInTheDocument();

    enterPhrase(ANOTHER_WALLET);
    expect(await screen.findByText('That phrase does not open this wallet.')).toBeInTheDocument();
    expect(nativeSessionStore.getSnapshot().lock_status.locked).toBeTruthy();

    enterPhrase(THIS_WALLET);
    // Rust opened the session; the store has it once the POW has played.
    await waitFor(() => expect(nativeSessionStore.getSnapshot().lock_status.locked).toBeFalsy());
    expect(nativeSessionStore.getSnapshot().lock_status.tries).toEqual(
      expect.objectContaining({ misses_left: 3 }),
    );

    // Every try reached Rust; nothing was decided here.
    expect(carried(arrivals)).toEqual([
      'session.lock',
      'session.unlock',
      'session.unlock',
      'session.unlock',
      'session.unlock',
      'session.unlock',
    ]);
  });
});
