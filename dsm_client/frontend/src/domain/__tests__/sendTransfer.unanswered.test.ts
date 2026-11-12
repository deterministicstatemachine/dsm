// SPDX-License-Identifier: Apache-2.0
// A send that was handed to Rust and brought back nothing that can be read is
// not a refusal: it may have been made. Both skins' send reports it as
// unknown, and reports as refused only what Rust refused. Each case runs the
// production send over the production transport, against a phone that answers
// the way the test scripts it.

import * as pb from '../../proto/dsm_app_pb';
import { sendTransfer } from '../sendTransfer';
import { appState, installScriptedPhone, removeScriptedPhone, type Answer } from '../../tests/helpers/scriptedPhone';
import { encodeBase32Crockford } from '../../utils/textId';

const to = encodeBase32Crockford(new Uint8Array(32).fill(7));
const request = { to, tokenId: 'ERA', amount: '5', note: '' };

/** Rust's own no, as the router answers it. */
function refusal(message: string): Answer {
  return { case: 'error', value: new pb.Error({ code: 460, message }) };
}

afterEach(removeScriptedPhone);

describe('an online send', () => {
  test('that the phone never answers is unknown', async () => {
    installScriptedPhone({});
    const outcome = await sendTransfer({ ...request, mode: 'online' });
    expect(outcome.kind).toBe('unknown');
  });

  test('answered with something that is not a send answer is unknown', async () => {
    installScriptedPhone({ 'wallet.sendSmart': appState('not a transfer answer') });
    const outcome = await sendTransfer({ ...request, mode: 'online' });
    expect(outcome.kind).toBe('unknown');
  });

  test('that Rust refuses is refused, with its reason', async () => {
    installScriptedPhone({ 'wallet.sendSmart': refusal('insufficient balance') });
    const outcome = await sendTransfer({ ...request, mode: 'online' });
    expect(outcome).toEqual({ kind: 'refused', message: 'DSM error: insufficient balance' });
  });
});

describe('an offline send', () => {
  test('that the phone never answers is unknown', async () => {
    installScriptedPhone({});
    const outcome = await sendTransfer({ ...request, mode: 'offline' });
    expect(outcome.kind).toBe('unknown');
  });

  // Rust's answer of another shape is Rust's answer: refused as what it is
  // (dsm/__tests__/offlineSend.test.ts), not an answer that never came.
  test('answered with an envelope that is not a prepare answer is refused', async () => {
    installScriptedPhone({ 'wallet.sendOffline': appState('not a prepare answer') });
    const outcome = await sendTransfer({ ...request, mode: 'offline' });
    expect(outcome).toEqual({ kind: 'refused', message: 'offlineSend: unexpected payload case appStateResponse' });
  });

  test('that Rust refuses is refused, with its reason', async () => {
    installScriptedPhone({ 'wallet.sendOffline': refusal('no offline allocation') });
    const outcome = await sendTransfer({ ...request, mode: 'offline' });
    expect(outcome).toEqual({ kind: 'refused', message: 'offlineSend: no offline allocation' });
  });
});
