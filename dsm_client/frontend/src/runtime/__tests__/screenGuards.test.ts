// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, items 1 and 3: while a screen holds a guard the phone's
// window is asked for it, and when the last holder lets go the phone is asked
// to drop it. The phone is asked one request at a time, so a guard dropped
// while an earlier request is still out is not undone by that request.

import * as pb from '../../proto/dsm_app_pb';
import { setBridgeInstance } from '../../bridge/BridgeRegistry';
import { heldScreenGuards, holdScreenGuard } from '../screenGuards';
import { removeScriptedPhone, settle } from '../../tests/helpers/scriptedPhone';

type BridgeHolder = { DsmBridge: unknown };

/** A phone that holds each answer until the test lets it go, recording what it was asked. */
function slowPhone(): { asked: number[]; answerNext: () => void } {
  const asked: number[] = [];
  const waiting: Array<() => void> = [];
  (window as unknown as BridgeHolder).DsmBridge = {
    sendMessageBin: (requestBytes: Uint8Array): Promise<Uint8Array> => {
      const request = pb.BridgeRpcRequest.fromBinary(requestBytes);
      if (request.method !== 'setScreenGuards' || request.payload.case !== 'bytes') {
        return Promise.reject(new Error(`unexpected ${request.method}`));
      }
      asked.push(request.payload.value.data[0]);
      const ok = new pb.BridgeRpcResponse({ result: { case: 'success', value: new pb.BytesPayload({ data: new Uint8Array(0) }) } });
      return new Promise((resolve) => waiting.push(() => resolve(ok.toBinary())));
    },
  };
  return {
    asked,
    answerNext: () => {
      const next = waiting.shift();
      if (next === undefined) throw new Error('the phone was asked nothing');
      next();
    },
  };
}

afterEach(() => {
  removeScriptedPhone();
  setBridgeInstance(undefined);
});

describe('screen guards', () => {
  it('asks the phone for each guard a screen holds, and to drop it after the last holder', async () => {
    const phone = slowPhone();

    const phrase = holdScreenGuard('secret');
    await settle();
    expect(phone.asked).toEqual([1]);
    phone.answerNext();
    await settle();

    const confirm = holdScreenGuard('confirm');
    await settle();
    expect(phone.asked).toEqual([1, 3]);
    phone.answerNext();
    await settle();

    // A second holder of the same guard: the first letting go keeps it held.
    const second = holdScreenGuard('secret');
    phrase();
    phrase();
    await settle();
    expect(heldScreenGuards()).toBe(3);
    expect(phone.asked).toEqual([1, 3]);

    second();
    await settle();
    expect(phone.asked).toEqual([1, 3, 2]);
    phone.answerNext();
    await settle();

    confirm();
    await settle();
    expect(phone.asked).toEqual([1, 3, 2, 0]);
    phone.answerNext();
    await settle();
    expect(heldScreenGuards()).toBe(0);
  });

  it('sends one request at a time, and the last one is what the screens hold', async () => {
    const phone = slowPhone();

    const shown = holdScreenGuard('secret');
    await settle();
    expect(phone.asked).toEqual([1]);

    // The screen goes away and a confirmation comes up before the phone answered.
    shown();
    const confirm = holdScreenGuard('confirm');
    await settle();
    expect(phone.asked).toEqual([1]);

    phone.answerNext();
    await settle();
    expect(phone.asked).toEqual([1, 2]);
    phone.answerNext();
    await settle();

    confirm();
    await settle();
    expect(phone.asked).toEqual([1, 2, 0]);
    phone.answerNext();
    await settle();
  });
});
