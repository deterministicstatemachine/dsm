// SPDX-License-Identifier: Apache-2.0
// The home screen's chameleon with mail waiting: each time the home screen
// comes up he puts his tongue out, from the start of the animation, and holds
// an envelope on it until it is tapped; the tap opens the b0x inbox, which
// reports the mail seen. With nothing waiting he plays his loop.

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import * as pb from '../../proto/dsm_app_pb';
import HomeChameleon, { TONGUE_OUT_MS } from '../HomeChameleon';
import InboxOverlay from '../screens/wallet/InboxOverlay';
import { askForInbox } from '../screens/wallet/inboxAsk';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import { installScriptedPhone, removeScriptedPhone, settle } from '../../tests/helpers/scriptedPhone';

afterEach(removeScriptedPhone);

const LOOP = 'images/vaulthunters/chameleon-pink.GIF';

function received(id: string): pb.TransactionInfo {
  return new pb.TransactionInfo({
    id,
    fromDeviceId: new Uint8Array(32).fill(0x11),
    toDeviceId: new Uint8Array(32).fill(0x22),
    tokenId: 'ERA',
    amount: 5n,
    txHash: new Uint8Array(32).fill(0x33),
    direction: pb.AmountDirection.CREDIT,
    txType: pb.TransactionType.TX_TYPE_BILATERAL_OFFLINE,
    status: 'completed',
    recipient: 'peer',
    displayAmount: '5',
  });
}

/** A phone whose Rust holds `mail` as the transfers not yet seen. */
function phoneWithMail(mail: pb.TransactionInfo[]): { seen: () => number } {
  let seen = 0;
  installScriptedPhone({
    'inbox.moneyWaiting': () => ({
      case: 'moneyWaitingResponse',
      value: new pb.MoneyWaitingResponse({ received: mail, through: BigInt(mail.length) }),
    }),
    'inbox.moneySeen': () => {
      seen += 1;
      mail.splice(0, mail.length);
      return { case: 'moneyWaitingResponse', value: new pb.MoneyWaitingResponse({ received: [], through: 1n }) };
    },
    'inbox.pull': { case: 'inboxResponse', value: new pb.InboxResponse({ items: [] }) },
  });
  return { seen: () => seen };
}

async function wait(ms: number): Promise<void> {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, ms)); });
}

function shownSrc(): string {
  return screen.getByRole('img').getAttribute('src') ?? 'no src';
}

test('with nothing waiting he plays his loop and holds out nothing', async () => {
  phoneWithMail([]);
  render(<HomeChameleon src={LOOP} onError={() => undefined} onOpenInbox={() => undefined} />);
  await act(settle);
  expect(shownSrc()).toBe(LOOP);
  expect(screen.queryByRole('button')).toBeNull();
});

test('mail arriving puts the tongue out; the envelope lands with it and opens the inbox', async () => {
  const mail: pb.TransactionInfo[] = [];
  const phone = phoneWithMail(mail);
  let taps = 0;
  const home = render(
    <HomeChameleon
      src={LOOP}
      onError={() => undefined}
      onOpenInbox={() => { askForInbox(); taps += 1; }}
    />,
  );
  await act(settle);
  expect(shownSrc()).toBe(LOOP);

  mail.push(received('tx-1'));
  await act(async () => { bridgeEvents.emit('money.waiting', undefined); await settle(); });
  expect(shownSrc()).toMatch(/^images\/vaulthunters\/chameleon-pink-mail\.gif\?play=\d+$/);

  // The tongue is on its way out: no envelope yet.
  fireEvent.load(screen.getByRole('img'));
  await wait(TONGUE_OUT_MS - 400);
  expect(screen.queryByRole('button')).toBeNull();

  // Frame 17: the tongue is out and the envelope is on it, and stays.
  await wait(600);
  const envelope = screen.getByRole('button', { name: '1 new in your inbox — open it' });
  await wait(2_000);
  expect(screen.getByRole('button', { name: '1 new in your inbox — open it' })).toBe(envelope);

  fireEvent.click(envelope);
  expect(taps).toBe(1);

  // The wallet screen comes up and its inbox opens, which reports the mail seen.
  home.unmount();
  render(<InboxOverlay headerHeight={0} />);
  await act(settle);
  expect(screen.getByRole('dialog', { name: 'Inbox' })).toBeTruthy();
  expect(phone.seen()).toBe(1);
}, 15_000);

test('each time the home screen comes up with mail waiting, the tongue goes out from the start', async () => {
  phoneWithMail([received('tx-1'), received('tx-2')]);
  const first = render(<HomeChameleon src={LOOP} onError={() => undefined} onOpenInbox={() => undefined} />);
  await act(settle);
  const firstPlay = shownSrc();
  first.unmount();

  render(<HomeChameleon src={LOOP} onError={() => undefined} onOpenInbox={() => undefined} />);
  await act(settle);
  expect(shownSrc()).toMatch(/-mail\.gif\?play=\d+$/);
  expect(shownSrc()).not.toBe(firstPlay);

  fireEvent.load(screen.getByRole('img'));
  await wait(TONGUE_OUT_MS + 100);
  expect(screen.getByRole('button', { name: '2 new in your inbox — open it' })).toBeTruthy();
}, 10_000);

test('an inbox nobody asked for stays shut', async () => {
  phoneWithMail([received('tx-1')]);
  render(<InboxOverlay headerHeight={0} />);
  await act(settle);
  expect(screen.queryByRole('dialog', { name: 'Inbox' })).toBeNull();
});
