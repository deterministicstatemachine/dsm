// SPDX-License-Identifier: Apache-2.0
// The Modern wallet has the b0x inbox, as the DGen wallet does: its button
// counts the received transfers Rust holds as not yet looked at, on the
// Wallet tab's banner and in the top bar of every other view, and opening it
// shows them and reports them seen.

import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../proto/dsm_app_pb';
import ModernShell from '../ModernShell';
import { WalletContext } from '../../../contexts/WalletContext';
import { ContactsContext } from '../../../contexts/ContactsContext';
import { appRuntimeStore } from '../../../runtime/appRuntimeStore';
import { navigationStore } from '../../../runtime/navigationStore';
import { modernNav } from '../modernNav';
import { installScriptedPhone, removeScriptedPhone, settle } from '../../../tests/helpers/scriptedPhone';

afterEach(removeScriptedPhone);

beforeEach(() => {
  modernNav.showTab('wallet');
  appRuntimeStore.setSkin('modern');
  appRuntimeStore.setSimpleMode('off');
  navigationStore.setCurrentScreen('home');
});

function received(id: string, display: string): pb.TransactionInfo {
  return new pb.TransactionInfo({
    id,
    fromDeviceId: new Uint8Array(32).fill(0x11),
    toDeviceId: new Uint8Array(32).fill(0x22),
    tokenId: 'ERA',
    amount: 5n,
    txHash: new Uint8Array(32).fill(id.length),
    direction: pb.AmountDirection.CREDIT,
    txType: pb.TransactionType.TX_TYPE_BILATERAL_OFFLINE,
    status: 'completed',
    recipient: 'peer',
    displayAmount: display,
  });
}

/** A phone whose Rust holds `mail` as received and not yet seen. */
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
      return { case: 'moneyWaitingResponse', value: new pb.MoneyWaitingResponse({ received: [], through: 2n }) };
    },
    'inbox.pull': { case: 'inboxResponse', value: new pb.InboxResponse({ items: [] }) },
  });
  return { seen: () => seen };
}

const loaded = 'loaded';
const walletValue = {
  genesisHash: 'G', deviceId: 'ME', balances: [], transactions: [], isLoading: loaded !== 'loaded', error: null,
  refreshAll: async () => undefined, refreshBalances: async () => undefined, refreshTransactions: async () => undefined,
  setError: () => undefined,
};
const contactsValue = {
  contacts: [], isLoading: loaded !== 'loaded', error: null,
  refreshContacts: async () => undefined,
  addContact: async () => ({ accepted: loaded !== 'loaded', error: 'not in this test' }) as never,
  setError: () => undefined,
};

function renderShell() {
  return render(
    <WalletContext.Provider value={walletValue as never}>
      <ContactsContext.Provider value={contactsValue as never}>
        <ModernShell eraTokenSrc="" btcLogoSrc="" />
      </ContactsContext.Provider>
    </WalletContext.Provider>,
  );
}

function slot(): HTMLElement {
  const found = document.querySelector<HTMLElement>('.s-inbox-slot');
  if (found === null) throw new Error('the Modern shell has no inbox');
  return found;
}

test('the Wallet tab shows the inbox on its banner, with the count, and opening it shows the mail and marks it seen', async () => {
  const phone = phoneWithMail([received('tx-1', '5.00'), received('tx-22', '7.50')]);
  renderShell();
  await act(settle);

  expect(slot()).toHaveAttribute('data-over', 'banner');
  const button = screen.getByRole('button', { name: 'Inbox (2 new)' });
  expect(button).toHaveAttribute('data-count', '2');
  expect(button).toHaveClass('has-items');

  await act(async () => { fireEvent.click(button); await settle(); });
  const inbox = screen.getByRole('dialog', { name: 'Inbox' });
  expect(within(inbox).getByText('5.00 ERA')).toBeInTheDocument();
  expect(within(inbox).getByText('7.50 ERA')).toBeInTheDocument();
  expect(phone.seen()).toBe(1);
  expect(screen.getByRole('button', { name: 'Inbox' })).not.toHaveClass('has-items');
});

test('every other view has the inbox in its top bar', async () => {
  phoneWithMail([received('tx-1', '5.00')]);
  renderShell();
  await act(settle);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'People' })); await settle(); });
  expect(slot()).toHaveAttribute('data-over', 'topbar');
  expect(screen.getByRole('button', { name: 'Inbox (1 new)' })).toBeInTheDocument();
});

test('with nothing waiting the inbox is there, with no count', async () => {
  phoneWithMail([]);
  renderShell();
  await act(settle);
  const button = screen.getByRole('button', { name: 'Inbox' });
  expect(button).toHaveAttribute('data-count', '0');
  expect(button).not.toHaveClass('has-items');
});
