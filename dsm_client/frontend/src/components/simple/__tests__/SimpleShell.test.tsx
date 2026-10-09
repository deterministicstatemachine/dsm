// SPDX-License-Identifier: Apache-2.0
// The Simple skin over the wallet's own data: what it shows, what it leaves
// out (sovereign finance), and how its pages open and close.

import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import SimpleShell from '../SimpleShell';
import SkinChoice from '../SkinChoice';
import { WalletContext } from '../../../contexts/WalletContext';
import { ContactsContext } from '../../../contexts/ContactsContext';
import { appRuntimeStore } from '../../../runtime/appRuntimeStore';
import { navigationStore } from '../../../runtime/navigationStore';
import { simpleNav } from '../simpleNav';
import { activityRows, mainBalance } from '../parts';
import type { DomainContact, DomainTransaction } from '../../../domain/types';
import type { TokenBalanceView } from '../../../dsm/types';

const JANE = 'JANEJANEJANEJANEJANEJANEJANEJANEJANEJANEJANEJANEJANE';
const MARK = 'MARKMARKMARKMARKMARKMARKMARKMARKMARKMARKMARKMARKMARK';

/** A contact as contacts.list answers one: its genesis named, so verified. */
function contact(alias: string, deviceId: string, profile?: DomainContact['profile']): DomainContact {
  const genesisHash = `G-${alias}`;
  return { alias, deviceId, genesisHash, pairing: 'idle', genesisVerifiedOnline: genesisHash.length > 2, signingPublicKey: `K-${alias}`, profile };
}

const contacts: DomainContact[] = [
  contact('jm', JANE, { name: 'Jane Miller', email: 'jane@example.com', phone: '', phoneLookupKey: '' }),
  contact('mark', MARK),
];

/** A currency row: ERA is the one the protocol defines. */
function currency(symbol: string, display: string, units: bigint): TokenBalanceView {
  return {
    tokenId: symbol, symbol, tokenName: symbol, baseUnits: units, displayAmount: display, decimals: 2,
    protocolDefined: symbol === 'ERA', holding: 'currency',
  };
}

const era = currency('ERA', '1,234.56', 123456n);

function tx(id: string, txType: DomainTransaction['txType'], amount: bigint, display: string, from: string, to: string, memo?: string): DomainTransaction {
  const stitchedReceipt = undefined;
  return {
    txId: id, txHash: id, txType, amount, displayAmount: display, tokenId: 'ERA', recipient: 'label', status: 'confirmed',
    fromDeviceId: from, toDeviceId: to, memo, stitchedReceipt, receiptVerified: stitchedReceipt !== undefined,
  };
}

const history: DomainTransaction[] = [
  tx('t1', 'online', -5000n, '-50.00', 'ME', JANE, 'Thanks for lunch!'),
  tx('t2', 'sofi_trade', -100n, '-1.00', 'ME', 'VAULT'),
  tx('t3', 'online', 12000n, '120.00', MARK, 'ME'),
];

/** The wallet as WalletContext holds it once loaded. */
function wallet(balances: TokenBalanceView[], transactions: DomainTransaction[]) {
  const loading = 'loaded';
  return {
    genesisHash: 'G', deviceId: 'ME', balances, transactions, isLoading: loading !== 'loaded', error: null,
    refreshAll: async () => undefined, refreshBalances: async () => undefined, refreshTransactions: async () => undefined,
    setError: () => undefined,
  };
}

const contactsValue = {
  contacts, isLoading: contacts.length === 0, error: null,
  refreshContacts: async () => undefined,
  addContact: async () => ({ accepted: contacts.length === 0, error: 'not in this test' }) as never,
  setError: () => undefined,
};

/** Resolves when the browser history steps back. */
function nextPop(): Promise<void> {
  return new Promise((resolve) => {
    const onPop = () => {
      window.removeEventListener('popstate', onPop);
      resolve();
    };
    window.addEventListener('popstate', onPop);
  });
}

function renderShell(balances: TokenBalanceView[] = [era], transactions: DomainTransaction[] = history) {
  return render(
    <WalletContext.Provider value={wallet(balances, transactions) as never}>
      <ContactsContext.Provider value={contactsValue as never}>
        <SimpleShell eraTokenSrc="" btcLogoSrc="" />
      </ContactsContext.Provider>
    </WalletContext.Provider>,
  );
}

beforeEach(() => {
  simpleNav.showTab('wallet');
  appRuntimeStore.setSkin('simple');
  appRuntimeStore.setSimpleOffline('off');
  appRuntimeStore.setReceiptsEmail('off');
  navigationStore.setCurrentScreen('home');
});

describe('the Simple skin', () => {
  it('shows the balance, Send and Receive, and the payments, without sovereign finance', () => {
    renderShell();
    expect(screen.getByRole('heading', { name: 'Wallet' })).toBeInTheDocument();
    expect(within(screen.getByLabelText('Total balance')).getByText('1,234.56')).toBeInTheDocument();
    const recent = screen.getByLabelText('Recent activity');
    // Jane by the name her details give, Mark by his alias; the SoFi trade is left out.
    expect(within(recent).getByText('Jane Miller')).toBeInTheDocument();
    expect(within(recent).getByText('Thanks for lunch!')).toBeInTheDocument();
    expect(within(recent).getByText('mark')).toBeInTheDocument();
    expect(within(recent).queryByText(/1\.00/)).not.toBeInTheDocument();
    expect(screen.queryByText(/swap|liquidity|vault|bitcoin|token/i)).not.toBeInTheDocument();
  });

  it('offers the welcome claim when the wallet holds nothing, never a made-up zero', () => {
    renderShell([], []);
    expect(screen.getByText('No money yet')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Get your welcome ERA' })).toBeInTheDocument();
    expect(screen.queryByText(/^0$/)).not.toBeInTheDocument();
  });

  it('opens a contact from People and closes it with Back, as the phone back button does', async () => {
    renderShell();
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Wallet sections' })).getByRole('button', { name: 'People' }));
    expect(screen.getByRole('heading', { name: 'People' })).toBeInTheDocument();
    fireEvent.click(screen.getByText('Jane Miller'));
    expect(screen.getByText('jane@example.com')).toBeInTheDocument();
    await act(async () => {
      const popped = nextPop();
      simpleNav.back();
      await popped;
    });
    expect(screen.getByRole('heading', { name: 'People' })).toBeInTheDocument();
  });

  it('lists payments by direction in Activity', () => {
    renderShell();
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Wallet sections' })).getByRole('button', { name: 'Activity' }));
    const list = screen.getByLabelText('Payments');
    fireEvent.click(screen.getByRole('button', { name: 'Received' }));
    expect(within(list).queryByText('Jane Miller')).not.toBeInTheDocument();
    expect(within(list).getByText('mark')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Sent' }));
    expect(within(list).getByText('Jane Miller')).toBeInTheDocument();
  });

  it('offers Online and Offline only when offline payments are on, and Offline says it is under construction', () => {
    renderShell();
    act(() => simpleNav.open({ kind: 'send', to: JANE }));
    expect(screen.queryByRole('group', { name: 'How to send' })).not.toBeInTheDocument();
    act(() => appRuntimeStore.setSimpleOffline('on'));
    fireEvent.click(within(screen.getByRole('group', { name: 'How to send' })).getByRole('button', { name: 'Offline' }));
    expect(screen.getByRole('alertdialog', { name: 'Offline' })).toHaveTextContent('Under construction, check back soon.');
  });

  it('says a receipt will be emailed only when receipts are on and the person has an email', () => {
    renderShell();
    act(() => simpleNav.open({ kind: 'send', to: JANE }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Amount' }), { target: { value: '50' } });
    fireEvent.click(screen.getByRole('button', { name: /Review Send/ }));
    expect(screen.getByRole('dialog', { name: 'Review send' })).not.toHaveTextContent(/receipt/);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    act(() => appRuntimeStore.setReceiptsEmail('on'));
    fireEvent.click(screen.getByRole('button', { name: /Review Send/ }));
    expect(screen.getByRole('dialog', { name: 'Review send' })).toHaveTextContent('A receipt will be emailed to jane@example.com.');
  });
});

describe('what the Simple skin reaches', () => {
  it('refuses the sovereign-finance screens while Simple is the skin, and only then', () => {
    appRuntimeStore.setSkin('simple');
    for (const screenType of ['sofi', 'accounts', 'storage', 'dev_policy', 'vault'] as const) {
      navigationStore.navigate(screenType);
      expect(navigationStore.getSnapshot().currentScreen).toBe('home');
    }
    navigationStore.navigate('lock_setup');
    expect(navigationStore.getSnapshot().currentScreen).toBe('lock_setup');
    navigationStore.setCurrentScreen('home');
    appRuntimeStore.setSkin('classic');
    navigationStore.navigate('sofi');
    expect(navigationStore.getSnapshot().currentScreen).toBe('sofi');
  });
});

describe('the choice of skin', () => {
  it('asks once the preferences are read and none is chosen, and remembers the choice', async () => {
    appRuntimeStore.setSkin(null);
    appRuntimeStore.setSkinRead('read');
    render(<SkinChoice />);
    expect(screen.getByRole('dialog', { name: 'Choose your wallet' })).toBeInTheDocument();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Simple: send, receive, people/ }));
    });
    expect(appRuntimeStore.getSnapshot().skin).toBe('simple');
    expect(screen.queryByRole('dialog', { name: 'Choose your wallet' })).not.toBeInTheDocument();
  });

  it('does not ask before the preferences are read', () => {
    appRuntimeStore.setSkin(null);
    appRuntimeStore.setSkinRead('unread');
    render(<SkinChoice />);
    expect(screen.queryByRole('dialog', { name: 'Choose your wallet' })).not.toBeInTheDocument();
  });
});

describe('how the Simple skin names things', () => {
  it('takes the protocol currency as the main balance and leaves non-payments out of activity', () => {
    expect(mainBalance([era])).toBe(era);
    expect(mainBalance([])).toBeNull();
    const rows = activityRows(history, contacts);
    expect(rows.map((r) => [r.who, r.direction, r.amount])).toEqual([
      ['Jane Miller', 'out', '50.00'],
      ['mark', 'in', '120.00'],
    ]);
  });
});
