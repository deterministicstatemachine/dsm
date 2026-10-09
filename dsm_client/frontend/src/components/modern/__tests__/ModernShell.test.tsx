// SPDX-License-Identifier: Apache-2.0
// The Modern skin over the wallet's own data: what it shows, what it leaves
// out (sovereign finance), and how its pages open and close.

import React from 'react';
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import ModernShell from '../ModernShell';
import LookPicker from '../../LookPicker';
import { WalletContext } from '../../../contexts/WalletContext';
import { ContactsContext } from '../../../contexts/ContactsContext';
import { appRuntimeStore } from '../../../runtime/appRuntimeStore';
import { navigationStore } from '../../../runtime/navigationStore';
import { modernNav } from '../modernNav';
import { activityRows, holdings, mainBalance, sendable } from '../parts';
import { versionLabel } from '../../../appVersion';
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
/** A token someone created: a currency the protocol does not define. */
const gold: TokenBalanceView = { ...currency('GOLD', '5.00', 500n), protocolDefined: era.symbol === 'GOLD' };

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
        <ModernShell eraTokenSrc="" btcLogoSrc="" />
      </ContactsContext.Provider>
    </WalletContext.Provider>,
  );
}

beforeEach(() => {
  modernNav.showTab('wallet');
  appRuntimeStore.setSkin('modern');
  appRuntimeStore.setSimpleMode('off');
  appRuntimeStore.setSimpleOffline('off');
  appRuntimeStore.setReceiptsEmail('off');
  navigationStore.setCurrentScreen('home');
});

describe('the Modern skin', () => {
  it('shows the balance, every token held, Send and Receive, the payments, and all of DSM', () => {
    renderShell([era, gold]);
    expect(screen.getByRole('heading', { name: 'Wallet' })).toBeInTheDocument();
    expect(within(screen.getByLabelText('Total balance')).getByText('1,234.56')).toBeInTheDocument();
    // A created token is listed with ERA, and tapping it sends it.
    const tokens = screen.getByLabelText('Your tokens');
    expect(within(tokens).getByText('GOLD')).toBeInTheDocument();
    const recent = screen.getByLabelText('Recent activity');
    // Jane by the name her details give, Mark by his alias; the SoFi trade is left out.
    expect(within(recent).getByText('Jane Miller')).toBeInTheDocument();
    expect(within(recent).getByText('Thanks for lunch!')).toBeInTheDocument();
    expect(within(recent).getByText('mark')).toBeInTheDocument();
    expect(within(recent).queryByText(/1\.00/)).not.toBeInTheDocument();
    const more = screen.getByRole('navigation', { name: 'More of DSM' });
    expect(within(more).getAllByRole('button').map((b) => b.textContent)).toEqual(['Tokens', 'Apps', 'Scan', 'Trade', 'Bitcoin', 'Storage']);
  });

  it('puts trading, the Bitcoin bridge and storage away in Simple mode, and keeps tokens and apps', () => {
    appRuntimeStore.setSimpleMode('on');
    renderShell();
    const more = screen.getByRole('navigation', { name: 'More of DSM' });
    expect(within(more).getAllByRole('button').map((b) => b.textContent)).toEqual(['Tokens', 'Apps', 'Scan']);
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
      modernNav.back();
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

  it('offers Offline in full, and in Simple mode only when switched on there; Offline says it is under construction', () => {
    appRuntimeStore.setSimpleMode('on');
    renderShell();
    act(() => modernNav.open({ kind: 'send', to: JANE }));
    expect(screen.queryByRole('group', { name: 'How to send' })).not.toBeInTheDocument();
    act(() => appRuntimeStore.setSimpleOffline('on'));
    fireEvent.click(within(screen.getByRole('group', { name: 'How to send' })).getByRole('button', { name: 'Offline' }));
    expect(screen.getByRole('alertdialog', { name: 'Offline' })).toHaveTextContent('Under construction, check back soon.');
  });

  it('says a receipt will be emailed only when receipts are on and the person has an email', () => {
    renderShell();
    act(() => modernNav.open({ kind: 'send', to: JANE }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Amount' }), { target: { value: '50' } });
    fireEvent.click(screen.getByRole('button', { name: /Review Send/ }));
    expect(screen.getByRole('dialog', { name: 'Review send' })).not.toHaveTextContent(/receipt/);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    act(() => appRuntimeStore.setReceiptsEmail('on'));
    fireEvent.click(screen.getByRole('button', { name: /Review Send/ }));
    expect(screen.getByRole('dialog', { name: 'Review send' })).toHaveTextContent('A receipt will be emailed to jane@example.com.');
  });

  it('sends a created token picked from the wallet', () => {
    renderShell([era, gold]);
    fireEvent.click(within(screen.getByLabelText('Your tokens')).getByText('GOLD'));
    expect(within(screen.getByLabelText('Available balance')).getByText('5.00')).toBeInTheDocument();
    expect(within(screen.getByLabelText('Available balance')).getByText('GOLD')).toBeInTheDocument();
  });
});

describe('what the Modern skin reaches', () => {
  it('reaches everything, and in Simple mode refuses trading, the Bitcoin bridge, storage and dev tools only', () => {
    appRuntimeStore.setSkin('modern');
    appRuntimeStore.setSimpleMode('on');
    for (const screenType of ['sofi', 'vault', 'storage', 'dev_policy'] as const) {
      navigationStore.navigate(screenType);
      expect(navigationStore.getSnapshot().currentScreen).toBe('home');
    }
    navigationStore.navigate('accounts');
    expect(navigationStore.getSnapshot().currentScreen).toBe('accounts');
    navigationStore.setCurrentScreen('home');
    appRuntimeStore.setSimpleMode('off');
    navigationStore.navigate('sofi');
    expect(navigationStore.getSnapshot().currentScreen).toBe('sofi');
    navigationStore.setCurrentScreen('home');
    appRuntimeStore.setSimpleMode('on');
    appRuntimeStore.setSkin('dgen');
    navigationStore.navigate('storage');
    expect(navigationStore.getSnapshot().currentScreen).toBe('storage');
  });
});

describe('the choice of look', () => {
  beforeEach(() => {
    appRuntimeStore.setSkin(null);
    appRuntimeStore.setLookPreview(null);
  });

  it('shows each look behind its box as it is picked, and keeps nothing until OK', () => {
    render(<LookPicker />);
    const box = screen.getByRole('dialog', { name: 'Choose your look' });
    expect(appRuntimeStore.getSnapshot().lookPreview).toEqual({ skin: 'dgen', scheme: 'light', simpleMode: 'off' });
    fireEvent.click(within(box).getByRole('radio', { name: 'Modern' }));
    fireEvent.click(within(box).getByRole('switch', { name: 'Dark mode' }));
    fireEvent.click(within(box).getByRole('switch', { name: 'Simple mode' }));
    expect(appRuntimeStore.getSnapshot().lookPreview).toEqual({ skin: 'modern', scheme: 'dark', simpleMode: 'on' });
    expect(appRuntimeStore.getSnapshot().skin).toBeNull();
    expect(box).toHaveTextContent('DGen: press SELECT to change the screen colour and backlight.');
  });

  it('keeps the look on OK, and closes', async () => {
    render(<LookPicker />);
    fireEvent.click(screen.getByRole('radio', { name: 'Modern' }));
    fireEvent.click(screen.getByRole('switch', { name: 'Dark mode' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    });
    const runtime = appRuntimeStore.getSnapshot();
    expect([runtime.skin, runtime.scheme, runtime.simpleMode, runtime.lookPreview]).toEqual(['modern', 'dark', 'off', null]);
  });

  it('keeps DGen too', async () => {
    render(<LookPicker />);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    });
    expect(appRuntimeStore.getSnapshot().skin).toBe('dgen');
  });
});

describe('how the Modern skin names things', () => {
  it('takes the protocol currency as the main balance and leaves non-payments out of activity', () => {
    expect(mainBalance([era])).toBe(era);
    expect(mainBalance([])).toBeNull();
    expect(holdings([gold, era]).map((b) => b.symbol)).toEqual(['GOLD', 'ERA']);
    expect(sendable([era, { ...gold, baseUnits: 0n }], null).map((b) => b.symbol)).toEqual(['ERA']);
    const rows = activityRows(history, contacts);
    expect(rows.map((r) => [r.who, r.direction, r.amount])).toEqual([
      ['Jane Miller', 'out', '50.00'],
      ['mark', 'in', '120.00'],
    ]);
  });
});

describe('the version the app shows', () => {
  it('is the Android build\'s own, named a pre-release', () => {
    expect(versionLabel()).toMatch(/^DSM v\d+\.\d+\.\d+-[0-9A-Za-z.]+ Pre-release$/);
    expect(versionLabel()).toBe(`DSM v${process.env.DSM_APP_VERSION} Pre-release`);
  });
});
