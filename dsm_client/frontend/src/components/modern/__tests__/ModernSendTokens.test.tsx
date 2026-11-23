// SPDX-License-Identifier: Apache-2.0
// The Modern send page offers a recipient only the tokens Rust says that
// contact can be sent (owner, 2026-11-21): a contact credits no token it has
// not added. A token the wallet holds and the recipient has not added is not
// sent in another's place: the page says so and offers what can be sent.

import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import ModernSend from '../ModernSend';
import { WalletContext } from '../../../contexts/WalletContext';
import { ContactsContext } from '../../../contexts/ContactsContext';
import type { TokenBalanceView } from '../../../dsm/types';
import type { DomainContact } from '../../../domain/types';

function held(tokenId: string, baseUnits: bigint): TokenBalanceView {
  return {
    tokenId, symbol: tokenId, tokenName: tokenId, baseUnits, displayAmount: `${baseUnits}`, decimals: 0,
    protocolDefined: tokenId === 'ERA', holding: 'currency',
  };
}

function contact(deviceId: string, alias: string, sendableTokenIds: string[]): DomainContact {
  const genesisHash = `G-${alias}`;
  return { alias, deviceId, genesisHash, pairing: 'idle', relationship: 'established', genesisVerifiedOnline: genesisHash.length > 2, signingPublicKey: `K-${alias}`, sendableTokenIds };
}

const PLAIN = contact('RXDC8XQMZ7JHAB', 'Plain', ['ERA']);
const BOTH = contact('NJ2C7P4CXGNY59', 'Both', ['ERA', 'WILD']);

function renderSend(to: DomainContact, asked?: string) {
  const state = 'loaded';
  const wallet = {
    genesisHash: 'G', deviceId: 'ME', balances: [held('ERA', 100n), held('WILD', 50n)], transactions: [],
    isInitialized: state === 'loaded', isLoading: state !== 'loaded', error: null,
    refreshAll: async () => undefined, refreshBalances: async () => undefined, refreshTransactions: async () => undefined,
    setError: () => undefined,
  };
  const contacts = {
    contacts: [PLAIN, BOTH], isLoading: state !== 'loaded', error: null,
    refreshContacts: async () => undefined,
    addContact: async () => { throw new Error('not in this test'); },
    unpairContact: async () => undefined,
    setError: () => undefined,
  };
  render(
    <WalletContext.Provider value={wallet as never}>
      <ContactsContext.Provider value={contacts as never}>
        {asked === undefined ? <ModernSend to={to.deviceId} /> : <ModernSend to={to.deviceId} tokenId={asked} />}
      </ContactsContext.Provider>
    </WalletContext.Provider>,
  );
}

/** The tickers on the token picker's buttons; none when the page shows no picker. */
function offered(): Array<string | null> {
  return screen.queryAllByRole('group', { name: 'Token' })
    .flatMap((group) => Array.from(group.querySelectorAll('button')))
    .map((b) => b.textContent);
}

describe('the tokens the Modern send page offers a recipient', () => {
  it('offers a contact that has added a second token the choice of both', () => {
    renderSend(BOTH);
    expect(offered()).toEqual(['ERA', 'WILD']);
  });

  it('offers no choice to a contact that can be sent one token', () => {
    renderSend(PLAIN);
    expect(offered()).toEqual([]);
    expect(screen.queryByText('WILD')).not.toBeInTheDocument();
  });

  it('says a token asked for is one the recipient has not added, and offers what can be sent', () => {
    renderSend(PLAIN, 'WILD');
    expect(offered()).toEqual(['ERA']);
    fireEvent.click(screen.getByRole('button', { name: /Review Send/ }));
    expect(screen.getByRole('alert')).toHaveTextContent('Plain has not added WILD. Choose a token they have added.');

    fireEvent.click(screen.getByRole('button', { name: 'ERA' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Enter an amount above zero.');
  });
});
