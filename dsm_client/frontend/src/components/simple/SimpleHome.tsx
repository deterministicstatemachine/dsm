// SPDX-License-Identifier: Apache-2.0
// The Simple skin's Wallet tab: the balance, Send and Receive, People, and the
// last few payments.

import React, { useState } from 'react';
import { useWallet } from '../../contexts/WalletContext';
import { dsmClient } from '../../services/dsmClient';
import { useContacts } from '../../contexts/ContactsContext';
import { ActivityItem, Icon, activityRows, mainBalance, otherBalances } from './parts';
import { simpleNav } from './simpleNav';

const RECENT = 3;

export default function SimpleHome(): React.JSX.Element {
  const wallet = useWallet();
  const { contacts } = useContacts();
  const main = mainBalance(wallet.balances);
  const others = otherBalances(wallet.balances);
  const recent = activityRows(wallet.transactions, contacts).slice(0, RECENT);
  const [claim, setClaim] = useState<{ state: 'idle' | 'claiming' } | { state: 'refused'; message: string }>({ state: 'idle' });

  // A new wallet holds nothing: its first ERA is the network's welcome claim.
  const claimWelcome = () => {
    setClaim({ state: 'claiming' });
    dsmClient.claimFaucet().then(
      (res) => {
        if (res.success) {
          setClaim({ state: 'idle' });
          return wallet.refreshAll();
        }
        setClaim({ state: 'refused', message: res.message });
        return undefined;
      },
      (e: unknown) => setClaim({ state: 'refused', message: e instanceof Error ? e.message : String(e) }),
    );
  };

  return (
    <>
      <h1 className="s-title">Wallet</h1>
      <section className="s-card s-balance" aria-label="Total balance">
        <div className="s-balance-label">Total Balance</div>
        {main !== null ? (
          <div className="s-balance-amount">
            {main.displayAmount}
            <small>{main.symbol}</small>
          </div>
        ) : wallet.isLoading ? (
          <div className="s-balance-amount">…</div>
        ) : (
          <>
            <div className="s-balance-amount" style={{ fontSize: 28 }}>No money yet</div>
            <button type="button" className="s-btn s-btn-small s-btn-primary" style={{ marginTop: 12 }} disabled={claim.state === 'claiming'} onClick={claimWelcome}>
              {claim.state === 'claiming' ? 'Getting it…' : 'Get your welcome ERA'}
            </button>
            {claim.state === 'refused' ? <div className="s-balance-other">{claim.message}</div> : null}
          </>
        )}
        {others.length > 0 ? (
          <div className="s-balance-other">
            Also: {others.map((b) => `${b.displayAmount} ${b.symbol}`).join(' · ')}
          </div>
        ) : null}
      </section>

      <div className="s-actions">
        <button type="button" className="s-btn s-btn-primary" onClick={() => simpleNav.open({ kind: 'send', to: null })}>
          <Icon name="send" /> Send
        </button>
        <button type="button" className="s-btn s-btn-secondary" onClick={() => simpleNav.open({ kind: 'receive' })}>
          <Icon name="receive" /> Receive
        </button>
      </div>

      <button type="button" className="s-card s-row" onClick={() => simpleNav.showTab('people')}>
        <span className="s-avatar b"><Icon name="people" /></span>
        <span className="s-row-main">
          <span className="s-row-title" style={{ display: 'block' }}>People</span>
          <span className="s-row-sub" style={{ display: 'block' }}>Send to friends and family</span>
        </span>
        <Icon name="chevron" />
      </button>

      <section className="s-card" aria-label="Recent activity">
        <div className="s-section-head">
          <span className="s-section-title">Recent Activity</span>
          <button type="button" className="s-chip" onClick={() => simpleNav.showTab('activity')}>View All ›</button>
        </div>
        {recent.length === 0 ? (
          <div className="s-empty">No payments yet. When you send or receive, it shows here.</div>
        ) : (
          recent.map((row) => <ActivityItem key={row.tx.txId} row={row} />)
        )}
      </section>
    </>
  );
}
