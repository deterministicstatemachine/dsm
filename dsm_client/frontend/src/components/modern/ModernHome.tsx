// SPDX-License-Identifier: Apache-2.0
// The Modern skin's Wallet tab: the balance, Send and Receive, every token the
// wallet holds, the rest of DSM (tokens, apps, trading, the Bitcoin bridge,
// storage; Simple mode puts some away), People, and the last few payments.

import React, { useState } from 'react';
import { useWallet } from '../../contexts/WalletContext';
import { dsmClient } from '../../services/dsmClient';
import { useContacts } from '../../contexts/ContactsContext';
import { useAppRuntimeStore } from '../../runtime/appRuntimeStore';
import { navigationStore, reachable } from '../../runtime/navigationStore';
import type { ScreenType } from '../../types/app';
import { TokenMark } from '../TokenMark';
import { ActivityItem, Icon, activityRows, holdings, mainBalance, type IconName } from './parts';
import { modernNav } from './modernNav';

const RECENT = 3;

/** The rest of DSM, each a DGen screen the Modern skin opens inside itself. */
const FEATURES: { to: ScreenType; label: string; icon: IconName }[] = [
  { to: 'accounts', label: 'Tokens', icon: 'tokens' },
  { to: 'apps', label: 'Apps', icon: 'apps' },
  { to: 'qr', label: 'Scan', icon: 'scan' },
  { to: 'sofi', label: 'Trade', icon: 'trade' },
  { to: 'vault', label: 'Bitcoin', icon: 'bitcoin' },
  { to: 'storage', label: 'Storage', icon: 'storage' },
];

export default function ModernHome(): React.JSX.Element {
  const wallet = useWallet();
  const { contacts } = useContacts();
  const main = mainBalance(wallet.balances);
  const held = holdings(wallet.balances);
  // Fungible tokens, or the one-of-a-kind objects (creatures, items): the same switch the DGen wallet has.
  const [shown, setShown] = useState<'currency' | 'object'>('currency');
  const showingObjects = shown === 'object';
  const listed = held.filter((b) => (b.holding === 'object' ? 'object' : 'currency') === shown);
  // Read so the grid follows Simple mode as it is switched.
  const runtime = useAppRuntimeStore();
  const features = FEATURES.filter((f) => runtime.simpleMode === 'off' || reachable(f.to));
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
      </section>

      <div className="s-actions">
        <button type="button" className="s-btn s-btn-primary" onClick={() => modernNav.open({ kind: 'send', to: null })}>
          <Icon name="send" /> Send
        </button>
        <button type="button" className="s-btn s-btn-secondary" onClick={() => modernNav.open({ kind: 'receive' })}>
          <Icon name="receive" /> Receive
        </button>
      </div>

      {held.length > 0 ? (
        <section className="s-card" aria-label={showingObjects ? 'Your objects' : 'Your tokens'}>
          <div className="s-section-head">
            <span className="s-section-title">{showingObjects ? 'Your Objects' : 'Your Tokens'}</span>
            <button
              type="button"
              role="switch"
              className="s-switch"
              aria-checked={showingObjects}
              aria-label="Show objects"
              onClick={() => setShown(showingObjects ? 'currency' : 'object')}
            >
              <span>Objects</span><span className="s-switch-knob" aria-hidden />
            </button>
          </div>
          {listed.length === 0 ? (
            <div className="s-empty">{showingObjects ? 'No objects yet. Creatures and other one-of-a-kind items show here.' : 'No tokens yet.'}</div>
          ) : (
            listed.map((b) => (
              <button key={b.tokenId} type="button" className="s-row" onClick={() => modernNav.open({ kind: 'send', to: null, tokenId: b.tokenId })}>
                <span className="s-coin"><TokenMark ticker={b.symbol} iconUrl={b.iconUrl} size={40} className="s-coin-img" /></span>
                <span className="s-row-main">
                  <span className="s-row-title" style={{ display: 'block' }}>{b.symbol}</span>
                  {b.tokenName !== b.symbol ? <span className="s-row-sub" style={{ display: 'block' }}>{b.tokenName}</span> : null}
                </span>
                <span className="s-row-end"><span className="s-row-title">{b.displayAmount}</span></span>
              </button>
            ))
          )}
          <button type="button" className="s-chip" style={{ marginTop: 10 }} onClick={() => navigationStore.navigate('accounts')}>Add or create a token ›</button>
        </section>
      ) : null}

      <nav className="s-grid" aria-label="More of DSM">
        {features.map((f) => (
          <button key={f.to} type="button" className="s-tile" onClick={() => navigationStore.navigate(f.to)}>
            <Icon name={f.icon} />
            {f.label}
          </button>
        ))}
      </nav>

      <button type="button" className="s-card s-row" onClick={() => modernNav.showTab('people')}>
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
          <button type="button" className="s-chip" onClick={() => modernNav.showTab('activity')}>View All ›</button>
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
