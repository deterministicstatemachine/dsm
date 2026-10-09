// SPDX-License-Identifier: Apache-2.0
// The Simple skin: a top bar, the page or tab in view, and the tab bar
// (Wallet / People / Activity / Settings). A Classic screen the Simple skin
// still needs (the lock, a connect request from an app) opens inside it, under
// a Back button.

import React, { useEffect } from 'react';
import AppScreenRouter from '../AppScreenRouter';
import { navigationStore, useNavigationStore } from '../../runtime/navigationStore';
import type { ScreenType } from '../../types/app';
import { Icon } from './parts';
import { currentPage, simpleNav, useSimpleNav, type SimpleTab } from './simpleNav';
import SimpleHome from './SimpleHome';
import SimplePeople from './SimplePeople';
import SimpleActivity from './SimpleActivity';
import SimpleSettings from './SimpleSettings';
import SimpleSend from './SimpleSend';
import SimpleReceive from './SimpleReceive';
import SimpleAddContact from './SimpleAddContact';
import SimpleContact from './SimpleContact';
import SimpleMyCard from './SimpleMyCard';
import SimpleReceipts from './SimpleReceipts';

/** The Classic screens the Simple skin opens inside itself. */
const CLASSIC_INSIDE = new Set<ScreenType>(['lock_setup', 'apps', 'recovery', 'nfc_recovery']);

const TABS: { id: SimpleTab; label: string; icon: 'home' | 'people' | 'activity' | 'settings' }[] = [
  { id: 'wallet', label: 'Wallet', icon: 'home' },
  { id: 'people', label: 'People', icon: 'people' },
  { id: 'activity', label: 'Activity', icon: 'activity' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

function TabContent({ tab }: { tab: SimpleTab }): React.JSX.Element {
  switch (tab) {
    case 'wallet': return <SimpleHome />;
    case 'people': return <SimplePeople />;
    case 'activity': return <SimpleActivity />;
    case 'settings': return <SimpleSettings />;
  }
}

export default function SimpleShell({ eraTokenSrc, btcLogoSrc }: { eraTokenSrc: string; btcLogoSrc: string }): React.JSX.Element {
  const nav = useSimpleNav();
  const navigation = useNavigationStore();
  const page = currentPage(nav);

  useEffect(() => {
    window.addEventListener('popstate', simpleNav.onPop);
    return () => window.removeEventListener('popstate', simpleNav.onPop);
  }, []);

  const classic = CLASSIC_INSIDE.has(navigation.currentScreen) ? navigation.currentScreen : null;

  let body: React.ReactNode;
  if (classic !== null) {
    body = (
      <div className="s-classic">
        <button type="button" className="s-icon-btn" aria-label="Back" onClick={() => navigationStore.navigate('home')}>
          <Icon name="back" />
        </button>
        <AppScreenRouter currentScreen={classic} navigate={navigationStore.navigate} eraTokenSrc={eraTokenSrc} btcLogoSrc={btcLogoSrc} />
      </div>
    );
  } else {
    switch (page.kind) {
      case 'tab': body = <TabContent tab={nav.tab} />; break;
      case 'send': body = <SimpleSend to={page.to} />; break;
      case 'receive': body = <SimpleReceive />; break;
      case 'add_contact': body = <SimpleAddContact />; break;
      case 'contact': body = <SimpleContact deviceId={page.deviceId} />; break;
      case 'my_card': body = <SimpleMyCard />; break;
      case 'receipts': body = <SimpleReceipts />; break;
    }
  }

  return (
    <div className="s-app">
      <header className="s-topbar">
        <div className="s-brand"><span className="s-brand-mark" aria-hidden /> DSM Wallet</div>
        <button type="button" className="s-icon-btn" aria-label="My contact card" onClick={() => simpleNav.open({ kind: 'my_card' })}>
          <Icon name="person" />
        </button>
      </header>
      <main className="s-body">{body}</main>
      <nav className="s-tabbar" aria-label="Wallet sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            className="s-tab"
            aria-current={classic === null && page.kind === 'tab' && nav.tab === t.id ? 'page' : undefined}
            onClick={() => {
              if (classic !== null) navigationStore.navigate('home');
              simpleNav.showTab(t.id);
            }}
          >
            <Icon name={t.icon} />
            {t.label}
          </button>
        ))}
      </nav>
    </div>
  );
}
