// SPDX-License-Identifier: Apache-2.0
// The Modern skin: a top bar, the page or tab in view, and the tab bar
// (Wallet / People / Activity / Settings). Every DGen screen the Modern skin
// has no page of its own for (tokens, trading, the Bitcoin bridge, storage,
// apps, the lock, …) opens inside it, in its colours, under a Back button.
// Simple mode puts some of them away (runtime/navigationStore.ts).

import React, { useEffect } from 'react';
import AppScreenRouter from '../AppScreenRouter';
import { navigationStore, useNavigationStore } from '../../runtime/navigationStore';
import type { ScreenType } from '../../types/app';
import { Icon } from './parts';
import { currentPage, modernNav, useModernNav, type ModernTab } from './modernNav';
import ModernHome from './ModernHome';
import ModernPeople from './ModernPeople';
import ModernActivity from './ModernActivity';
import ModernSettings from './ModernSettings';
import ModernSend from './ModernSend';
import ModernReceive from './ModernReceive';
import ModernAddContact from './ModernAddContact';
import ModernContact from './ModernContact';
import ModernMyCard from './ModernMyCard';
import ModernReceipts from './ModernReceipts';
import ProfileHeader from './ProfileHeader';
import { useOwnCard } from './ownCard';

/** The DGen screens the Modern skin opens inside itself. */
const CLASSIC_INSIDE = new Set<ScreenType>([
  'accounts', 'apps', 'qr', 'sofi', 'vault', 'storage', 'settings', 'dev_policy',
  'lock_setup', 'recovery', 'nfc_recovery', 'recovery_pipeline',
]);

/** DGen screens the Modern skin has its own tab for. */
const OWN_TAB: Partial<Record<ScreenType, ModernTab>> = {
  wallet: 'wallet',
  transactions: 'activity',
  contacts: 'people',
};

const TABS: { id: ModernTab; label: string; icon: 'home' | 'people' | 'activity' | 'settings' }[] = [
  { id: 'wallet', label: 'Wallet', icon: 'home' },
  { id: 'people', label: 'People', icon: 'people' },
  { id: 'activity', label: 'Activity', icon: 'activity' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

function TabContent({ tab }: { tab: ModernTab }): React.JSX.Element {
  switch (tab) {
    case 'wallet': return <ModernHome />;
    case 'people': return <ModernPeople />;
    case 'activity': return <ModernActivity />;
    case 'settings': return <ModernSettings />;
  }
}

export default function ModernShell({ eraTokenSrc, btcLogoSrc }: { eraTokenSrc: string; btcLogoSrc: string }): React.JSX.Element {
  const nav = useModernNav();
  const own = useOwnCard();
  const navigation = useNavigationStore();
  const page = currentPage(nav);

  useEffect(() => {
    window.addEventListener('popstate', modernNav.onPop);
    return () => window.removeEventListener('popstate', modernNav.onPop);
  }, []);

  // A DGen screen that sends the app to a screen the Modern skin draws itself
  // (a scan cancelled back to contacts, a card opened) lands on that tab or page.
  useEffect(() => {
    const to = navigation.currentScreen;
    const tab = OWN_TAB[to];
    if (tab !== undefined) {
      navigationStore.setCurrentScreen('home');
      modernNav.showTab(tab);
    } else if (to === 'mycontact') {
      navigationStore.setCurrentScreen('home');
      modernNav.open({ kind: 'my_card' });
    }
  }, [navigation.currentScreen]);

  const classic = CLASSIC_INSIDE.has(navigation.currentScreen) ? navigation.currentScreen : null;

  let body: React.ReactNode;
  if (classic !== null) {
    body = (
      <div className="s-classic">
        <button type="button" className="s-icon-btn s-classic-back" aria-label="Back" onClick={() => navigationStore.navigate('home')}>
          <Icon name="back" />
        </button>
        <AppScreenRouter currentScreen={classic} navigate={navigationStore.navigate} eraTokenSrc={eraTokenSrc} btcLogoSrc={btcLogoSrc} />
      </div>
    );
  } else {
    switch (page.kind) {
      case 'tab': body = <TabContent tab={nav.tab} />; break;
      case 'send': body = <ModernSend to={page.to} tokenId={page.tokenId} />; break;
      case 'receive': body = <ModernReceive />; break;
      case 'add_contact': body = <ModernAddContact />; break;
      case 'contact': body = <ModernContact deviceId={page.deviceId} />; break;
      case 'my_card': body = <ModernMyCard />; break;
      case 'receipts': body = <ModernReceipts />; break;
    }
  }

  // The Wallet tab is headed by who the wallet is: the banner, photo and name.
  const onWallet = classic === null && page.kind === 'tab' && nav.tab === 'wallet';

  return (
    <div className="s-app">
      {onWallet ? null : (
      <header className="s-topbar">
        <div className="s-brand"><span className="s-brand-mark" aria-hidden /> DSM Wallet</div>
        <button type="button" className="s-icon-btn s-me" aria-label="My contact card" onClick={() => modernNav.open({ kind: 'my_card' })}>
          {own.kind === 'read' && own.photo !== null ? <img src={own.photo} alt="" /> : <Icon name="person" />}
        </button>
      </header>
      )}
      <main className="s-body">
        {onWallet ? <ProfileHeader mode="show" onOpen={() => modernNav.open({ kind: 'my_card' })} /> : null}
        {body}
      </main>
      <nav className="s-tabbar" aria-label="Wallet sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            className="s-tab"
            aria-current={classic === null && page.kind === 'tab' && nav.tab === t.id ? 'page' : undefined}
            onClick={() => {
              if (classic !== null) navigationStore.navigate('home');
              modernNav.showTab(t.id);
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
