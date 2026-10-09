// SPDX-License-Identifier: Apache-2.0
// Pieces the Modern screens share: icons, a person's avatar (the linked phone
// contact's photo, or their initial), and how a person, a balance and a
// history row are named on these screens.

import React, { useEffect, useState } from 'react';
import type { DomainContact, DomainTransaction } from '../../domain/types';
import type { TokenBalanceView } from '../../dsm/types';
import { phoneContactPhoto } from '../../dsm/WebViewBridge/phoneContacts';
import logger from '../../utils/logger';

export type IconName =
  | 'send' | 'receive' | 'people' | 'home' | 'activity' | 'settings' | 'person' | 'back' | 'chevron' | 'share' | 'copy' | 'info'
  | 'tokens' | 'trade' | 'bitcoin' | 'storage' | 'apps' | 'scan';

export function Icon({ name }: { name: IconName }): React.JSX.Element {
  const paths: Record<string, React.ReactNode> = {
    send: <path d="M3 11.5 21 3l-7.5 18-2.6-7.3L3 11.5Z" />,
    receive: <><path d="M12 3v12" /><path d="m7 10 5 5 5-5" /><path d="M4 19h16" /></>,
    people: <><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20c.7-3.6 3.3-5.5 6.5-5.5s5.8 1.9 6.5 5.5" /><circle cx="17" cy="9" r="2.8" /><path d="M16 14.6c2.8 0 5 1.7 5.5 5.4" /></>,
    home: <path d="M4 11 12 4l8 7v9h-5v-6H9v6H4v-9Z" />,
    activity: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3.2" /><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1" /></>,
    person: <><circle cx="12" cy="8" r="4" /><path d="M4 21c.9-4.4 4-6.8 8-6.8s7.1 2.4 8 6.8" /></>,
    back: <path d="M19 12H5m6-6-6 6 6 6" />,
    chevron: <path d="m9 5 7 7-7 7" />,
    share: <><circle cx="18" cy="5" r="2.6" /><circle cx="6" cy="12" r="2.6" /><circle cx="18" cy="19" r="2.6" /><path d="m8.3 10.8 7.4-4.4M8.3 13.2l7.4 4.4" /></>,
    copy: <><rect x="8" y="8" width="12" height="12" rx="2.5" /><path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8" /></>,
    info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7.5v.5" /></>,
    tokens: <><ellipse cx="12" cy="6.5" rx="7" ry="3" /><path d="M5 6.5v5c0 1.7 3.1 3 7 3s7-1.3 7-3v-5" /><path d="M5 11.5v5c0 1.7 3.1 3 7 3s7-1.3 7-3v-5" /></>,
    trade: <><path d="M4 8h14l-4-4" /><path d="M20 16H6l4 4" /></>,
    bitcoin: <><circle cx="12" cy="12" r="9" /><path d="M9.5 7.5h4a2 2 0 0 1 0 4h-4m0 0h4.5a2 2 0 0 1 0 4h-4.5m0-8v8M11 6v1.5M11 15.5V17M13 6v1.5M13 15.5V17" /></>,
    storage: <><rect x="4" y="4" width="16" height="6" rx="2" /><rect x="4" y="14" width="16" height="6" rx="2" /><path d="M8 7h.01M8 17h.01" /></>,
    apps: <><rect x="4" y="4" width="6.5" height="6.5" rx="1.6" /><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.6" /><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.6" /><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.6" /></>,
    scan: <><path d="M4 9V5.5A1.5 1.5 0 0 1 5.5 4H9M15 4h3.5A1.5 1.5 0 0 1 20 5.5V9M20 15v3.5a1.5 1.5 0 0 1-1.5 1.5H15M9 20H5.5A1.5 1.5 0 0 1 4 18.5V15" /><path d="M4 12h16" /></>,
  };
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {paths[name]}
    </svg>
  );
}

/** The name a person goes by on these screens: their details' name, else the contact's alias. */
export function personName(contact: DomainContact): string {
  const name = contact.profile?.name;
  return name !== undefined && name.length > 0 ? name : contact.alias;
}

/** Two avatar colours, alternating by name so a list is not one colour. */
function tone(name: string): 'a' | 'b' {
  return name.length % 2 === 0 ? 'a' : 'b';
}

export function Avatar({ name, lookupKey, large }: { name: string; lookupKey?: string; large?: 'large' }): React.JSX.Element {
  const [photo, setPhoto] = useState<string | null>(null);
  useEffect(() => {
    let live = 'yes';
    if (lookupKey === undefined || lookupKey.length === 0) {
      setPhoto(null);
      return undefined;
    }
    phoneContactPhoto(lookupKey).then(
      (url) => { if (live === 'yes') setPhoto(url); },
      (e: unknown) => logger.warn('[simple] the contact photo was not read:', e),
    );
    return () => { live = 'no'; };
  }, [lookupKey]);
  const initial = name.trim().slice(0, 1).toUpperCase();
  const classes = ['s-avatar', tone(name) === 'b' ? 'b' : '', large === 'large' ? 'large' : ''].filter((c) => c.length > 0).join(' ');
  return (
    <span className={classes}>
      {photo !== null ? <img src={photo} alt="" /> : initial}
    </span>
  );
}

/** The wallet's main currency: the first currency the protocol defines (ERA). */
export function mainBalance(balances: TokenBalanceView[]): TokenBalanceView | null {
  return balances.find((b) => b.protocolDefined && b.holding === 'currency') ?? null;
}

/**
 * Every token the wallet lists, as Rust listed it: the currencies (ERA, dBTC,
 * and every token created or adopted) first, then the one-of-a-kind items.
 */
export function holdings(balances: TokenBalanceView[]): TokenBalanceView[] {
  const items = balances.filter((b) => b.holding === 'object');
  return [...balances.filter((b) => b.holding !== 'object'), ...items];
}

/** What can be sent: every holding with something in it, and the one asked for. */
export function sendable(balances: TokenBalanceView[], asked: string | null): TokenBalanceView[] {
  return holdings(balances).filter((b) => b.baseUnits > 0n || b.tokenId === asked);
}

/** The history rows the Modern skin lists: payments, sent or received. */
const PAYMENT_TYPES = new Set(['online', 'bilateral_offline', 'faucet']);

export type ActivityRow = {
  tx: DomainTransaction;
  direction: 'in' | 'out';
  /** Who the payment was with, as the person is named here. */
  who: string;
  /** The contact behind it, when it is one. */
  contact: DomainContact | null;
  amount: string;
};

export function activityRows(transactions: DomainTransaction[], contacts: DomainContact[]): ActivityRow[] {
  return transactions
    .filter((tx) => PAYMENT_TYPES.has(tx.txType))
    .map((tx) => {
      const direction = tx.amount < 0n ? 'out' : 'in';
      const other = direction === 'out' ? tx.toDeviceId : tx.fromDeviceId;
      const contact = contacts.find((c) => c.deviceId === other) ?? null;
      const who = contact !== null ? personName(contact) : tx.txType === 'faucet' ? 'DSM welcome' : tx.recipient;
      const amount = tx.displayAmount.startsWith('-') ? tx.displayAmount.slice(1) : tx.displayAmount;
      return { tx, direction, who, contact, amount };
    });
}

export function ActivityItem({ row }: { row: ActivityRow }): React.JSX.Element {
  const verb = row.direction === 'out' ? 'To' : 'From';
  return (
    <div className="s-row">
      <Avatar name={row.who} lookupKey={row.contact?.profile?.phoneLookupKey} />
      <div className="s-row-main">
        <div className="s-row-title">{row.who}</div>
        <div className="s-row-sub">{row.tx.memo !== undefined && row.tx.memo.length > 0 ? row.tx.memo : `${verb} ${row.who}`}</div>
      </div>
      <div className="s-row-end">
        <div className={`s-amount ${row.direction}`}>{row.direction === 'out' ? '−' : '+'} {row.amount} {row.tx.tokenId}</div>
        <div className="s-row-sub">{row.direction === 'out' ? 'Sent' : 'Received'}</div>
      </div>
    </div>
  );
}

/** A page opened over a tab: its title, and Back. */
export function PageTitle({ title, onBack }: { title: string; onBack: () => void }): React.JSX.Element {
  return (
    <div className="s-title-row">
      <button type="button" className="s-icon-btn" aria-label="Back" onClick={onBack}><Icon name="back" /></button>
      <h1 className="s-title">{title}</h1>
    </div>
  );
}

/** A bottom sheet over the screen. */
export function Sheet({ label, onClose, children }: { label: string; onClose: () => void; children: React.ReactNode }): React.JSX.Element {
  return (
    <div className="s-sheet-backdrop" onClick={onClose}>
      <div className="s-sheet" role="dialog" aria-label={label} onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}
