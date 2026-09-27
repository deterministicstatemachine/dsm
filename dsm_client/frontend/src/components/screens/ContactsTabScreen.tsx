/* SPDX-License-Identifier: Apache-2.0 */
/* eslint-disable no-console */
// Contacts on the StateBoy frame: the people this wallet deals with, adding
// one from a contact code, and this wallet's own code.
const CONTACTS_DEBUG = false; // flip to true for on-device BLE/contacts debugging
import React, { useCallback, useEffect, useState, useRef, useMemo } from 'react';
import BluetoothIcon from '../icons/BluetoothIcon';
import QRCodeScannerPanel from '../qr/QRCodeScannerPanel';
import MyContactInfoPanel from '../contacts/MyContactInfoPanel';
import { useContacts } from '../../contexts/ContactsContext';
import { useTransactions } from '../../hooks/useTransactions';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import StitchedReceiptDetails from '../receipts/StitchedReceiptDetails';
import { useDpadNav } from '../../hooks/useDpadNav';
import { Disclosure, Notice, ScreenFrame, ScreenTabs } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';
import type { DomainContact } from '../../domain/types';

interface Props { onNavigate?: (screen: string) => void; eraTokenSrc?: string }

type Tab = 'list' | 'add' | 'myqr';

const TABS: ReadonlyArray<{ id: Tab; label: string }> = [
  { id: 'list', label: 'My Contacts' },
  { id: 'add', label: 'Add Contact' },
  { id: 'myqr', label: 'My QR' },
];

const TAB_STORAGE_KEY = 'dsm_contacts_active_tab';

/** Where a contact's pairing stands, as Rust states it on the contact. */
function pairingLineFor(c: DomainContact): string | null {
  switch (c.pairing) {
    case 'paired': return 'Paired over Bluetooth';
    case 'connected': return 'Connecting…';
    case 'searching':
    case 'retrying': return 'Pairing…';
    default: return null;
  }
}

const ContactsTabScreen: React.FC<Props> = () => {
  const [activeTab, setActiveTab] = useState<Tab>(() => {
    try {
      const saved = localStorage.getItem(TAB_STORAGE_KEY);
      if (saved === 'list' || saved === 'add' || saved === 'myqr') return saved;
    } catch {}
    return 'list';
  });
  const { contacts, refreshContacts, isLoading: contextLoading } = useContacts();
  const { transactions, refresh: refreshTransactions } = useTransactions();
  const [selected, setSelected] = useState<number | null>(null);
  const [error] = useState<string | null>(null);

  // Debounce ref to prevent rapid refresh calls
  const refreshPendingRef = useRef(false);

  // Debounced load function - prevents rapid-fire refreshes
  const load = useCallback(async (reason?: string) => {
    if (CONTACTS_DEBUG) console.log('[ContactsTab] Refreshing contacts:', reason || 'manual');
    await refreshContacts();
  }, [refreshContacts]);

  // Load contacts on mount
  useEffect(() => { void load('mount'); }, [load]);

  // Load when switching to ANY tab - ensures pairing checks have fresh contact data
  useEffect(() => {
    if (CONTACTS_DEBUG) console.log('[ContactsTab] Tab switched to:', activeTab);
    // Optimization: Do not flood reload when switching to QR screens (myqr/add)
    // This prevents BridgeGate congestion when generating the QR code.
    if (activeTab === 'list') {
      void load('tab-switch');
      void refreshTransactions();
    }
    try {
      localStorage.setItem(TAB_STORAGE_KEY, activeTab);
    } catch {}
  }, [activeTab, load, refreshTransactions]);

  // Periodic refresh to catch backend updates (e.g., BLE pairing completion)
  useEffect(() => {
    const interval = setInterval(() => {
      void load('periodic');
    }, 5000);
    return () => clearInterval(interval);
  }, [load]);

  // Listen for BLE mapping events - refresh the list. An added contact reaches
  // this screen through the contacts store, which the add itself refreshes.
  useEffect(() => {
    const offBleMapped = bridgeEvents.on('contact.bleMapped', () => {
      if (CONTACTS_DEBUG) console.log('[ContactsTab] contact.bleMapped event received');
      if (refreshPendingRef.current) return;
      refreshPendingRef.current = true;
      queueMicrotask(() => {
        refreshPendingRef.current = false;
        void load('ble-mapped');
      });
    });

    const offBleUpdated = bridgeEvents.on('contact.bleUpdated', () => {
      if (CONTACTS_DEBUG) console.log('[ContactsTab] contact.bleUpdated event received');
      if (refreshPendingRef.current) return;
      refreshPendingRef.current = true;
      queueMicrotask(() => {
        refreshPendingRef.current = false;
        void load('ble-updated');
      });
    });

    // A pairing moved on: the list states where it stands now.
    const offPairingStatus = bridgeEvents.on('ble.pairingStatus', () => {
      if (refreshPendingRef.current) return;
      refreshPendingRef.current = true;
      queueMicrotask(() => {
        refreshPendingRef.current = false;
        void load('pairing-status');
      });
    });

    return () => {
      offBleMapped();
      offBleUpdated();
      offPairingStatus();
    };
  }, [load]);

  // When pairing runs is Rust's: while the app is in the foreground with
  // Bluetooth on and permitted, until no contact is left unpaired. Where it
  // stands is Rust's too: each contact carries its phase from the pairing
  // loop, and the line shows the furthest a pairing has got.
  const pairingLine: 'connected' | 'searching' | null = contacts.some((c) => c.pairing === 'connected')
    ? 'connected'
    : contacts.some((c) => c.pairing === 'searching' || c.pairing === 'retrying')
      ? 'searching'
      : null;

  // Only on a cold start with no contacts at all: a refresh with rows already
  // on screen is near-instant and would only flicker.
  const showLoading = contextLoading && contacts.length === 0;

  // --- D-pad navigation ---
  // Items: 3 tab buttons + content items (contact rows on list tab, or scan button if empty)
  const contentItemCount = activeTab === 'list'
    ? (contacts.length > 0 ? contacts.length : 1) // contacts or "Scan QR Code" button
    : 0; // add/myqr tabs have no navigable items below tabs
  const navItemCount = 3 + contentItemCount;

  const navActions = useMemo(() => {
    const actions: Array<() => void> = [
      () => setActiveTab('list'),
      () => setActiveTab('add'),
      () => setActiveTab('myqr'),
    ];
    if (activeTab === 'list') {
      if (contacts.length > 0) {
        contacts.forEach((_c, i) => {
          actions.push(() => setSelected(selected === i ? null : i));
        });
      } else {
        actions.push(() => setActiveTab('add')); // "Scan QR Code" button
      }
    }
    return actions;
  }, [activeTab, contacts, selected]);

  const { focusedIndex } = useDpadNav({
    itemCount: navItemCount,
    onSelect: (idx) => navActions[idx]?.(),
  });

  const fc = (idx: number) => (idx === focusedIndex ? ' focused' : '');

  return (
    <ScreenFrame
      title="Contacts"
      className="contacts-screen"
      info={(
        <InfoTip title="Contacts">
          <p><b>My Contacts</b> lists everyone you have added. Open one for its device, genesis and key, and the receipts you hold with it.</p>
          <p><b>Add Contact</b> reads someone&apos;s contact code, from the camera or pasted. <b>My QR</b> shows your own code, so others can add you.</p>
          <p>Bluetooth pairing runs on its own while the app is open with Bluetooth on, until every contact&apos;s appliance has been met. Where it stands is shown on the list.</p>
        </InfoTip>
      )}
      actions={activeTab === 'list' ? (
        <button
          type="button"
          onClick={() => { void load('manual'); void refreshTransactions(); }}
          className={`sb-icon-btn${contextLoading ? ' spinning' : ''}`}
          disabled={contextLoading}
          title="Refresh"
          aria-label="Refresh"
        >
          <img src="images/icons/icon_refresh.svg" alt="" />
        </button>
      ) : undefined}
      tabs={(
        <ScreenTabs
          tabs={TABS}
          active={activeTab}
          onChange={setActiveTab}
          ariaLabel="Contact sections"
          dataTour="contacts-tabs"
          focusedIndex={focusedIndex < 3 ? focusedIndex : undefined}
        />
      )}
      banner={error ? <Notice kind="error" banner>{error}</Notice> : null}
    >
      {activeTab === 'list' ? (
        <div className="contacts-list-tab">
          {/* Where pairing stands, as Rust states it on each contact */}
          {pairingLine && (
            <section className="sb-card sb-card--dark" aria-live="polite">
              <div className="sb-row" style={{ padding: 0, borderBottom: 0 }}>
                <span className="sb-row__lead">
                  <BluetoothIcon size={18} color="var(--bg)" />
                </span>
                <div className="sb-row__main">
                  <div className="sb-row__title">
                    {pairingLine === 'searching' && 'Scanning for Peers'}
                    {pairingLine === 'connected' && 'Connected'}
                  </div>
                  <div className="sb-row__sub">
                    {pairingLine === 'searching' && 'Keep the app open on both appliances, near each other'}
                    {pairingLine === 'connected' && 'Exchanging identity...'}
                  </div>
                </div>
              </div>
            </section>
          )}

          {showLoading ? (
            <div className="sb-empty">Loading contacts{'…'}</div>
          ) : contacts.length === 0 ? (
            <div className="sb-empty">
              <div style={{ fontWeight: 700, marginBottom: 4 }}>No contacts yet</div>
              <div>Scan a contact&#39;s QR code to get started</div>
              <button
                type="button"
                className={`sb-btn sb-btn--primary${fc(3)}`}
                style={{ marginTop: 12 }}
                onClick={() => setActiveTab('add')}
              >
                Scan QR Code
              </button>
            </div>
          ) : (
            <section className="sb-card">
              {contacts.map((c, i) => {
                const isOpen = selected === i;
                const toggle = () => setSelected(isOpen ? null : i);
                const sub = pairingLineFor(c);
                const contactTxs = isOpen
                  ? transactions.filter((tx) => tx.fromDeviceId === c.deviceId || tx.toDeviceId === c.deviceId)
                  : [];
                return (
                  <React.Fragment key={c.deviceId}>
                    <div
                      className={`sb-row sb-row--tap${isOpen ? ' is-open' : ''}${fc(i + 3)}`}
                      role="button"
                      tabIndex={0}
                      aria-expanded={isOpen}
                      onClick={toggle}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          toggle();
                        }
                      }}
                    >
                      <div className="sb-row__main">
                        <div className="sb-row__title">{c.alias}</div>
                        {sub && <div className="sb-row__sub">{sub}</div>}
                      </div>
                      {c.bleAddress && (
                        <span className="sb-row__lead" title="Bluetooth address known">
                          <BluetoothIcon size={12} color="var(--text-dark)" />
                        </span>
                      )}
                      <span className="sb-row__chev" aria-hidden="true">{isOpen ? '▾' : '›'}</span>
                    </div>

                    {isOpen && (
                      <div className="sb-row__detail">
                        <div className="sb-card sb-card--dark" style={{ marginBottom: 0 }}>
                          <div className="sb-card__title">
                            <span>{c.pairing === 'paired' ? 'BLE PAIRED' : c.genesisVerifiedOnline ? 'VERIFIED' : 'NOT VERIFIED'}</span>
                          </div>
                          <div className="sb-kv">
                            <span className="sb-kv__k">Device</span>
                            <span className="sb-kv__v sb-kv__v--mono">{c.deviceId}</span>
                          </div>
                          <div className="sb-kv">
                            <span className="sb-kv__k">Genesis</span>
                            <span className="sb-kv__v sb-kv__v--mono">{c.genesisHash}</span>
                          </div>
                          <div className="sb-kv">
                            <span className="sb-kv__k">Chain tip</span>
                            <span className="sb-kv__v sb-kv__v--mono">{c.chainTip ? c.chainTip : '—'}</span>
                          </div>
                          <div className="sb-kv">
                            <span className="sb-kv__k">Pub Key</span>
                            <span className="sb-kv__v sb-kv__v--mono">
                              {c.signingPublicKey.length > 24 ? `${c.signingPublicKey.slice(0, 12)}...${c.signingPublicKey.slice(-10)}` : c.signingPublicKey}
                            </span>
                          </div>
                          <div className="sb-kv">
                            <span className="sb-kv__k">Verified</span>
                            <span className="sb-kv__v">{c.genesisVerifiedOnline ? 'YES' : 'NO'}</span>
                          </div>

                          <Disclosure summary={`Stitched receipts (${contactTxs.length})`} className="sb-details--plain">
                            {contactTxs.length === 0 ? (
                              <div className="sb-hint sb-hint--tight">No receipts yet</div>
                            ) : (
                              contactTxs.map((tx, idx) => {
                                const direction = tx.amount < 0n ? 'Sent' : 'Received';
                                const amountLabel = `${tx.displayAmount} ${tx.tokenId}`;
                                return (
                                  <Disclosure key={`${tx.txId}-${idx}`} summary={`#${idx + 1} · ${direction} ${amountLabel}`} className="sb-details--plain">
                                    <div className="sb-kv">
                                      <span className="sb-kv__k">Tx ID</span>
                                      <span className="sb-kv__v sb-kv__v--mono">{tx.txId}</span>
                                    </div>
                                    <div className="sb-kv">
                                      <span className="sb-kv__k">Type</span>
                                      <span className="sb-kv__v">{tx.txType}</span>
                                    </div>
                                    <StitchedReceiptDetails bytes={tx.stitchedReceipt} />
                                  </Disclosure>
                                );
                              })
                            )}
                          </Disclosure>
                        </div>
                      </div>
                    )}
                  </React.Fragment>
                );
              })}
            </section>
          )}
        </div>
      ) : activeTab === 'add' ? (
        <QRCodeScannerPanel onCancel={() => setActiveTab('list')} />
      ) : (
        <MyContactInfoPanel />
      )}
    </ScreenFrame>
  );
};

export default ContactsTabScreen;
