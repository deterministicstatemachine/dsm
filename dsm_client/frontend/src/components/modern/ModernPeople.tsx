// SPDX-License-Identifier: Apache-2.0
// The Modern skin's People tab: everyone in the wallet, named as the owner
// linked them, with Send beside each, and Add contact. Bluetooth pairing with
// them runs on its own (Rust's, while the app is open with Bluetooth on);
// this tab shows where it stands and reads the list again as it moves on.

import React, { useEffect, useState } from 'react';
import { bridgeEvents } from '../../bridge/bridgeEvents';
import logger from '../../utils/logger';
import { pairingStage, pairingWordFor } from '../../domain/pairing';
import { useContacts } from '../../contexts/ContactsContext';
import { Avatar, Icon, personName } from './parts';
import { modernNav } from './modernNav';

export default function ModernPeople(): React.JSX.Element {
  const { contacts, isLoading, error, refreshContacts } = useContacts();
  const stage = pairingStage(contacts);

  // While the tab is open the list is read again: on opening, every few
  // seconds, and whenever a pairing moves on, so a finished pairing shows.
  useEffect(() => {
    const read = () => {
      refreshContacts().then(
        () => undefined,
        (e: unknown) => logger.warn('[modern] the contacts were not read again:', e),
      );
    };
    read();
    const every = setInterval(read, 5000);
    const offStatus = bridgeEvents.on('ble.pairingStatus', read);
    return () => {
      clearInterval(every);
      offStatus();
    };
  }, [refreshContacts]);
  const [search, setSearch] = useState('');
  const shown = contacts.filter((c) => personName(c).toLowerCase().includes(search.trim().toLowerCase()));

  return (
    <>
      <h1 className="s-title">People</h1>
      <p className="s-subtitle">Ready to pay</p>
      <p className="s-hint">These contacts are on DSM.</p>
      {contacts.length > 4 ? (
        <input className="s-input" style={{ marginBottom: 14 }} placeholder="Search DSM contacts" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search DSM contacts" />
      ) : null}
      {error !== null ? <div className="s-notice s-error">{error}</div> : null}
      {stage !== null ? (
        <div className="s-notice s-pairing" aria-live="polite">
          <Icon name="bluetooth" />
          <div>
            <strong>{stage === 'connected' ? 'Connected' : 'Looking for your contacts nearby'}</strong>
            <div>{stage === 'connected' ? 'Exchanging identity…' : 'Keep the app open on both phones, near each other.'}</div>
          </div>
        </div>
      ) : null}
      <section className="s-card" aria-label="Contacts">
        {shown.length === 0 ? (
          <div className="s-empty">{isLoading ? 'Loading…' : contacts.length === 0 ? 'Nobody yet. Add someone who uses DSM to pay them.' : 'Nobody by that name.'}</div>
        ) : (
          shown.map((c) => (
            <div key={c.deviceId} className="s-row">
              <button type="button" className="s-row" style={{ padding: 0, flex: '1 1 auto', minWidth: 0 }} onClick={() => modernNav.open({ kind: 'contact', deviceId: c.deviceId })}>
                <Avatar name={personName(c)} lookupKey={c.profile?.phoneLookupKey} deviceId={c.deviceId} />
                <span className="s-row-main">
                  <span className="s-row-title" style={{ display: 'block' }}>{personName(c)}</span>
                  {pairingWordFor(c) !== null ? (
                    <span className="s-row-sub s-paired" style={{ display: 'flex' }}><Icon name="bluetooth" />{pairingWordFor(c)}</span>
                  ) : (
                    <span className="s-row-sub" style={{ display: 'block' }}>Send to {personName(c).split(' ')[0]}</span>
                  )}
                </span>
              </button>
              <button type="button" className="s-btn s-btn-small s-btn-primary" style={{ flex: '0 0 auto' }} onClick={() => modernNav.open({ kind: 'send', to: c.deviceId })}>
                <Icon name="send" /> Send
              </button>
            </div>
          ))
        )}
      </section>
      <button type="button" className="s-card s-row" onClick={() => modernNav.open({ kind: 'add_contact' })}>
        <span className="s-avatar b"><Icon name="people" /></span>
        <span className="s-row-main">
          <span className="s-row-title" style={{ display: 'block' }}>Add Contact</span>
          <span className="s-row-sub" style={{ display: 'block' }}>Scan their DSM code, then pick them from your phone</span>
        </span>
        <Icon name="chevron" />
      </button>
      <div className="s-notice"><Icon name="info" /> Only people who use DSM are shown here. Add someone by scanning the code on their Receive screen.</div>
    </>
  );
}
