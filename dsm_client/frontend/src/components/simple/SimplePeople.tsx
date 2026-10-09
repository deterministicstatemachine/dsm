// SPDX-License-Identifier: Apache-2.0
// The Simple skin's People tab: everyone in the wallet, named as the owner
// linked them, with Send beside each, and Add contact.

import React, { useState } from 'react';
import { useContacts } from '../../contexts/ContactsContext';
import { Avatar, Icon, personName } from './parts';
import { simpleNav } from './simpleNav';

export default function SimplePeople(): React.JSX.Element {
  const { contacts, isLoading, error } = useContacts();
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
      <section className="s-card" aria-label="Contacts">
        {shown.length === 0 ? (
          <div className="s-empty">{isLoading ? 'Loading…' : contacts.length === 0 ? 'Nobody yet. Add someone who uses DSM to pay them.' : 'Nobody by that name.'}</div>
        ) : (
          shown.map((c) => (
            <div key={c.deviceId} className="s-row">
              <button type="button" className="s-row" style={{ padding: 0 }} onClick={() => simpleNav.open({ kind: 'contact', deviceId: c.deviceId })}>
                <Avatar name={personName(c)} lookupKey={c.profile?.phoneLookupKey} />
                <span className="s-row-main">
                  <span className="s-row-title" style={{ display: 'block' }}>{personName(c)}</span>
                  <span className="s-row-sub" style={{ display: 'block' }}>Send to {personName(c).split(' ')[0]}</span>
                </span>
              </button>
              <button type="button" className="s-btn s-btn-small s-btn-primary" onClick={() => simpleNav.open({ kind: 'send', to: c.deviceId })}>
                <Icon name="send" /> Send
              </button>
            </div>
          ))
        )}
      </section>
      <button type="button" className="s-card s-row" onClick={() => simpleNav.open({ kind: 'add_contact' })}>
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
