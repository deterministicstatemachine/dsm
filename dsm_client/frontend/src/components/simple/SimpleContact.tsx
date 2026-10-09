// SPDX-License-Identifier: Apache-2.0
// One contact in the Simple skin: who they are, Send, and their details to
// edit or link to a phone contact. The details are the wallet's own, for
// showing and for emailing receipts (DSM Amendment A17).

import React, { useState } from 'react';
import { useContacts } from '../../contexts/ContactsContext';
import { contactsStore } from '../../stores/contactsStore';
import { pickPhoneContact } from '../../dsm/WebViewBridge/phoneContacts';
import type { PersonProfile } from '../../domain/types';
import { Avatar, Icon, PageTitle, personName } from './parts';
import { simpleNav } from './simpleNav';

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function SimpleContact({ deviceId }: { deviceId: string }): React.JSX.Element {
  const { contacts } = useContacts();
  const contact = contacts.find((c) => c.deviceId === deviceId) ?? null;
  const [draft, setDraft] = useState<PersonProfile | null>(null);
  const [said, setSaid] = useState<string | null>(null);

  if (contact === null) {
    return (
      <>
        <PageTitle title="Contact" onBack={() => simpleNav.back()} />
        <div className="s-empty">This contact is not in your wallet.</div>
      </>
    );
  }

  const name = personName(contact);
  const held: PersonProfile = contact.profile !== undefined
    ? contact.profile
    : { name: contact.alias, email: '', phone: '', phoneLookupKey: '' };

  const save = (profile: PersonProfile) => {
    setSaid('Saving…');
    contactsStore.setProfile(contact.deviceId, profile).then(
      () => {
        setDraft(null);
        setSaid('Saved');
      },
      (e: unknown) => setSaid(messageOf(e)),
    );
  };

  const link = () => {
    pickPhoneContact().then(
      (picked) => {
        if (picked === null) return;
        setDraft({
          name: picked.name.length > 0 ? picked.name : held.name,
          email: picked.email.length > 0 ? picked.email : held.email,
          phone: picked.phone.length > 0 ? picked.phone : held.phone,
          phoneLookupKey: picked.phoneLookupKey,
        });
      },
      (e: unknown) => setSaid(`Your contacts did not open: ${messageOf(e)}`),
    );
  };

  return (
    <>
      <PageTitle title={name} onBack={() => simpleNav.back()} />
      <section className="s-card" style={{ textAlign: 'center' }}>
        <Avatar name={name} lookupKey={contact.profile?.phoneLookupKey} large="large" />
        <div className="s-row-title" style={{ marginTop: 10 }}>{name}</div>
        {held.email.length > 0 ? <div className="s-row-sub">{held.email}</div> : null}
        {held.phone.length > 0 ? <div className="s-row-sub">{held.phone}</div> : null}
      </section>
      <div className="s-stack">
        <button type="button" className="s-btn s-btn-primary" onClick={() => simpleNav.open({ kind: 'send', to: contact.deviceId })}>
          <Icon name="send" /> Send to {name.split(' ')[0]}
        </button>
        {draft === null ? (
          <>
            <button type="button" className="s-btn s-btn-quiet" onClick={() => setDraft(held)}>Edit details</button>
            <button type="button" className="s-btn s-btn-quiet" onClick={link}><Icon name="people" /> Link a phone contact</button>
          </>
        ) : (
          <section className="s-card" aria-label="Edit details">
            {(['name', 'email', 'phone'] as const).map((field) => (
              <div key={field} className="s-field">
                <label className="s-label" htmlFor={`s-edit-${field}`}>{field === 'name' ? 'Name' : field === 'email' ? 'Email (for receipts)' : 'Phone'}</label>
                <input
                  id={`s-edit-${field}`}
                  className="s-input"
                  inputMode={field === 'email' ? 'email' : field === 'phone' ? 'tel' : 'text'}
                  value={draft[field]}
                  onChange={(e) => setDraft({ ...draft, [field]: e.target.value })}
                />
              </div>
            ))}
            <div className="s-stack">
              <button type="button" className="s-btn s-btn-primary" onClick={() => save(draft)}>Save</button>
              <button type="button" className="s-btn s-btn-quiet" onClick={() => setDraft(null)}>Cancel</button>
            </div>
          </section>
        )}
      </div>
      {said !== null ? <p className="s-hint" style={{ textAlign: 'center', marginTop: 12 }}>{said}</p> : null}
    </>
  );
}
