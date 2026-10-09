// SPDX-License-Identifier: Apache-2.0
// One contact in the Modern skin: who they are (with a photo the owner sets
// for them: tap the picture), Send, and their details to edit or link to a
// phone contact. The details are the wallet's own, for
// showing and for emailing receipts (DSM Amendment A17).

import React, { useId, useState } from 'react';
import { useContacts } from '../../contexts/ContactsContext';
import { contactsStore } from '../../stores/contactsStore';
import { pickPhoneContact } from '../../dsm/WebViewBridge/phoneContacts';
import type { PersonProfile } from '../../domain/types';
import { Avatar, Icon, PageTitle, personName } from './parts';
import { modernNav } from './modernNav';
import { loadImageFile } from '../../utils/imageCrop';
import ImageCropper from './ImageCropper';
import { contactPhotoStore, useContactPhoto } from './contactPhotos';

/** The size a contact's photo is kept at. */
const PHOTO_SIDE = 320;

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function ModernContact({ deviceId }: { deviceId: string }): React.JSX.Element {
  const { contacts } = useContacts();
  const contact = contacts.find((c) => c.deviceId === deviceId) ?? null;
  const [draft, setDraft] = useState<PersonProfile | null>(null);
  const [said, setSaid] = useState<string | null>(null);
  const [framing, setFraming] = useState<{ image: HTMLImageElement; release: () => void } | null>(null);
  const inputId = useId();
  const setPhoto = useContactPhoto(deviceId);

  if (contact === null) {
    return (
      <>
        <PageTitle title="Contact" onBack={() => modernNav.back()} />
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

  const choosePhoto = (file: File) => {
    setSaid(null);
    loadImageFile(file).then(
      ({ image, release }) => setFraming({ image, release }),
      (e: unknown) => setSaid(messageOf(e)),
    );
  };

  const endFraming = () => {
    framing?.release();
    setFraming(null);
  };

  const keepPhoto = (photo: string | null) => {
    endFraming();
    contactPhotoStore.keep(contact.deviceId, photo).then(
      () => undefined,
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
      <PageTitle title={name} onBack={() => modernNav.back()} />
      <section className="s-card" style={{ textAlign: 'center' }}>
        <input
          id={inputId}
          type="file"
          className="sb-file"
          accept="image/png,image/jpeg,image/webp"
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = '';
            if (file !== undefined) choosePhoto(file);
          }}
        />
        <label htmlFor={inputId} className="s-avatar-pick" aria-label={`Choose a photo for ${name}`}>
          <Avatar name={name} lookupKey={contact.profile?.phoneLookupKey} deviceId={contact.deviceId} large="large" />
          <span className="s-profile-camera" aria-hidden>+</span>
        </label>
        {setPhoto !== null ? (
          <div style={{ marginTop: 8 }}>
            <button type="button" className="s-chip" onClick={() => keepPhoto(null)}>Remove photo</button>
          </div>
        ) : null}
        <div className="s-row-title" style={{ marginTop: 10 }}>{name}</div>
        {held.email.length > 0 ? <div className="s-row-sub">{held.email}</div> : null}
        {held.phone.length > 0 ? <div className="s-row-sub">{held.phone}</div> : null}
      </section>
      <div className="s-stack">
        <button type="button" className="s-btn s-btn-primary" onClick={() => modernNav.open({ kind: 'send', to: contact.deviceId })}>
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
      {framing !== null ? (
        <ImageCropper
          image={framing.image}
          shape="circle"
          title={`Frame ${name.split(' ')[0]}'s photo`}
          width={PHOTO_SIDE}
          height={PHOTO_SIDE}
          onSave={(photo) => keepPhoto(photo)}
          onCancel={endFraming}
        />
      ) : null}
    </>
  );
}
