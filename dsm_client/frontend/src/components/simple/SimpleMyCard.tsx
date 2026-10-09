// SPDX-License-Identifier: Apache-2.0
// Your own contact card (DSM Amendment A17): the name, and the email and
// phone you choose to share. It rides on your DSM code, so whoever scans it
// sees who you are, and can email you a receipt when they pay you.

import React, { useEffect, useState } from 'react';
import { getOwnProfile, setOwnProfile } from '../../dsm/contacts';
import type { PersonProfile } from '../../domain/types';
import { Avatar, PageTitle } from './parts';
import { simpleNav } from './simpleNav';

const BLANK: PersonProfile = { name: '', email: '', phone: '', phoneLookupKey: '' };

type Card = { kind: 'reading' } | { kind: 'read'; card: PersonProfile } | { kind: 'failed'; message: string };

export default function SimpleMyCard(): React.JSX.Element {
  const [card, setCard] = useState<Card>({ kind: 'reading' });
  const [said, setSaid] = useState<string | null>(null);

  useEffect(() => {
    let live = 'yes';
    getOwnProfile().then(
      (own) => { if (live === 'yes') setCard({ kind: 'read', card: own !== null ? own : BLANK }); },
      (e: unknown) => { if (live === 'yes') setCard({ kind: 'failed', message: e instanceof Error ? e.message : String(e) }); },
    );
    return () => { live = 'no'; };
  }, []);

  if (card.kind !== 'read') {
    return (
      <>
        <PageTitle title="My Card" onBack={() => simpleNav.back()} />
        {card.kind === 'reading' ? <div className="s-empty">Loading…</div> : <div className="s-notice s-error">{card.message}</div>}
      </>
    );
  }

  const draft = card.card;
  const save = () => {
    setSaid('Saving…');
    setOwnProfile(draft).then(
      (stored) => {
        setCard({ kind: 'read', card: stored });
        setSaid('Saved. Your DSM code now carries it.');
      },
      (e: unknown) => setSaid(e instanceof Error ? e.message : String(e)),
    );
  };

  return (
    <>
      <PageTitle title="My Card" onBack={() => simpleNav.back()} />
      <section className="s-card" style={{ textAlign: 'center' }}>
        <Avatar name={draft.name.length > 0 ? draft.name : '?'} large="large" />
        <div className="s-row-title" style={{ marginTop: 10 }}>{draft.name.length > 0 ? draft.name : 'Your name'}</div>
        <p className="s-hint">People who scan your code see this. Leave a line empty to keep it to yourself.</p>
      </section>
      {(['name', 'email', 'phone'] as const).map((field) => (
        <div key={field} className="s-field">
          <label className="s-label" htmlFor={`s-card-${field}`}>{field === 'name' ? 'Your name' : field === 'email' ? 'Email (receipts can be sent here)' : 'Phone'}</label>
          <input
            id={`s-card-${field}`}
            className="s-input"
            inputMode={field === 'email' ? 'email' : field === 'phone' ? 'tel' : 'text'}
            maxLength={field === 'email' ? 254 : field === 'phone' ? 32 : 64}
            value={draft[field]}
            onChange={(e) => setCard({ kind: 'read', card: { ...draft, [field]: e.target.value } })}
          />
        </div>
      ))}
      <button type="button" className="s-btn s-btn-primary" onClick={save}>Save my card</button>
      {said !== null ? <p className="s-hint" style={{ textAlign: 'center', marginTop: 12 }}>{said}</p> : null}
    </>
  );
}
