// SPDX-License-Identifier: Apache-2.0
// Your own contact card on the DGen Game Boy (DSM Amendment A17): the name,
// and the email and phone you choose to share. It rides on your contact code,
// so whoever scans it sees who you are, and can email you a receipt when they
// pay you. The Modern skin's My Card page edits the same card.

import React, { useEffect, useId, useState } from 'react';
import { getOwnProfile, setOwnProfile } from '../../dsm/contacts';
import type { PersonProfile } from '../../domain/types';
import { Notice } from '../common/ScreenFrame';

const BLANK: PersonProfile = { name: '', email: '', phone: '', phoneLookupKey: '' };

const FIELDS: { field: 'name' | 'email' | 'phone'; label: string; max: number; mode: 'text' | 'email' | 'tel' }[] = [
  { field: 'name', label: 'Your name', max: 64, mode: 'text' },
  { field: 'email', label: 'Email (receipts can be sent here)', max: 254, mode: 'email' },
  { field: 'phone', label: 'Phone', max: 32, mode: 'tel' },
];

type Card = { kind: 'reading' } | { kind: 'read'; card: PersonProfile } | { kind: 'failed'; message: string };

export default function MyCardPanel({ onSaved }: { onSaved: () => void }): React.JSX.Element {
  const id = useId();
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

  if (card.kind === 'reading') return <p className="sb-hint">Reading your card…</p>;
  if (card.kind === 'failed') return <Notice kind="error">{card.message}</Notice>;

  const draft = card.card;
  const save = () => {
    setSaid('Saving…');
    setOwnProfile(draft).then(
      (stored) => {
        setCard({ kind: 'read', card: stored });
        setSaid('Saved. Your contact code now carries it.');
        onSaved();
      },
      (e: unknown) => setSaid(e instanceof Error ? e.message : String(e)),
    );
  };

  return (
    <section className="sb-card" aria-labelledby={`${id}-title`}>
      <div id={`${id}-title`} className="sb-card__title">My contact card</div>
      <p className="sb-hint">People who scan your code see this. Leave a line empty to keep it to yourself.</p>
      {FIELDS.map((f) => (
        <div key={f.field} className="sb-field">
          <label htmlFor={`${id}-${f.field}`}>{f.label}</label>
          <input
            id={`${id}-${f.field}`}
            className="sb-input"
            inputMode={f.mode}
            maxLength={f.max}
            value={draft[f.field]}
            onChange={(e) => setCard({ kind: 'read', card: { ...draft, [f.field]: e.target.value } })}
          />
        </div>
      ))}
      <button type="button" className="sb-btn sb-btn--primary sb-btn--block" onClick={save}>Save my card</button>
      {said !== null ? <p className="sb-hint" role="status">{said}</p> : null}
    </section>
  );
}
