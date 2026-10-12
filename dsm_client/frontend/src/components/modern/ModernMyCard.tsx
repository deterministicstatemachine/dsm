// SPDX-License-Identifier: Apache-2.0
// Your own contact card (DSM Amendment A17): your banner and photo (kept on
// this phone), the name, email and phone you choose to share, and your code. The card rides on your DSM code, so
// whoever scans it sees who you are, and can email you a receipt when they
// pay you. Saving says so in a pop-up and goes back to the wallet.

import React, { useEffect, useState } from 'react';
import { getOwnProfile, setOwnProfile } from '../../dsm/contacts';
import type { PersonProfile } from '../../domain/types';
import { PageTitle } from './parts';
import { useFx } from '../fx/FxProvider';
import ProfileHeader from './ProfileHeader';
import { ownCardStore } from './ownCard';
import { modernNav } from './modernNav';
import ModernMyCode from './ModernMyCode';

const BLANK: PersonProfile = { name: '', email: '', phone: '', phoneLookupKey: '' };

type Card = { kind: 'reading' } | { kind: 'read'; card: PersonProfile } | { kind: 'failed'; message: string };

export default function ModernMyCard(): React.JSX.Element {
  const [card, setCard] = useState<Card>({ kind: 'reading' });
  const [said, setSaid] = useState<string | null>(null);
  const [saving, setSaving] = useState<'idle' | 'saving'>('idle');
  const fx = useFx();

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
        <PageTitle title="My Card" onBack={() => modernNav.back()} />
        {card.kind === 'reading' ? <div className="s-empty">Loading…</div> : <div className="s-notice s-error">{card.message}</div>}
      </>
    );
  }

  const draft = card.card;
  const save = () => {
    if (saving === 'saving') return;
    setSaving('saving');
    setSaid(null);
    setOwnProfile(draft).then(
      (stored) => {
        ownCardStore.setName(stored.name);
        // Saved: a pop-up says so, and the wallet is shown again. Nothing on
        // this page changes under the owner on the way out.
        fx.play({ anim: 'confirm', title: 'Saved', caption: 'Your card is saved, and your DSM code carries it.', tone: 'good', okLabel: 'OK' });
        modernNav.showTab('wallet');
      },
      (e: unknown) => {
        setSaving('idle');
        setSaid(e instanceof Error ? e.message : String(e));
      },
    );
  };

  return (
    <>
      <PageTitle title="My Card" onBack={() => modernNav.back()} />
      <ProfileHeader mode="edit" />
      <p className="s-hint">People who scan your code see your name, and the email and phone you add. Leave a line empty to keep it to yourself.</p>
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
      <button type="button" className="s-btn s-btn-primary" disabled={saving === 'saving'} onClick={save}>
        {saving === 'saving' ? 'Saving…' : 'Save my card'}
      </button>
      {said !== null ? <div className="s-notice s-error" role="alert" style={{ marginTop: 12 }}>{said}</div> : null}
      <div style={{ marginTop: 18 }}>
        <ModernMyCode heading="Your code: let someone scan it to add you." />
      </div>
    </>
  );
}
