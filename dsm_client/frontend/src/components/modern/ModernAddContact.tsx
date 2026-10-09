// SPDX-License-Identifier: Apache-2.0
// Adding someone in the Modern skin: scan (or paste) their DSM code, then say
// who they are by picking them from the phone's contacts, or keep the name
// their card gives. Rust reads the code and adds the contact; the details go
// with it (DSM Amendment A17).

import React, { useCallback, useEffect, useState } from 'react';
import { useContacts } from '../../contexts/ContactsContext';
import { readContactCode } from '../../dsm/contacts';
import { pickPhoneContact } from '../../dsm/WebViewBridge/phoneContacts';
import { startNativeQrScannerViaRouter } from '../../dsm/WebViewBridge';
import type { ContactCard } from '../../dsm/types';
import type { PersonProfile } from '../../domain/types';
import { profileFromCard, withPhoneContact } from '../../domain/personProfile';
import { Avatar, Icon, PageTitle } from './parts';
import { modernNav } from './modernNav';

type Step =
  | { kind: 'code' }
  | { kind: 'reading' }
  | { kind: 'who'; card: ContactCard; profile: PersonProfile }
  | { kind: 'adding'; card: ContactCard; profile: PersonProfile }
  | { kind: 'added'; name: string };

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function ModernAddContact(): React.JSX.Element {
  const { addContact } = useContacts();
  const [step, setStep] = useState<Step>({ kind: 'code' });
  const [pasted, setPasted] = useState('');
  const [problem, setProblem] = useState<string | null>(null);

  const read = useCallback((text: string) => {
    setProblem(null);
    setStep({ kind: 'reading' });
    readContactCode(text.trim()).then(
      (card) => setStep({ kind: 'who', card, profile: profileFromCard(card) }),
      (e: unknown) => {
        setProblem(messageOf(e));
        setStep({ kind: 'code' });
      },
    );
  }, []);

  // The native scanner answers on the page's event channel.
  useEffect(() => {
    const onScan = (e: Event) => {
      const detail = (e as CustomEvent<{ topic: string; payloadText?: string }>).detail;
      if (detail?.topic !== 'qr_scan_result') return;
      const text = detail.payloadText;
      if (text !== undefined && text.length > 0) read(text);
    };
    window.addEventListener('dsm-event', onScan);
    return () => window.removeEventListener('dsm-event', onScan);
  }, [read]);

  const scan = () => {
    setProblem(null);
    startNativeQrScannerViaRouter().then(
      () => undefined,
      (e: unknown) => setProblem(`The camera did not open: ${messageOf(e)}`),
    );
  };

  const pick = (card: ContactCard, current: PersonProfile) => {
    pickPhoneContact().then(
      (picked) => {
        if (picked === null) return;
        setStep({ kind: 'who', card, profile: withPhoneContact(current, picked) });
      },
      (e: unknown) => setProblem(`Your contacts did not open: ${messageOf(e)}`),
    );
  };

  const add = (card: ContactCard, profile: PersonProfile) => {
    setStep({ kind: 'adding', card, profile });
    addContact(profile.name, card, profile).then(
      (result) => {
        if (result.accepted) {
          setStep({ kind: 'added', name: profile.name.length > 0 ? profile.name : result.alias });
          return;
        }
        setProblem(result.error);
        setStep({ kind: 'who', card, profile });
      },
      (e: unknown) => {
        setProblem(messageOf(e));
        setStep({ kind: 'who', card, profile });
      },
    );
  };

  return (
    <>
      <PageTitle title="Add Contact" onBack={() => modernNav.back()} />
      {problem !== null ? <div className="s-notice s-error">{problem}</div> : null}

      {step.kind === 'code' || step.kind === 'reading' ? (
        <>
          <p className="s-hint">Ask them to open Receive in their DSM wallet, then scan the code they show you.</p>
          <button type="button" className="s-btn s-btn-primary" disabled={step.kind === 'reading'} onClick={scan}>
            Scan their code
          </button>
          <div className="s-field" style={{ marginTop: 18 }}>
            <label className="s-label" htmlFor="s-paste">Or paste a code they sent you</label>
            <input id="s-paste" className="s-input" placeholder="dsm:contact/v3:…" value={pasted} onChange={(e) => setPasted(e.target.value)} />
          </div>
          <button type="button" className="s-btn s-btn-quiet" disabled={pasted.trim().length === 0 || step.kind === 'reading'} onClick={() => read(pasted)}>
            {step.kind === 'reading' ? 'Reading…' : 'Use this code'}
          </button>
        </>
      ) : null}

      {step.kind === 'who' || step.kind === 'adding' ? (
        <>
          <section className="s-card" style={{ textAlign: 'center' }}>
            <Avatar name={step.profile.name.length > 0 ? step.profile.name : '?'} lookupKey={step.profile.phoneLookupKey} large="large" />
            <div className="s-row-title" style={{ marginTop: 10 }}>{step.profile.name.length > 0 ? step.profile.name : 'Who is this?'}</div>
            {step.profile.email.length > 0 ? <div className="s-row-sub">{step.profile.email}</div> : null}
            {step.profile.phone.length > 0 ? <div className="s-row-sub">{step.profile.phone}</div> : null}
          </section>
          <div className="s-stack">
            <button type="button" className="s-btn s-btn-quiet" disabled={step.kind === 'adding'} onClick={() => pick(step.card, step.profile)}>
              <Icon name="people" /> Pick from phone contacts
            </button>
            <div className="s-field">
              <label className="s-label" htmlFor="s-name">Name</label>
              <input
                id="s-name"
                className="s-input"
                maxLength={64}
                value={step.profile.name}
                onChange={(e) => setStep({ kind: 'who', card: step.card, profile: { ...step.profile, name: e.target.value } })}
              />
            </div>
            <button type="button" className="s-btn s-btn-primary" disabled={step.kind === 'adding'} onClick={() => add(step.card, step.profile)}>
              {step.kind === 'adding' ? 'Adding…' : 'Add to DSM contacts'}
            </button>
          </div>
        </>
      ) : null}

      {step.kind === 'added' ? (
        <section className="s-card" style={{ textAlign: 'center' }}>
          <h2 className="s-section-title">{step.name} is added</h2>
          <p className="s-hint">You can pay them now.</p>
          <button type="button" className="s-btn s-btn-primary" onClick={() => modernNav.showTab('people')}>Done</button>
        </section>
      ) : null}
    </>
  );
}
