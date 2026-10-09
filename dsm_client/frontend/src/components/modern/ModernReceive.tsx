// SPDX-License-Identifier: Apache-2.0
// The Modern skin's Receive page: your contact code as a QR for someone to
// scan, and to share or copy. Paying you starts with them adding you.

import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { getContactCode } from '../../dsm/contacts';
import { shareText } from '../../dsm/WebViewBridge/phoneContacts';
import { copyText } from '../../utils/anchorDisplay';
import { Icon, PageTitle } from './parts';
import { modernNav } from './modernNav';

type Code = { kind: 'reading' } | { kind: 'read'; code: string; qr: string } | { kind: 'failed'; message: string };

export default function ModernReceive(): React.JSX.Element {
  const [code, setCode] = useState<Code>({ kind: 'reading' });
  const [said, setSaid] = useState<string | null>(null);

  useEffect(() => {
    let live = 'yes';
    getContactCode()
      .then(async (text) => ({ text, qr: await QRCode.toDataURL(text, { margin: 1, width: 440 }) }))
      .then(
        ({ text, qr }) => { if (live === 'yes') setCode({ kind: 'read', code: text, qr }); },
        (e: unknown) => { if (live === 'yes') setCode({ kind: 'failed', message: e instanceof Error ? e.message : String(e) }); },
      );
    return () => { live = 'no'; };
  }, []);

  const report = (what: Promise<unknown>, done: string) => {
    what.then(
      () => setSaid(done),
      (e: unknown) => setSaid(e instanceof Error ? e.message : String(e)),
    );
  };

  return (
    <>
      <PageTitle title="Receive" onBack={() => modernNav.back()} />
      <section className="s-card s-balance" style={{ textAlign: 'center' }} aria-label="Your code">
        <p className="s-row-title" style={{ whiteSpace: 'normal', fontSize: 22 }}>Let someone scan this code to pay you.</p>
        {code.kind === 'read' ? (
          <>
            <div className="s-qr"><img src={code.qr} alt="Your DSM code" /></div>
            <div className="s-row-sub">Your DSM Wallet</div>
            <div className="s-code">{code.code.slice(-16)}</div>
          </>
        ) : code.kind === 'reading' ? (
          <div className="s-empty">Getting your code…</div>
        ) : (
          <div className="s-notice s-error">{code.message}</div>
        )}
      </section>
      <div className="s-stack">
        <button
          type="button"
          className="s-btn s-btn-primary"
          disabled={code.kind !== 'read'}
          onClick={() => { if (code.kind === 'read') report(shareText(code.code), 'Choose where to send it.'); }}
        >
          <Icon name="share" /> Share My Code
        </button>
        <button
          type="button"
          className="s-btn s-btn-quiet"
          disabled={code.kind !== 'read'}
          onClick={() => { if (code.kind === 'read') report(copyText(code.code), 'Copied'); }}
        >
          <Icon name="copy" /> Copy My Code
        </button>
        <button type="button" className="s-btn s-btn-quiet" onClick={() => modernNav.open({ kind: 'my_card' })}>
          <Icon name="person" /> My contact card
        </button>
      </div>
      {said !== null ? <p className="s-hint" style={{ textAlign: 'center', marginTop: 12 }}>{said}</p> : null}
    </>
  );
}
