// SPDX-License-Identifier: Apache-2.0
// Your DSM contact code in the Modern skin: the QR for someone to scan, the
// whole code written out underneath for them to paste, and Copy and Share.
// Receive, My Card and Add Contact all show it, since being added starts here.

import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { getContactCode } from '../../dsm/contacts';
import { shareText } from '../../dsm/WebViewBridge/phoneContacts';
import { copyText } from '../../utils/anchorDisplay';
import { Icon } from './parts';

type Code = { kind: 'reading' } | { kind: 'read'; code: string; qr: string } | { kind: 'failed'; message: string };

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** `heading`: what the card asks of the person looking at it. */
export default function ModernMyCode({ heading }: { heading: string }): React.JSX.Element {
  const [code, setCode] = useState<Code>({ kind: 'reading' });
  const [reads, setReads] = useState(0);
  const [said, setSaid] = useState<string | null>(null);

  useEffect(() => {
    let live = 'yes';
    setCode({ kind: 'reading' });
    getContactCode()
      .then(async (text) => ({ text, qr: await QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 1, width: 440 }) }))
      .then(
        ({ text, qr }) => { if (live === 'yes') setCode({ kind: 'read', code: text, qr }); },
        (e: unknown) => { if (live === 'yes') setCode({ kind: 'failed', message: messageOf(e) }); },
      );
    return () => { live = 'no'; };
  }, [reads]);

  const copy = (text: string) => {
    copyText(text).then(
      (copied) => setSaid(copied ? 'Copied your code.' : 'It was not copied. Select the code and copy it by hand.'),
      (e: unknown) => setSaid(messageOf(e)),
    );
  };

  const share = (text: string) => {
    shareText(text).then(
      () => setSaid(null),
      (e: unknown) => setSaid(messageOf(e)),
    );
  };

  return (
    <section className="s-card s-mycode" aria-label="Your DSM code">
      <p className="s-row-title" style={{ whiteSpace: 'normal', textAlign: 'center' }}>{heading}</p>
      {code.kind === 'read' ? (
        <>
          <div className="s-qr"><img src={code.qr} alt="Your DSM code as a QR" /></div>
          <label className="s-label" htmlFor="s-mycode-text">Your code</label>
          <textarea
            id="s-mycode-text"
            className="s-input s-code-text"
            readOnly
            rows={4}
            value={code.code}
            onClick={(e) => e.currentTarget.select()}
          />
          <div className="s-actions" style={{ marginTop: 12, marginBottom: 0 }}>
            <button type="button" className="s-btn s-btn-primary s-btn-small" style={{ width: '100%' }} onClick={() => share(code.code)}>
              <Icon name="share" /> Share
            </button>
            <button type="button" className="s-btn s-btn-secondary s-btn-small" style={{ width: '100%' }} onClick={() => copy(code.code)}>
              <Icon name="copy" /> Copy
            </button>
          </div>
        </>
      ) : code.kind === 'reading' ? (
        <div className="s-empty">Getting your code…</div>
      ) : (
        <>
          <div className="s-notice s-error">{code.message}</div>
          <button type="button" className="s-btn s-btn-quiet" onClick={() => setReads((n) => n + 1)}>Try again</button>
        </>
      )}
      {said !== null ? <p className="s-hint" role="status" style={{ textAlign: 'center', marginTop: 10 }}>{said}</p> : null}
    </section>
  );
}
