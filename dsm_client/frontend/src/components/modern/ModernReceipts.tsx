// SPDX-License-Identifier: Apache-2.0
// Email receipts: the permission page. Receipts go on only from here, after
// the owner has read exactly what the receipt service is sent; off is one tap
// and asks nothing.

import React, { useState } from 'react';
import { useAppRuntimeStore } from '../../runtime/appRuntimeStore';
import { setReceiptsEmail } from '../../runtime/skinPreferences';
import { RECEIPT_CONSENT } from '../../domain/receiptConsent';
import { PageTitle } from './parts';
import { modernNav } from './modernNav';

export default function ModernReceipts(): React.JSX.Element {
  const runtime = useAppRuntimeStore();
  const [said, setSaid] = useState<string | null>(null);
  const on = runtime.receiptsEmail === 'on';

  const turn = (value: 'on' | 'off') => {
    setReceiptsEmail(value).then(
      () => setSaid(value === 'on' ? 'Receipts are on.' : 'Receipts are off.'),
      (e: unknown) => setSaid(e instanceof Error ? e.message : String(e)),
    );
  };

  return (
    <>
      <PageTitle title="Email Receipts" onBack={() => modernNav.back()} />
      <section className="s-card">
        <p className="s-row-title" style={{ whiteSpace: 'normal' }}>{RECEIPT_CONSENT.lead}</p>
        <p className="s-hint" style={{ marginTop: 10 }}>{RECEIPT_CONSENT.given}</p>
        <ul className="s-hint">
          {RECEIPT_CONSENT.items.map((item) => <li key={item}>{item}</li>)}
        </ul>
        <p className="s-hint">{RECEIPT_CONSENT.after}</p>
      </section>
      {on ? (
        <button type="button" className="s-btn s-btn-quiet" onClick={() => turn('off')}>Turn receipts off</button>
      ) : (
        <button type="button" className="s-btn s-btn-primary" onClick={() => turn('on')}>I agree, turn receipts on</button>
      )}
      {said !== null ? <p className="s-hint" style={{ textAlign: 'center', marginTop: 12 }}>{said}</p> : null}
    </>
  );
}
