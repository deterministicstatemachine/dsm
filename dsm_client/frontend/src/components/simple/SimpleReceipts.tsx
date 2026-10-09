// SPDX-License-Identifier: Apache-2.0
// Email receipts: the permission page. Receipts go on only from here, after
// the owner has read exactly what the receipt service is sent; off is one tap
// and asks nothing.

import React, { useState } from 'react';
import { useAppRuntimeStore } from '../../runtime/appRuntimeStore';
import { setReceiptsEmail } from '../../runtime/skinPreferences';
import { PageTitle } from './parts';
import { simpleNav } from './simpleNav';

export default function SimpleReceipts(): React.JSX.Element {
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
      <PageTitle title="Email Receipts" onBack={() => simpleNav.back()} />
      <section className="s-card">
        <p className="s-row-title" style={{ whiteSpace: 'normal' }}>
          When you pay someone whose email you have, DSM can email them a receipt.
        </p>
        <p className="s-hint" style={{ marginTop: 10 }}>To send it, the DSM receipt service is given, for that payment only:</p>
        <ul className="s-hint">
          <li>their email address</li>
          <li>your name, from your contact card</li>
          <li>the amount, the currency and your note</li>
          <li>the payment&apos;s reference, and your phone&apos;s date and time</li>
        </ul>
        <p className="s-hint">Nothing else is sent, and the service keeps no copy. Payments work the same with receipts off.</p>
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
