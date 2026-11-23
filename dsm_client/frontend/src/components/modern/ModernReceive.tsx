// SPDX-License-Identifier: Apache-2.0
// The Modern skin's Receive page: your contact code as a QR for someone to
// scan, written out in full to paste, and to share or copy. Paying you starts
// with both of you adding each other (DSM Amendment A33).

import React from 'react';
import { Icon, PageTitle } from './parts';
import { modernNav } from './modernNav';
import ModernMyCode from './ModernMyCode';

export default function ModernReceive(): React.JSX.Element {
  return (
    <>
      <PageTitle title="Receive" onBack={() => modernNav.back()} />
      <ModernMyCode heading="Let someone scan this code, or send them the code, to add you. Once you have added them too, they can pay you." />
      <button type="button" className="s-btn s-btn-quiet" onClick={() => modernNav.open({ kind: 'my_card' })}>
        <Icon name="person" /> My contact card
      </button>
    </>
  );
}
