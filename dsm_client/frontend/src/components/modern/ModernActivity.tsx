// SPDX-License-Identifier: Apache-2.0
// The Modern skin's Activity tab: every payment, newest first, filtered to
// what was sent or received.

import React, { useState } from 'react';
import { useWallet } from '../../contexts/WalletContext';
import { useContacts } from '../../contexts/ContactsContext';
import { ActivityItem, activityRows } from './parts';

type Filter = 'all' | 'in' | 'out';

export default function ModernActivity(): React.JSX.Element {
  const wallet = useWallet();
  const { contacts } = useContacts();
  const [filter, setFilter] = useState<Filter>('all');
  const rows = activityRows(wallet.transactions, contacts).filter((r) => filter === 'all' || r.direction === filter);

  return (
    <>
      <h1 className="s-title">Activity</h1>
      <div className="s-seg" role="group" aria-label="Show" style={{ marginBottom: 14 }}>
        <button type="button" aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>All</button>
        <button type="button" aria-pressed={filter === 'in'} onClick={() => setFilter('in')}>Received</button>
        <button type="button" aria-pressed={filter === 'out'} onClick={() => setFilter('out')}>Sent</button>
      </div>
      <section className="s-card" aria-label="Payments">
        {rows.length === 0 ? (
          <div className="s-empty">{wallet.isLoading ? 'Loading…' : 'Nothing here yet.'}</div>
        ) : (
          rows.map((row) => <ActivityItem key={row.tx.txId} row={row} />)
        )}
      </section>
    </>
  );
}
