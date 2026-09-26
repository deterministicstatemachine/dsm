// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { StorageMembersPanel, StorageSetPanel } from '../StorageNodePanels';
import type { StorageStatus } from '../../../dsm/types';

const status: StorageStatus = {
  networkId: 'dsm-testnet',
  storageSetIdB32: 'DN61X37SS8ZVV96E98Q4MSFGG8JGR7438ADNY38C7X8WNBZR5S90',
  members: [
    {
      memberId: 'dsm-node-1',
      registerIncarnationB32: '5VVWG3GB04F8NG43VVKA9E8CRPZXHBCG04GSWSRC5ZR3ZH28T3M0',
      endpoint: 'https://node-1:8080',
      answer: {
        kind: 'latest',
        cycle: 12n,
        bytesUsed: 2048n,
        rootB32: 'ROOTROOTROOTROOTROOT',
        parentB32: 'PARENTPARENTPARENT',
        digestB32: 'DIGESTDIGESTDIGEST',
      },
      answeredAs: 'dsm-node-1',
    },
    {
      memberId: 'dsm-node-2',
      registerIncarnationB32: 'M0WKNKC31F50D0GZW6JYM9YZTDS38W3AD7GYZNN40NQV8KPQ3F50',
      endpoint: 'https://node-2:8080',
      answer: { kind: 'noCycle' },
      answeredAs: 'dsm-node-3',
    },
    {
      memberId: 'dsm-node-3',
      registerIncarnationB32: 'KCAGAY7R518SNJ0EN9C290FBWF592VB77MWKAH8STMGVBCFTBW2G',
      endpoint: 'https://node-3:8080',
      answer: { kind: 'unanswered', why: 'transport: connection refused' },
    },
  ],
  completedSyncs: 7n,
  databaseBytes: 4096n,
};

describe('StorageSetPanel', () => {
  it('shows the set and counts only the members that gave an answer', () => {
    render(<StorageSetPanel status={status} />);
    expect(screen.getByText('dsm-testnet')).toBeInTheDocument();
    expect(screen.getByText('2/3')).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
    expect(screen.getByText('4.0 KB')).toBeInTheDocument();
    expect(screen.getByTitle(status.storageSetIdB32)).toBeInTheDocument();
  });
});

describe('StorageMembersPanel', () => {
  it("shows a member's cycle and bytes only when it stated a ByteCommit", () => {
    render(<StorageMembersPanel members={status.members} />);
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('2.0 KB')).toBeInTheDocument();
    // dsm-node-2 and dsm-node-3 have no ByteCommit to show: no number is shown for them.
    expect(screen.getAllByText('—')).toHaveLength(4);
  });

  it('shows why a member has no answer, and who answered in its place', () => {
    render(<StorageMembersPanel members={status.members} />);

    fireEvent.click(screen.getByText('dsm-node-3'));
    expect(screen.getByText('transport: connection refused')).toBeInTheDocument();

    fireEvent.click(screen.getByText('dsm-node-2'));
    expect(screen.getByText('States it has closed no cycle yet.')).toBeInTheDocument();
    expect(screen.getByText('Answered as dsm-node-3.')).toBeInTheDocument();
  });
});
