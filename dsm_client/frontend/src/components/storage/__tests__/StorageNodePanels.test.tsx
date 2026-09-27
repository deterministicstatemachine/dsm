// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { StorageMembersPanel, StorageSetPanel } from '../StorageNodePanels';
import type { StorageStatus } from '../../../dsm/types';

const status: StorageStatus = {
  networkId: 'dsm-testnet',
  storageSetIdB32: '7GBBB51DM8XP433F6H896G4R88W6RJZATZ3CT0WTRAFZ2EHYZ9D0',
  members: [
    {
      memberId: 'dsm-node-1',
      registerIncarnationB32: 'B6DZ4TFJ2Y1GSJ8X57CE8BWX0QM5JRVAJP08JRQTV65DEQ53DYKG',
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
      registerIncarnationB32: 'QYR6K65CD8SZ40G4PZV4PMS2R0VK02N14TECZ0GP00ZR9VCSYC20',
      endpoint: 'https://node-2:8080',
      answer: { kind: 'noCycle' },
      answeredAs: 'dsm-node-3',
    },
    {
      memberId: 'dsm-node-3',
      registerIncarnationB32: '2AJ8GZ4QM7YH7D5G552EAHSPTSTWG9KXE04RTBKYN8ES17Y9BTWG',
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
