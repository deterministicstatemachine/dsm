// SPDX-License-Identifier: Apache-2.0
// A release is said as soon as Rust answers it. The tab used to read its vault
// lists again before it said anything: on the rig (2026-11-22) a release that
// took Rust well under a minute showed nothing for two, behind a walk of every
// vault on the screen, and a re-read that failed was reported as "Release
// failed" over a stake Rust had already released. The tab now says what the
// release answered, then reads the lists again, and a re-read that fails is
// named as the re-read's failure. The balances are refreshed either way.

import React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../proto/dsm_app_pb';
import EscrowTab from '../sofi/EscrowTab';
import { installScriptedPhone, removeScriptedPhone } from '../../../tests/helpers/scriptedPhone';
import type { Answer } from '../../../tests/helpers/scriptedPhone';

function id(fill: number): Uint8Array<ArrayBuffer> {
  return new Uint8Array(32).fill(fill);
}

afterEach(removeScriptedPhone);

describe('the escrow tab after a release', () => {
  it('says what the release answered, then reads the vaults again, and names a failed re-read as the re-read', async () => {
    const me = id(0x11);
    const winner = new Uint8Array(Buffer.from('a-wins'));
    // One vault another device locked, on an outcome that pays this device.
    const vaults: Answer = {
      case: 'escrowVaultsResponse',
      value: new pb.EscrowVaultsResponse({
        vaults: [new pb.EscrowVaultV1({
          vaultId: id(0x71),
          ownerDeviceId: id(0x41),
          verdictCell: id(0x72),
          tokenSymbol: 'STEEL',
          amountDisplay: '12',
          status: pb.SofiVaultStatus.ACTIVE,
          outcomes: [me].map((recipientDeviceId) => new pb.EscrowVaultOutcomeV1({
            outcome: winner,
            recipientDeviceId,
            paysThisDevice: recipientDeviceId === me,
          })),
        })],
      }),
    };
    const unread: Answer = { case: 'error', value: new pb.Error({ code: 8, message: 'the nodes did not answer' }) };
    const asked: string[] = [];
    installScriptedPhone({
      'escrow.party': { case: 'escrowPartyResponse', value: new pb.EscrowPartyResponse({ genesis: id(0x12), deviceId: me }) },
      // The list is read when the tab opens, and cannot be read after the release.
      'escrow.vaults': () => {
        asked.push('escrow.vaults');
        return asked.length === 1 ? vaults : unread;
      },
      'escrow.release': () => {
        asked.push('escrow.release');
        return { case: 'sofiPositionResponse', value: new pb.SofiPositionResponse({ position: 7n, state: pb.SofiPositionState.REALIZED }) };
      },
    });
    const refreshed: string[] = [];
    render(<EscrowTab tokenOptions={[]} onMoved={async () => { refreshed.push('balances'); }} />);

    const card = await screen.findByRole('region', { name: /^Escrow vault / });
    expect(within(card).getByText('pays you')).toBeInTheDocument();
    fireEvent.click(within(card).getByRole('button', { name: 'Release' }));

    expect(
      await screen.findByText('Released at position 7. Reading the vaults again failed: the nodes did not answer'),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Release failed/)).not.toBeInTheDocument();
    expect(asked).toEqual(['escrow.vaults', 'escrow.release', 'escrow.vaults']);
    expect(refreshed).toEqual(['balances']);
  });
});
