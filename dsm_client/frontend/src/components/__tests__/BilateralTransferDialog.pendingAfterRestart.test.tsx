// SPDX-License-Identifier: MIT OR Apache-2.0

//! An incoming offline step that is still waiting for this user outlives an
//! app restart in the SDK's session store, but its PREPARE_RECEIVED event does
//! not. Once the wallet is up the dialog shows it again, from the SDK's list,
//! so the user can still accept or reject it.

import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import { BilateralTransferDialog } from '../BilateralTransferDialog';
import type { PendingBilateralDto } from '../../domain/bilateral';

const notifyToast = jest.fn();
jest.mock('../../contexts/UXContext', () => ({
  useUX: () => ({ hideComplexity: true, setHideComplexity: jest.fn(), notifyToast }),
}));

jest.mock('../../contexts/WalletContext', () => ({
  useWallet: () => ({ refreshAll: jest.fn() }),
}));

let listed: PendingBilateralDto[] | Error = [];
jest.mock('../../dsm/WebViewBridge', () => ({
  getPendingBilateralListStrictBridge: jest.fn(async () => new Uint8Array([1])),
}));
jest.mock('../../domain/bilateral', () => ({
  ...jest.requireActual('../../domain/bilateral'),
  decodeOfflinePendingList: jest.fn(async () => {
    if (listed instanceof Error) throw listed;
    return listed;
  }),
}));

const decode = jest.requireMock('../../domain/bilateral').decodeOfflinePendingList as jest.Mock;

/** Let the dialog's read of the list, and any state it sets, finish. */
async function settle(): Promise<void> {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 20));
  });
}

function step(fields: Partial<PendingBilateralDto>): PendingBilateralDto {
  return {
    id: '392XXK8ZMME2EZ7G26VJ0VDKWPHE2ZF6AD3TD9Q7PN4DJGHEHTM0',
    direction: 'incoming',
    phase: 'pending_user_action',
    counterpartyDeviceId: 'KT4ZBZ8SXD73HR6HH3S2SB27E7HNQG9NR49G55CSX09GM0FCFW1G',
    amount: 6n,
    displayAmount: '6',
    tokenId: 'ERA',
    commitmentHash: '392XXK8ZMME2EZ7G26VJ0VDKWPHE2ZF6AD3TD9Q7PN4DJGHEHTM0',
    cancellable: false,
    ...fields,
  };
}

describe('an incoming step awaiting this user, after a restart', () => {
  beforeEach(() => {
    notifyToast.mockClear();
    decode.mockClear();
  });

  test('is shown again once the wallet is up', async () => {
    listed = [step({})];
    render(<BilateralTransferDialog walletReady />);

    await waitFor(() => expect(screen.getByText('Incoming Offline Transfer')).toBeTruthy());
    expect(screen.getByText('6 ERA')).toBeTruthy();
    expect(screen.getByText(/KT4ZBZ8SXD73/)).toBeTruthy();
  });

  test('is not shown before the wallet is up', async () => {
    listed = [step({})];
    render(<BilateralTransferDialog walletReady={false} />);

    await settle();
    expect(decode).not.toHaveBeenCalled();
    expect(screen.queryByText('Incoming Offline Transfer')).toBeNull();
  });

  test('an outgoing step, or one past its decision, is not offered for a decision', async () => {
    listed = [step({ direction: 'outgoing', phase: 'pending_user_action' }), step({ phase: 'accepted' })];
    render(<BilateralTransferDialog walletReady />);

    await waitFor(() => expect(decode).toHaveBeenCalled());
    await settle();
    expect(screen.queryByText('Incoming Offline Transfer')).toBeNull();
  });

  test('a list that cannot be read is said, not shown as nothing waiting', async () => {
    listed = new Error('bilateral.pending_list: unreadable');
    render(<BilateralTransferDialog walletReady />);

    await waitFor(() => expect(notifyToast).toHaveBeenCalledWith('error', expect.stringContaining('unreadable')));
  });
});
