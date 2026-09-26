// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

import PendingBilateralPanel from '../PendingBilateralPanel';
import * as pb from '../../../proto/dsm_app_pb';
import { encodeBase32Crockford } from '../../../utils/textId';

// The bridge is the source of truth: the panel shows what the SDK answered.
jest.mock('../../../dsm/WebViewBridge', () => ({
  getPendingBilateralListStrictBridge: jest.fn(),
  acceptBilateralByCommitmentBridge: jest.fn(),
  rejectBilateralByCommitmentBridge: jest.fn(),
  cancelBilateralByCommitmentBridge: jest.fn(),
  addDsmEventListener: jest.fn(() => () => {}),
  routerInvokeBin: jest.fn(),
}));

import {
  cancelBilateralByCommitmentBridge,
  getPendingBilateralListStrictBridge,
} from '../../../dsm/WebViewBridge';

const mockGetList = getPendingBilateralListStrictBridge as jest.Mock;
const mockCancel = cancelBilateralByCommitmentBridge as jest.Mock;

const SELF = new Uint8Array(32).fill(0x11);
const PEER = new Uint8Array(32).fill(0x22);

function framed(payload: pb.Envelope['payload']): Uint8Array {
  const bytes = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(1 + bytes.length);
  out[0] = 0x03;
  out.set(bytes, 1);
  return out;
}

/** An outgoing ERA step to PEER, as the SDK states one; `fields` override it. */
function step(
  commitmentHash: Uint8Array,
  fields: Partial<pb.OfflineBilateralTransaction> = {},
): pb.OfflineBilateralTransaction {
  return new pb.OfflineBilateralTransaction({
    id: encodeBase32Crockford(commitmentHash),
    senderId: SELF,
    recipientId: PEER,
    commitmentHash: new Uint8Array(commitmentHash),
    phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_PREPARED,
    direction: pb.OfflineBilateralDirection.OFFLINE_DIRECTION_OUTGOING,
    amount: BigInt(3),
    displayAmount: '3',
    tokenId: 'ERA',
    cancellable: false,
    ...fields,
  });
}

function listAnswer(...transactions: pb.OfflineBilateralTransaction[]): Uint8Array {
  return framed({
    case: 'offlineBilateralPendingListResponse',
    value: new pb.OfflineBilateralPendingListResponse({ transactions }),
  });
}

function errorAnswer(message: string): Uint8Array {
  return framed({ case: 'error', value: new pb.Error({ code: 460, message }) });
}

describe('PendingBilateralPanel', () => {
  beforeEach(() => {
    mockGetList.mockReset();
    mockCancel.mockReset();
  });

  test('shows each step as the SDK stated it', async () => {
    mockGetList.mockResolvedValue(
      listAnswer(
        step(new Uint8Array(32).fill(0xa1), {
          senderId: PEER,
          recipientId: SELF,
          direction: pb.OfflineBilateralDirection.OFFLINE_DIRECTION_INCOMING,
          phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_PENDING_USER_ACTION,
          amount: BigInt(150),
          displayAmount: '1.50',
          tokenId: 'RIGB',
          counterpartyAlias: 'alice',
        }),
      ),
    );

    render(<PendingBilateralPanel />);

    expect(await screen.findByText('1.50 RIGB')).toBeInTheDocument();
    expect(screen.getByText('alice')).toBeInTheDocument();
    expect(screen.getByText('From:')).toBeInTheDocument();
    expect(screen.getByText('[AWAITING YOUR DECISION]')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'ACCEPT' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'REJECT' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'CANCEL' })).toBeNull();
  });

  test('a step whose token decimals the device does not know shows its base units', async () => {
    mockGetList.mockResolvedValue(
      listAnswer(
        step(new Uint8Array(32).fill(0xa2), {
          amount: BigInt(150),
          displayAmount: undefined,
          tokenId: 'RIGB',
        }),
      ),
    );

    render(<PendingBilateralPanel />);

    expect(await screen.findByText('150 RIGB base units')).toBeInTheDocument();
    expect(screen.getByText('To:')).toBeInTheDocument();
  });

  test('offers cancel only where the SDK says the step may be cancelled; cancelling re-reads the list', async () => {
    const unconfirmed = new Uint8Array(32).fill(0xa3);
    const confirmed = new Uint8Array(32).fill(0xa4);
    mockGetList.mockResolvedValue(
      listAnswer(
        step(unconfirmed, { cancellable: true }),
        step(confirmed, {
          phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_CONFIRM_PENDING,
          cancellable: false,
        }),
      ),
    );
    mockCancel.mockResolvedValue(
      framed({
        case: 'bilateralPrepareReject',
        value: new pb.BilateralPrepareReject({ reason: 'Sender cancelled transfer' }),
      }),
    );

    render(<PendingBilateralPanel />);

    const cancel = await screen.findAllByRole('button', { name: 'CANCEL' });
    expect(cancel).toHaveLength(1);
    fireEvent.click(cancel[0]);

    await waitFor(() => expect(mockGetList).toHaveBeenCalledTimes(2));
    expect(mockCancel).toHaveBeenCalledTimes(1);
    expect(Array.from(mockCancel.mock.calls[0][0] as Uint8Array)).toEqual(Array.from(unconfirmed));
    expect(screen.queryByRole('alert')).toBeNull();
  });

  test("the SDK's refusal to cancel is shown", async () => {
    mockGetList.mockResolvedValue(listAnswer(step(new Uint8Array(32).fill(0xa5), { cancellable: true })));
    mockCancel.mockResolvedValue(errorAnswer('a confirmed step cannot be cancelled'));

    render(<PendingBilateralPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'CANCEL' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Cancel failed: a confirmed step cannot be cancelled',
    );
  });

  test('an error answer is shown, never an empty list', async () => {
    mockGetList.mockResolvedValue(errorAnswer('pending-list failed'));

    render(<PendingBilateralPanel />);

    expect(await screen.findByRole('alert')).toHaveTextContent('pending-list failed');
    expect(screen.queryByText('No pending bilateral transfers')).toBeNull();
  });

  test('a step in a phase the wire does not name is refused, not shown', async () => {
    mockGetList.mockResolvedValue(
      listAnswer(
        step(new Uint8Array(32).fill(0xa6), { phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_UNSPECIFIED }),
      ),
    );

    render(<PendingBilateralPanel />);

    expect(await screen.findByRole('alert')).toHaveTextContent('which the wire does not name');
    expect(screen.queryByText('3 ERA')).toBeNull();
  });
});
