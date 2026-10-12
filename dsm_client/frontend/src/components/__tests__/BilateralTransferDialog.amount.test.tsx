// SPDX-License-Identifier: MIT OR Apache-2.0

//! Accepting a transfer is a decision about a quantity, so the dialog shows the
//! quantity the sender's device stated: Rust's display form, or — when this
//! device does not know the token's decimals — the base units, named as such.
//! It used to print bare base units as if they were the amount, name a missing
//! token ERA, and upper-case the token it was given.

import React from 'react';
import { act, render, screen } from '@testing-library/react';
import { emit } from '../../dsm/EventBridge';
import { BilateralTransferDialog } from '../BilateralTransferDialog';
import * as pb from '../../proto/dsm_app_pb';

jest.mock('../../contexts/UXContext', () => ({
  useUX: () => ({
    hideComplexity: true,
    setHideComplexity: jest.fn(),
    notifyToast: jest.fn(),
  }),
}));

jest.mock('../../contexts/WalletContext', () => ({
  useWallet: () => ({ refreshAll: jest.fn() }),
}));

function proposal(fields: Partial<pb.BilateralEventNotification>): Uint8Array {
  return new pb.BilateralEventNotification({
    eventType: pb.BilateralEventType.BILATERAL_EVENT_PREPARE_RECEIVED,
    counterpartyDeviceId: new Uint8Array(32).fill(0x22),
    commitmentHash: new Uint8Array(32).fill(0x33),
    status: 'pending',
    message: 'incoming',
    ...fields,
  }).toBinary();
}

describe('BilateralTransferDialog amount', () => {
  let warnSpy: jest.SpyInstance;
  beforeEach(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => warnSpy.mockRestore());

  test("shows Rust's display form with the token as named", () => {
    render(<BilateralTransferDialog />);
    act(() => emit('bilateral.event', proposal({ amount: 150n, displayAmount: '1.50', tokenId: 'mTok' })));
    expect(screen.getByText('1.50 mTok')).toBeTruthy();
  });

  test('shows base units, named as such, when the display form is absent', () => {
    render(<BilateralTransferDialog />);
    act(() => emit('bilateral.event', proposal({ amount: 150n, tokenId: 'RIGB' })));
    expect(screen.getByText('150 RIGB base units')).toBeTruthy();
  });

  test('names no token the event does not name', () => {
    render(<BilateralTransferDialog />);
    act(() => emit('bilateral.event', proposal({ amount: 7n })));
    expect(screen.getByText('7 (token not named) base units')).toBeTruthy();
    expect(screen.queryByText(/ERA/)).toBeNull();
  });
});
