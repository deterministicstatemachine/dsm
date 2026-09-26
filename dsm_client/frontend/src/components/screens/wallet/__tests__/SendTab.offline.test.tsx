// SPDX-License-Identifier: Apache-2.0
//! An offline send ends one of three ways, and the screen says which.
//!
//! When the screen stopped waiting, it used to report "did not complete in
//! time" as a failed send, while the step stayed open on both phones and
//! completed when they met again: a lost link fails no step.

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

const mockPlay = jest.fn();
jest.mock('../../../fx/FxProvider', () => ({
  useFx: () => ({ play: mockPlay, dismiss: jest.fn() }),
}));

jest.mock('../../../../services/dsmClient', () => ({
  dsmClient: {
    resolveBleAddressForContact: jest.fn().mockResolvedValue('AA:BB:CC:DD:EE:FF'),
    sendOfflineTransfer: jest.fn(),
    sendOnlineTransferSmart: jest.fn(),
  },
}));

import { dsmClient } from '../../../../services/dsmClient';
import SendTab from '../SendTab';

const D3 = { deviceId: 'NJ2C7P4CXGNY59', alias: 'nj2c7p4c' } as any;

function sendOffline(props: { setError: jest.Mock; onSendComplete: jest.Mock }) {
  render(
    <SendTab
      contacts={[D3]}
      balances={[{ tokenId: 'RIGB', symbol: 'RIGB', tokenName: 'RIGB', baseUnits: 1000n, displayAmount: '1000', decimals: 0, protocolDefined: false }]}
      onCancel={jest.fn()}
      loadWalletData={jest.fn().mockResolvedValue(undefined)}
      {...props}
    />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
  fireEvent.change(screen.getByLabelText(/recipient/i), { target: { value: D3.deviceId } });
  fireEvent.change(screen.getByLabelText('Amount'), { target: { value: '5' } });
  fireEvent.click(screen.getByRole('button', { name: /^send$/i }));
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
}

describe('SendTab offline outcome', () => {
  beforeEach(() => mockPlay.mockReset());

  it('reports a step still open as open, not as a failed send', async () => {
    (dsmClient.sendOfflineTransfer as jest.Mock).mockResolvedValue({
      accepted: false,
      open: true,
      result: 'The transfer is still open.',
    });
    const setError = jest.fn();
    const onSendComplete = jest.fn();

    sendOffline({ setError, onSendComplete });

    await waitFor(() => expect(mockPlay).toHaveBeenCalled());
    expect(mockPlay).toHaveBeenCalledWith(
      expect.objectContaining({ anim: 'trace', title: 'Not finished yet', tone: 'neutral' }),
    );
    expect(mockPlay).not.toHaveBeenCalledWith(expect.objectContaining({ anim: 'fail' }));
    expect(setError).not.toHaveBeenCalledWith(expect.any(String));
    expect(onSendComplete).toHaveBeenCalled();
    expect(dsmClient.sendOfflineTransfer).toHaveBeenCalledWith(
      expect.objectContaining({ tokenId: 'RIGB', to: D3.deviceId, amount: '5' }),
    );
  });

  it("reports a refused send as failed, in the SDK's words", async () => {
    (dsmClient.sendOfflineTransfer as jest.Mock).mockResolvedValue({
      accepted: false,
      result: 'Bilateral transfer rejected',
    });
    const setError = jest.fn();
    const onSendComplete = jest.fn();

    sendOffline({ setError, onSendComplete });

    await waitFor(() => expect(setError).toHaveBeenCalledWith('Bilateral transfer rejected'));
    expect(mockPlay).toHaveBeenCalledWith(expect.objectContaining({ anim: 'fail' }));
    expect(onSendComplete).not.toHaveBeenCalled();
  });
});
