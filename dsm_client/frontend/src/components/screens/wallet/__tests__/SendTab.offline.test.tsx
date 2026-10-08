// SPDX-License-Identifier: Apache-2.0
//! Offline sending is under construction (owner ruling 2026-10-08): the
//! Offline switch says so in a pop-up, and the send stays online.

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

const mockPlay = jest.fn();
jest.mock('../../../fx/FxProvider', () => ({
  useFx: () => ({ play: mockPlay, dismiss: jest.fn() }),
}));

jest.mock('../../../../services/dsmClient', () => ({
  dsmClient: {
    sendOfflineTransfer: jest.fn(),
    sendOnlineTransferSmart: jest.fn(),
  },
}));

import { dsmClient } from '../../../../services/dsmClient';
import SendTab from '../SendTab';

const D3 = { deviceId: 'NJ2C7P4CXGNY59', alias: 'nj2c7p4c' } as any;

describe('SendTab offline outcome', () => {
  beforeEach(() => mockPlay.mockReset());

  it('Offline says it is under construction, and the send stays online', async () => {
    render(
      <SendTab
        contacts={[D3]}
        balances={[]}
        onCancel={() => undefined}
        loadWalletData={async () => undefined}
        setError={() => undefined}
        onSendComplete={() => undefined}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    expect(screen.getByRole('alertdialog', { name: 'Offline' })).toHaveTextContent('Under construction, check back soon.');
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Online' })).toHaveClass('active');
    expect(screen.getByRole('button', { name: 'Offline' })).not.toHaveClass('active');
    expect(dsmClient.sendOfflineTransfer).not.toHaveBeenCalled();
  });

});
