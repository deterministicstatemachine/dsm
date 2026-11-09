// SPDX-License-Identifier: Apache-2.0
//! Offline is on again (owner, 2026-11-06: "You can turn it back on now."). Choosing it switches the
//! send to offline and offers the two things an offline send needs besides Bluetooth, Offline Funding
//! and Appliance, the appliance being read by itself. Choosing it sends nothing.

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

describe('SendTab offline', () => {
  it('Offline switches the send to offline, offers funding and the appliance, and sends nothing', async () => {
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
    expect(screen.queryByRole('button', { name: 'Offline Funding' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Offline' })).toHaveClass('active');
    expect(screen.getByRole('button', { name: 'Online' })).not.toHaveClass('active');
    expect(screen.getByRole('button', { name: 'Offline Funding' })).toBeInTheDocument();
    // The appliance is read on its own; with no bridge here the read ends, and the button is idle.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Appliance' })).toBeInTheDocument());
    expect(dsmClient.sendOfflineTransfer).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Online' }));
    expect(screen.getByRole('button', { name: 'Online' })).toHaveClass('active');
    expect(screen.queryByRole('button', { name: 'Offline Funding' })).not.toBeInTheDocument();
  });
});
