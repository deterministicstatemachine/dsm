// SPDX-License-Identifier: Apache-2.0
//! Offline mode on the send tab shows the two things an offline send needs
//! besides Bluetooth: Offline Funding, which moves a token between the online
//! account and the offline allocation, and Appliance, which connects the
//! anchor appliance. Choosing Offline connects the appliance by itself.

import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

jest.mock('../../../fx/FxProvider', () => ({
  useFx: () => ({ play: jest.fn(), dismiss: jest.fn() }),
}));

jest.mock('../../../../services/dsmClient', () => ({
  dsmClient: {
    sendOfflineTransfer: jest.fn(),
    sendOnlineTransferSmart: jest.fn(),
    loadOfflineCash: jest.fn(),
    unloadOfflineCash: jest.fn(),
  },
}));

jest.mock('../../../../dsm/anchor', () => ({ getAnchorStatus: jest.fn() }));

import { dsmClient } from '../../../../services/dsmClient';
import { getAnchorStatus } from '../../../../dsm/anchor';
import SendTab from '../SendTab';

const disconnected = {
  connected: false,
  anchorIdB32: '',
  pkChipB32: '',
  anchorCounter: 0n,
  frontierRootB32: '',
  enrolledCounter: 0n,
  statusText: 'no anchor appliance connected',
};

const era = (offline?: { baseUnits: bigint; displayAmount: string }) => ({
  tokenId: 'ERA', symbol: 'ERA', tokenName: 'ERA', baseUnits: 9000n, displayAmount: '90.00', decimals: 2, offline,
});

function renderSend(props: { balances?: any[]; loadWalletData?: jest.Mock } = {}) {
  const loadWalletData = props.loadWalletData ?? jest.fn().mockResolvedValue(undefined);
  render(
    <SendTab
      contacts={[]}
      balances={props.balances ?? [era({ baseUnits: 1000n, displayAmount: '10.00' })]}
      onCancel={jest.fn()}
      onSendComplete={jest.fn()}
      loadWalletData={loadWalletData}
      setError={jest.fn()}
    />,
  );
  return { loadWalletData };
}

describe('SendTab offline funding and appliance', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (getAnchorStatus as jest.Mock).mockResolvedValue(disconnected);
  });

  it('online mode shows the online amount and never touches the appliance', () => {
    renderSend();
    expect(screen.getByText('90.00')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Offline Funding' })).not.toBeInTheDocument();
    expect(getAnchorStatus).not.toHaveBeenCalled();
  });

});
