// SPDX-License-Identifier: Apache-2.0
//! Offline mode on the send tab shows the two things an offline send needs
//! besides Bluetooth: Offline Funding, which moves a token between the online
//! account and the offline allocation, and Appliance, which connects the
//! anchor appliance. Choosing Offline connects the appliance by itself.

import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
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
const connected = {
  ...disconnected,
  connected: true,
  anchorIdB32: 'ANCH0R1DXX',
  anchorCounter: 7n,
  frontierRootB32: 'FR0NT1ERXX',
  statusText: 'anchor connected (counter u=7)',
};

const era = (offline?: { baseUnits: bigint; displayAmount: string }) => ({
  tokenId: 'ERA', symbol: 'ERA', tokenName: 'ERA', baseUnits: 90n, displayAmount: '90', decimals: 0, protocolDefined: true, offline,
});

function renderSend(props: { balances?: any[]; loadWalletData?: jest.Mock } = {}) {
  const loadWalletData = props.loadWalletData ?? jest.fn().mockResolvedValue(undefined);
  render(
    <SendTab
      contacts={[]}
      balances={props.balances ?? [era({ baseUnits: 10n, displayAmount: '10' })]}
      onCancel={jest.fn()}
      onSendComplete={jest.fn()}
      loadWalletData={loadWalletData}
      setError={jest.fn()}
    />,
  );
  return { loadWalletData };
}

function renderOffline(props: { balances?: any[]; loadWalletData?: jest.Mock } = {}) {
  const out = renderSend(props);
  fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
  return out;
}

describe('SendTab offline funding and appliance', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (getAnchorStatus as jest.Mock).mockResolvedValue(disconnected);
  });

  it('online mode shows the online amount and never touches the appliance', () => {
    renderSend();
    expect(screen.getByText('90')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Offline Funding' })).not.toBeInTheDocument();
    expect(getAnchorStatus).not.toHaveBeenCalled();
  });

  it('offline mode shows the offline allocation, the two controls, and reads the appliance by itself', async () => {
    renderOffline();
    expect(screen.getByRole('button', { name: 'Offline Funding' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'About offline funding' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Appliance/ })).toBeInTheDocument();
    // The card shows the pot an offline send spends, not the online amount.
    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.queryByText('90')).not.toBeInTheDocument();
    await waitFor(() => expect(getAnchorStatus).toHaveBeenCalledTimes(1));
  });

  it('says the offline allocation is unknown until the appliance connects, never 0', () => {
    renderOffline({ balances: [era(undefined)] });
    expect(screen.getByText('—')).toBeInTheDocument();
    expect(screen.getByText(/unknown until the appliance connects/)).toBeInTheDocument();
    expect(screen.queryByText('0')).not.toBeInTheDocument();
  });

  it('re-reads the wallet once the appliance is connected, so the balances can name their allocations', async () => {
    (getAnchorStatus as jest.Mock).mockResolvedValue(connected);
    const { loadWalletData } = renderOffline({ balances: [era(undefined)] });
    await waitFor(() => expect(loadWalletData).toHaveBeenCalledTimes(1));
  });

  it("Offline Funding loads through Rust with the amount as typed and shows Rust's answer", async () => {
    (dsmClient.loadOfflineCash as jest.Mock).mockResolvedValue({
      onlineDisplay: '85',
      allocationDisplay: '15',
      message: 'loaded 5 ERA — offline allocation now 15, online 85',
    });
    const { loadWalletData } = renderOffline();
    fireEvent.click(screen.getByRole('button', { name: 'Offline Funding' }));
    const dialog = screen.getByRole('dialog', { name: 'Offline Funding' });
    expect(within(dialog).getByText('90 ERA')).toBeInTheDocument();
    expect(within(dialog).getByText('10 ERA')).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText('Amount'), { target: { value: '5' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Load' }));
    await waitFor(() => expect(dsmClient.loadOfflineCash).toHaveBeenCalledWith('ERA', '5'));
    expect(await within(dialog).findByText(/offline allocation now 15/)).toBeInTheDocument();
    expect(loadWalletData).toHaveBeenCalledTimes(1);
    expect(dsmClient.unloadOfflineCash).not.toHaveBeenCalled();
  });

  it('Unload to online goes the other way through Rust', async () => {
    (dsmClient.unloadOfflineCash as jest.Mock).mockResolvedValue({
      onlineDisplay: '95',
      allocationDisplay: '5',
      message: 'unloaded 5 ERA — offline allocation now 5, online 95',
    });
    renderOffline();
    fireEvent.click(screen.getByRole('button', { name: 'Offline Funding' }));
    const dialog = screen.getByRole('dialog', { name: 'Offline Funding' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Unload to online' }));
    fireEvent.change(within(dialog).getByLabelText('Amount'), { target: { value: '5' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Unload' }));
    await waitFor(() => expect(dsmClient.unloadOfflineCash).toHaveBeenCalledWith('ERA', '5'));
    expect(await within(dialog).findByText(/offline allocation now 5/)).toBeInTheDocument();
    expect(dsmClient.loadOfflineCash).not.toHaveBeenCalled();
  });

  it("shows Rust's refusal in Rust's words and re-reads nothing", async () => {
    (dsmClient.loadOfflineCash as jest.Mock).mockRejectedValue(
      new Error('wallet.loadOffline: connect your anchor device to manage offline cash'),
    );
    const { loadWalletData } = renderOffline();
    fireEvent.click(screen.getByRole('button', { name: 'Offline Funding' }));
    const dialog = screen.getByRole('dialog', { name: 'Offline Funding' });
    fireEvent.change(within(dialog).getByLabelText('Amount'), { target: { value: '5' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Load' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('connect your anchor device');
    expect(loadWalletData).not.toHaveBeenCalled();
  });

  it('Appliance opens the setup pop-up, and Connect reads the appliance again', async () => {
    renderOffline();
    await waitFor(() => expect(getAnchorStatus).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: /^Appliance/ }));
    const dialog = screen.getByRole('dialog', { name: 'Appliance' });
    expect(within(dialog).getByTestId('appliance-state')).toHaveTextContent('no anchor appliance connected');
    (getAnchorStatus as jest.Mock).mockResolvedValue(connected);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(within(dialog).getByTestId('appliance-state')).toHaveTextContent('anchor connected (counter u=7)'),
    );
    expect(getAnchorStatus).toHaveBeenCalledTimes(2);
    expect(within(dialog).getByText('ANCH0R1DXX')).toBeInTheDocument();
    expect(within(dialog).getByText('7')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Check again' })).toBeInTheDocument();
  });
});
