// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { render, screen, waitFor, act, fireEvent, within } from '@testing-library/react';
import EnhancedWalletScreen from '../EnhancedWalletScreen';
import { dsmClient } from '../../../services/dsmClient';
import { bridgeEvents } from '../../../bridge/bridgeEvents';
import { encodeBase32Crockford } from '../../../utils/textId';

jest.mock('../../../services/bitcoinTap', () => ({
  formatBtc: (v: bigint | string | number) => String(v),
  getDbtcBalance: jest.fn().mockResolvedValue({ available: 0n, locked: 0n, source: 'CHAIN' }),
}));

/** A contact as getContacts returns it: the DTO contacts.list decodes to. */
function contactDto(alias: string, fill: number, bleAddress?: string) {
  return {
    alias,
    deviceId: new Uint8Array(32).fill(fill),
    genesisHash: new Uint8Array(32).fill(fill + 1),
    publicKey: new Uint8Array(64).fill(fill + 2),
    genesisVerifiedOnline: true,
    bleAddress,
  };
}

function installStandardWalletMocks(contactList: any[] = []) {
  (dsmClient.isReady as any) = jest.fn().mockResolvedValue(true);
  (dsmClient.getIdentity as any) = jest.fn().mockResolvedValue({
    genesisHash: 'G'.repeat(32),
    deviceId: 'D'.repeat(32),
  });
  (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: contactList });
}

describe('EnhancedWalletScreen event-driven refresh', () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    (dsmClient.listB0xMessages as any) = jest.fn().mockResolvedValue([]);
  });

  test('reloads transactions when dsm-wallet-refresh is dispatched', async () => {
    // Prepare identity to satisfy loadWalletData
    (dsmClient.isReady as any) = jest.fn().mockResolvedValue(true);
    (dsmClient.getIdentity as any) = jest.fn().mockResolvedValue({ genesisHash: 'G'.repeat(32), deviceId: 'D'.repeat(32) });

    // getAllBalances: first empty, then updated
    (dsmClient.getAllBalances as any) = jest.fn()
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ tokenId: 'ERA', symbol: 'ERA', baseUnits: 100n, displayAmount: '100', decimals: 0 }]);

    // getWalletHistory: first empty, then returns 1 transaction on second invocation
    (dsmClient.getWalletHistory as any) = jest.fn()
      .mockResolvedValueOnce({ transactions: [] })
      .mockResolvedValueOnce({ transactions: [{ txId: 'tx123', txHash: 'TX123HASH', txType: 'online', type: 'online', amount: 100n, displayAmount: '100', tokenId: 'ERA', recipient: 'peer', status: 'confirmed', fromDeviceId: 'FROM', toDeviceId: 'TO', receiptVerified: false }] });

    // Minimal contacts and BLE functions used by loadWalletData
    (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: [] });

    render(<EnhancedWalletScreen />);

    // wait for initial load(s) to complete (bridge-ready retry may cause 2 calls)
    await waitFor(() => expect((dsmClient.getWalletHistory as any).mock.calls.length).toBeGreaterThanOrEqual(1));
    const callsBeforeEvent = (dsmClient.getWalletHistory as any).mock.calls.length;

    // dispatch the canonical refresh event which EnhancedWalletScreen listens for
    await act(async () => {
      bridgeEvents.emit('wallet.refresh', { source: 'test' });
    });

    // after handling, the UI should reflect the new transaction that our mocked dsmClient returned
    await waitFor(() => {
      expect((dsmClient.getWalletHistory as any).mock.calls.length).toBeGreaterThan(callsBeforeEvent);
      // The overview shows 'Recent Activity' with the transaction amount (100)
      expect(screen.getByText(/Recent Activity/)).toBeInTheDocument();
      expect(screen.queryAllByText(/100/).length).toBeGreaterThanOrEqual(1);
    });
  });

  test('offline send submits through sendOfflineTransfer', async () => {
    const contact = contactDto('Receiver', 0x0a, 'AA:BB:CC:DD:EE:FF');

    (dsmClient.isReady as any) = jest.fn().mockResolvedValue(true);
    (dsmClient.getIdentity as any) = jest
      .fn()
      .mockResolvedValue({ genesisHash: 'G'.repeat(32), deviceId: 'D'.repeat(32) });
    (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: [contact] });
    (dsmClient.getAllBalances as any) = jest
      .fn()
      .mockResolvedValue([{ tokenId: 'ROOT', symbol: 'ERA', baseUnits: 100n, displayAmount: '100', decimals: 0 }]);
    (dsmClient.getWalletHistory as any) = jest.fn().mockResolvedValue({ transactions: [] });
    (dsmClient.resolveBleAddressForContact as any) = jest.fn().mockResolvedValue(contact.bleAddress);
    (dsmClient.sendOfflineTransfer as any) = jest.fn().mockResolvedValue({ success: true });

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('DSM Wallet')).toBeInTheDocument());

    fireEvent.click(screen.getAllByRole('button', { name: 'Send' })[0]);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Send Transaction' })).toBeInTheDocument());
    // The form no longer pre-selects a recipient: pick one, as a user must.
    fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: encodeBase32Crockford(contact.deviceId) } });
    fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    fireEvent.change(screen.getByLabelText(/Amount/i), { target: { value: '1' } });
    // The token picker is a listbox, not a native select: it shows each
    // token's coin, which an <option> cannot render. The one token on offer
    // DISPLAYS as "ERA" while its id is "ROOT", which is what this test is
    // about, so take it by position and let the assertion below check that the
    // identity, not the label, is what gets sent.
    fireEvent.click(screen.getByRole('button', { name: 'Token' }));
    fireEvent.click(within(screen.getByRole('listbox', { name: 'Token' })).getAllByRole('option')[0]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Send' }).at(-1)!);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    await waitFor(() => {
      expect(dsmClient.sendOfflineTransfer).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenId: 'ROOT',
          to: encodeBase32Crockford(contact.deviceId),
          amount: '1',
          bleAddress: contact.bleAddress,
        })
      );
    });
  });

  test('online sender updates visible balance in the UI after send completes', async () => {
    const contact = contactDto('Receiver', 0x0a);

    installStandardWalletMocks([contact]);

    let balancesState = [{ tokenId: 'ERA', symbol: 'ERA', baseUnits: 100n, displayAmount: '100', decimals: 0 }];
    let historyState: any[] = [];

    (dsmClient.getAllBalances as any) = jest.fn().mockImplementation(async () => balancesState);
    (dsmClient.getWalletHistory as any) = jest.fn().mockImplementation(async () => ({ transactions: historyState }));
    (dsmClient.sendOnlineTransferSmart as any) = jest.fn().mockImplementation(async () => {
      balancesState = [{ tokenId: 'ERA', symbol: 'ERA', baseUnits: 75n, displayAmount: '75', decimals: 0 }];
      historyState = [{ txId: 'tx-online-sender', txHash: 'TXONLINESENDERHASH', txType: 'online', type: 'online', amount: -25n, displayAmount: '-25', tokenId: 'ERA', recipient: 'Receiver', status: 'confirmed', fromDeviceId: 'FROM', toDeviceId: 'TO', receiptVerified: false }];
      return { success: true, message: 'ok', newBalance: 75n };
    });

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('100')).toBeInTheDocument());

    fireEvent.click(screen.getAllByRole('button', { name: 'Send' })[0]);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Send Transaction' })).toBeInTheDocument());
    // The form no longer pre-selects a recipient: pick one, as a user must.
    fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: encodeBase32Crockford(contact.deviceId) } });
    fireEvent.change(screen.getByLabelText(/Amount/i), { target: { value: '25' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Send' }).at(-1)!);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    await waitFor(() => {
      expect(dsmClient.sendOnlineTransferSmart).toHaveBeenCalledWith('Receiver', '25', undefined, 'ERA');
      expect(screen.queryByRole('heading', { name: 'Send Transaction' })).not.toBeInTheDocument();
      expect(screen.getAllByText('75').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Recent Activity/)).toBeInTheDocument();
    });
  });

  test('offline sender updates visible balance in the UI after send completes', async () => {
    const contact = contactDto('Receiver', 0x0a, 'AA:BB:CC:DD:EE:FF');

    installStandardWalletMocks([contact]);

    let balancesState = [{ tokenId: 'ROOT', symbol: 'ERA', baseUnits: 80n, displayAmount: '80', decimals: 0 }];
    let historyState: any[] = [];

    (dsmClient.getAllBalances as any) = jest.fn().mockImplementation(async () => balancesState);
    (dsmClient.getWalletHistory as any) = jest.fn().mockImplementation(async () => ({ transactions: historyState }));
    (dsmClient.resolveBleAddressForContact as any) = jest.fn().mockResolvedValue(contact.bleAddress);
    (dsmClient.sendOfflineTransfer as any) = jest.fn().mockImplementation(async () => {
      balancesState = [{ tokenId: 'ROOT', symbol: 'ERA', baseUnits: 55n, displayAmount: '55', decimals: 0 }];
      historyState = [{ txId: 'tx-offline-sender', txHash: 'TXOFFLINESENDERHASH', txType: 'bilateral_offline', type: 'offline', amount: -25n, displayAmount: '-25', tokenId: 'ERA', recipient: 'Receiver', status: 'confirmed', fromDeviceId: 'FROM', toDeviceId: 'TO', receiptVerified: false }];
      return { accepted: true, result: 'Bilateral transfer complete' };
    });

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('80')).toBeInTheDocument());

    fireEvent.click(screen.getAllByRole('button', { name: 'Send' })[0]);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Send Transaction' })).toBeInTheDocument());
    // The form no longer pre-selects a recipient: pick one, as a user must.
    fireEvent.change(screen.getAllByRole('combobox')[0], { target: { value: encodeBase32Crockford(contact.deviceId) } });
    fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    fireEvent.change(screen.getByLabelText(/Amount/i), { target: { value: '25' } });
    // The token picker is a listbox, not a native select: it shows each
    // token's coin, which an <option> cannot render. The one token on offer
    // DISPLAYS as "ERA" while its id is "ROOT", which is what this test is
    // about, so take it by position and let the assertion below check that the
    // identity, not the label, is what gets sent.
    fireEvent.click(screen.getByRole('button', { name: 'Token' }));
    fireEvent.click(within(screen.getByRole('listbox', { name: 'Token' })).getAllByRole('option')[0]);
    fireEvent.click(screen.getAllByRole('button', { name: 'Send' }).at(-1)!);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    await waitFor(() => {
      expect(dsmClient.sendOfflineTransfer).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenId: 'ROOT',
          to: encodeBase32Crockford(contact.deviceId),
          amount: '25',
          bleAddress: contact.bleAddress,
        })
      );
      expect(screen.queryByRole('heading', { name: 'Send Transaction' })).not.toBeInTheDocument();
      expect(screen.getAllByText('55').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Recent Activity/)).toBeInTheDocument();
    });
  });

  test('online receiver refresh updates visible balance and history in the UI', async () => {
    installStandardWalletMocks([]);

    let balancesState = [{ tokenId: 'ERA', symbol: 'ERA', baseUnits: 40n, displayAmount: '40', decimals: 0 }];
    let historyState: any[] = [];

    (dsmClient.getAllBalances as any) = jest.fn().mockImplementation(async () => balancesState);
    (dsmClient.getWalletHistory as any) = jest.fn().mockImplementation(async () => ({ transactions: historyState }));

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('40')).toBeInTheDocument());

    balancesState = [{ tokenId: 'ERA', symbol: 'ERA', baseUnits: 65n, displayAmount: '65', decimals: 0 }];
    historyState = [{ txId: 'tx-online-receiver', txHash: 'TXONLINERECEIVERHASH', txType: 'online', type: 'online', amount: 25n, displayAmount: '25', tokenId: 'ERA', recipient: 'Sender', status: 'confirmed', fromDeviceId: 'FROM', toDeviceId: 'TO', receiptVerified: false }];

    await act(async () => {
      bridgeEvents.emit('wallet.refresh', { source: 'wallet.send' });
    });

    await waitFor(() => {
      expect(screen.getAllByText('65').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Recent Activity/)).toBeInTheDocument();
      expect(screen.getAllByText(/25/).length).toBeGreaterThanOrEqual(1);
    });
  });

  test('inbox check loads preview items without full storage sync', async () => {
    (dsmClient.isReady as any) = jest.fn().mockResolvedValue(true);
    (dsmClient.getIdentity as any) = jest
      .fn()
      .mockResolvedValue({ genesisHash: 'G'.repeat(32), deviceId: 'D'.repeat(32) });
    (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: [] });
    (dsmClient.getAllBalances as any) = jest
      .fn()
      .mockResolvedValue([{ tokenId: 'ERA', symbol: 'ERA', baseUnits: 100n, displayAmount: '100', decimals: 0 }]);
    (dsmClient.getWalletHistory as any) = jest.fn().mockResolvedValue({ transactions: [] });
    (dsmClient.syncWithStorage as any) = jest.fn().mockResolvedValue({ success: true, processed: 1 });
    (dsmClient.listB0xMessages as any) = jest.fn().mockResolvedValue([
      { id: 'inbox-1', preview: 'Incoming online transfer 25 ERA' },
    ]);

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('DSM Wallet')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /Inbox/ }));

    await waitFor(() => {
      expect(dsmClient.syncWithStorage).not.toHaveBeenCalled();
      expect(dsmClient.listB0xMessages).toHaveBeenCalled();
      expect(screen.getByText('Incoming online transfer 25 ERA')).toBeInTheDocument();
    });
  });

  test('inbox badge updates before the user opens the inbox', async () => {
    (dsmClient.isReady as any) = jest.fn().mockResolvedValue(true);
    (dsmClient.getIdentity as any) = jest
      .fn()
      .mockResolvedValue({ genesisHash: 'G'.repeat(32), deviceId: 'D'.repeat(32) });
    (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: [] });
    (dsmClient.getAllBalances as any) = jest
      .fn()
      .mockResolvedValue([{ tokenId: 'ERA', symbol: 'ERA', baseUnits: 100n, displayAmount: '100', decimals: 0 }]);
    (dsmClient.getWalletHistory as any) = jest.fn().mockResolvedValue({ transactions: [] });
    (dsmClient.listB0xMessages as any) = jest.fn().mockResolvedValue([]);

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('DSM Wallet')).toBeInTheDocument());

    await act(async () => {
      bridgeEvents.emit('inbox.updated', { unreadCount: 2, newItems: 2, source: 'poll' });
    });

    const button = screen.getByRole('button', { name: 'Inbox (2 new)' });
    expect(button.className).toContain('has-items');
  });
});
