/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { render, screen, waitFor, act, fireEvent } from '@testing-library/react';
import EnhancedWalletScreen from '../EnhancedWalletScreen';
import { dsmClient } from '../../../services/dsmClient';
import { bridgeEvents } from '../../../bridge/bridgeEvents';

jest.mock('../../../services/bitcoinTap', () => ({
  formatBtc: (v: bigint | string | number) => String(v),
  getDbtcBalance: jest.fn().mockResolvedValue({ available: 0n, locked: 0n, source: 'CHAIN' }),
}));

function installStandardWalletMocks(contactList: any[] = []) {
  (dsmClient.isReady as any) = jest.fn().mockResolvedValue(true);
  (dsmClient.getIdentity as any) = jest.fn().mockResolvedValue({
    genesisHash: 'G'.repeat(32),
    deviceId: 'D'.repeat(32),
  });
  (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: contactList });
  (dsmClient.getConnectedBluetoothDevices as any) = jest.fn().mockResolvedValue([]);
  (dsmClient.getConnectedDeviceIds as any) = jest.fn().mockResolvedValue([]);
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
      .mockResolvedValueOnce([{ tokenId: 'ERA', symbol: 'ERA', balance: '100' }]);

    // getWalletHistory: first empty, then returns 1 transaction on second invocation
    (dsmClient.getWalletHistory as any) = jest.fn()
      .mockResolvedValueOnce({ transactions: [] })
      .mockResolvedValueOnce({ transactions: [{ txId: 'tx123', type: 'online', amount: '100', recipient: 'FAUCET', status: 'confirmed' }] });

    // Minimal contacts and BLE functions used by loadWalletData
    (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: [] });
    (dsmClient.getConnectedBluetoothDevices as any) = jest.fn().mockResolvedValue([]);
    (dsmClient.getConnectedDeviceIds as any) = jest.fn().mockResolvedValue([]);

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
    const contact = {
      alias: 'Receiver',
      deviceId: 'ABCDEFGH12345678ABCDEFGH12345678',
      genesisHash: 'HGFEDCBA12345678HGFEDCBA12345678',
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    };

    (dsmClient.isReady as any) = jest.fn().mockResolvedValue(true);
    (dsmClient.getIdentity as any) = jest
      .fn()
      .mockResolvedValue({ genesisHash: 'G'.repeat(32), deviceId: 'D'.repeat(32) });
    (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: [contact] });
    (dsmClient.getAllBalances as any) = jest
      .fn()
      .mockResolvedValue([{ tokenId: 'ROOT', symbol: 'ERA', balance: '100', decimals: 2 }]);
    (dsmClient.getWalletHistory as any) = jest.fn().mockResolvedValue({ transactions: [] });
    (dsmClient.resolveBleAddressForContact as any) = jest.fn().mockResolvedValue(contact.bleAddress);
    (dsmClient.sendOfflineTransfer as any) = jest.fn().mockResolvedValue({ success: true });

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('DSM Wallet')).toBeInTheDocument());

    fireEvent.click(screen.getAllByRole('button', { name: 'Send' })[0]);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Send Transaction' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    fireEvent.change(screen.getByLabelText(/Amount/i), { target: { value: '1' } });
    fireEvent.change(screen.getAllByRole('combobox')[1], { target: { value: 'ROOT' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Send' }).at(-1)!);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    await waitFor(() => {
      expect(dsmClient.sendOfflineTransfer).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenId: 'ROOT',
          to: contact.deviceId,
          amount: '1',
          bleAddress: contact.bleAddress,
        })
      );
    });
  });

  test('online sender updates visible balance in the UI after send completes', async () => {
    const contact = {
      alias: 'Receiver',
      deviceId: 'ABCDEFGH12345678ABCDEFGH12345678',
      genesisHash: 'HGFEDCBA12345678HGFEDCBA12345678',
    };

    installStandardWalletMocks([contact]);

    let balancesState = [{ tokenId: 'ERA', symbol: 'ERA', balance: '100', decimals: 0 }];
    let historyState: any[] = [];

    (dsmClient.getAllBalances as any) = jest.fn().mockImplementation(async () => balancesState);
    (dsmClient.getWalletHistory as any) = jest.fn().mockImplementation(async () => ({ transactions: historyState }));
    (dsmClient.sendOnlineTransferSmart as any) = jest.fn().mockImplementation(async () => {
      balancesState = [{ tokenId: 'ERA', symbol: 'ERA', balance: '75', decimals: 0 }];
      historyState = [{ txId: 'tx-online-sender', type: 'online', amount: '25', recipient: 'Receiver', status: 'confirmed' }];
      return { success: true, message: 'ok', newBalance: 75n };
    });

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('100')).toBeInTheDocument());

    fireEvent.click(screen.getAllByRole('button', { name: 'Send' })[0]);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Send Transaction' })).toBeInTheDocument());
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
    const contact = {
      alias: 'Receiver',
      deviceId: 'ABCDEFGH12345678ABCDEFGH12345678',
      genesisHash: 'HGFEDCBA12345678HGFEDCBA12345678',
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    };

    installStandardWalletMocks([contact]);

    let balancesState = [{ tokenId: 'ROOT', symbol: 'ERA', balance: '80', decimals: 2 }];
    let historyState: any[] = [];

    (dsmClient.getAllBalances as any) = jest.fn().mockImplementation(async () => balancesState);
    (dsmClient.getWalletHistory as any) = jest.fn().mockImplementation(async () => ({ transactions: historyState }));
    (dsmClient.resolveBleAddressForContact as any) = jest.fn().mockResolvedValue(contact.bleAddress);
    (dsmClient.sendOfflineTransfer as any) = jest.fn().mockImplementation(async () => {
      balancesState = [{ tokenId: 'ROOT', symbol: 'ERA', balance: '55', decimals: 2 }];
      historyState = [{ txId: 'tx-offline-sender', type: 'offline', amount: '25', recipient: 'Receiver', status: 'confirmed' }];
      return { success: true };
    });

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('80')).toBeInTheDocument());

    fireEvent.click(screen.getAllByRole('button', { name: 'Send' })[0]);
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Send Transaction' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    fireEvent.change(screen.getByLabelText(/Amount/i), { target: { value: '25' } });
    fireEvent.change(screen.getAllByRole('combobox')[1], { target: { value: 'ROOT' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Send' }).at(-1)!);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));

    await waitFor(() => {
      expect(dsmClient.sendOfflineTransfer).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenId: 'ROOT',
          to: contact.deviceId,
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

    let balancesState = [{ tokenId: 'ERA', symbol: 'ERA', balance: '40', decimals: 0 }];
    let historyState: any[] = [];

    (dsmClient.getAllBalances as any) = jest.fn().mockImplementation(async () => balancesState);
    (dsmClient.getWalletHistory as any) = jest.fn().mockImplementation(async () => ({ transactions: historyState }));

    render(<EnhancedWalletScreen />);

    await waitFor(() => expect(screen.getByText('40')).toBeInTheDocument());

    balancesState = [{ tokenId: 'ERA', symbol: 'ERA', balance: '65', decimals: 0 }];
    historyState = [{ txId: 'tx-online-receiver', type: 'online', amount: '25', recipient: 'Self', status: 'confirmed' }];

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
      .mockResolvedValue([{ tokenId: 'ERA', symbol: 'ERA', balance: '100' }]);
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
      .mockResolvedValue([{ tokenId: 'ERA', symbol: 'ERA', balance: '100' }]);
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
