/* eslint-disable @typescript-eslint/no-explicit-any */
import { renderHook, act, waitFor } from '@testing-library/react';
import { useTransactions } from '../useTransactions';
import { dsmClient } from '../../services/dsmClient';
import { headerService } from '../../services/headerService';
import * as pb from '../../proto/dsm_app_pb';

describe('useTransactions', () => {
  const original = {
    getWalletHistory: dsmClient.getWalletHistory,
    sendOnlineTransferSmart: (dsmClient as any).sendOnlineTransferSmart,
    getContacts: dsmClient.getContacts,
    offlineSend: (dsmClient as any).offlineSend,
    isReady: (dsmClient as any).isReady,
    invalidateCache: headerService.invalidateCache,
  };

  function setupIdentityBridge() {
    const g: any = globalThis as any;
    g.window = g.window || ({} as any);
    const win: any = g.window;
    const deviceId = new Uint8Array(32).fill(0x01);
    const genesisHash = new Uint8Array(32).fill(0x02);
    const chainTip = new Uint8Array(32).fill(0x03);
    const headers = new pb.Headers({ deviceId: deviceId as any, genesisHash: genesisHash as any, chainTip: chainTip as any, seq: BigInt(1) as any });
    win.DsmBridge = {
      __binary: true,
      __callBin: async (reqBytes: Uint8Array) => {
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const br = new pb.BridgeRpcResponse({ result: { case: 'success', value: { data: new Uint8Array([0]) } } });
        if (method === 'hasIdentityDirect') {
          return new pb.BridgeRpcResponse({ result: { case: 'success', value: { data: new Uint8Array([1]) } } }).toBinary();
        }
        return br.toBinary();
      },
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        const method = req.method || '';
        const p = req.payload?.case === 'bytes' ? req.payload.value.data : new Uint8Array(0);
        const readU32 = (buf: Uint8Array, off: number) => ((buf[off] ?? 0) << 24) | ((buf[off + 1] ?? 0) << 16) | ((buf[off + 2] ?? 0) << 8) | (buf[off + 3] ?? 0);
        const withRid = (bytes: Uint8Array) => {
          const rid = new Uint8Array(8);
          const out = new Uint8Array(rid.length + bytes.length);
          out.set(rid, 0);
          out.set(bytes, rid.length);
          return out;
        };
        if (method === 'getTransportHeadersV3Bin') {
          return new pb.BridgeRpcResponse({ result: { case: 'success', value: { data: headers.toBinary() } } }).toBinary();
        }
        if (method === 'appRouterQuery') {
          const n = readU32(p, 0);
          const path = new TextDecoder().decode(p.slice(4, 4 + n));
          if (path === '/transport/headersV3') {
            const data = withRid(headers.toBinary());
            return new pb.BridgeRpcResponse({ result: { case: 'success', value: { data } } }).toBinary();
          }
        }
        return new pb.BridgeRpcResponse({ result: { case: 'success', value: { data: withRid(new Uint8Array(0)) } } }).toBinary();
      },
    };
  }

  function restoreAll() {
    (dsmClient as any).getWalletHistory = original.getWalletHistory;
    (dsmClient as any).sendOnlineTransferSmart = original.sendOnlineTransferSmart;
    (dsmClient as any).getContacts = original.getContacts;
    (dsmClient as any).offlineSend = original.offlineSend;
    (dsmClient as any).isReady = original.isReady;
    (headerService as any).invalidateCache = original.invalidateCache;
    if ((globalThis as any).window) delete (globalThis as any).window.DsmBridge;
  }

  beforeEach(() => {
    restoreAll();
    setupIdentityBridge();
    (dsmClient as any).isReady = async () => true;
  });

  afterEach(() => {
    restoreAll();
  });

  async function renderTransactionsHook() {
    const hook = renderHook(() => useTransactions());
    // Flush initial async effect under act to avoid warnings.
    await act(async () => {
      await Promise.resolve();
    });
    return hook;
  }

  test('fetches and maps transactions on mount', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    (dsmClient as any).getWalletHistory = async () => ({
      transactions: [
        {
          txId: 'tx1',
          type: 'online',
          amount: '12345',
          recipient: 'abc123',
          tickIndex: '100',
          status: 'confirmed',
          syncStatus: 'synced',
        },
      ],
    });

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions.length).toBe(1);
    });

    const tx = result.current.transactions[0];
    expect(tx.txId).toBe('tx1');
    expect(tx.type).toBe('online');
    expect(tx.amount).toBe(12345n);
    expect(tx.recipient).toBe('abc123');
    expect(tx.status).toBe('confirmed');
    expect(tx.syncStatus).toBe('synced');
  });

  test('sets error when getTransactionHistory fails', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    (dsmClient as any).getWalletHistory = async () => {
      throw new Error('oops');
    };

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.error).toBe('oops');
    });
  });

  test('returns empty array when no transactions', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    (dsmClient as any).getWalletHistory = async () => ({ transactions: [] });

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions).toEqual([]);
    });
  });

  test('sendTransfer calls sendOnlineTransferSmart and refreshes on success', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    (dsmClient as any).getWalletHistory = async () => ({ transactions: [] });
    let sendArgs: any[] | null = null;
    (dsmClient as any).sendOnlineTransferSmart = async (...args: any[]) => {
      sendArgs = args;
      return { success: true };
    };
    let invalidated = 0;
    (headerService as any).invalidateCache = () => {
      invalidated += 1;
    };

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions).toEqual([]);
    });

    let sendResult: boolean | undefined;
    await act(async () => {
      sendResult = await result.current.sendTransfer({
        recipientAlias: 'alice',
        amount: '10.0',
        decimals: 2,
      });
    });

    expect(sendResult).toBe(true);
    expect(sendArgs).toEqual(['alice', '10.0', undefined, undefined]);
    expect(invalidated).toBeGreaterThan(0);
    expect(result.current.error).toBeNull();
  });

  test('sendTransfer sets error when transfer fails', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    (dsmClient as any).getWalletHistory = async () => ({ transactions: [] });
    (dsmClient as any).sendOnlineTransferSmart = async () => ({ success: false, error: { message: 'insufficient funds' } });

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions).toEqual([]);
    });

    let sendResult: boolean | undefined;
    await act(async () => {
      sendResult = await result.current.sendTransfer({
        recipientAlias: 'bob',
        amount: '999.0',
        decimals: 2,
      });
    });

    expect(sendResult).toBe(false);
    expect(result.current.error).toMatch(/insufficient funds/);
  });

  test('formatAmount stringifies unknown values', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    (dsmClient as any).getWalletHistory = async () => ({ transactions: [] });

    const { result } = await renderTransactionsHook();

    expect(result.current.formatAmount(123n)).toBe('123');
    expect(result.current.formatAmount(null)).toBe('');
    expect(result.current.formatAmount(undefined)).toBe('');
  });

  test('refresh can be called manually to reload transactions', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    let call = 0;
    (dsmClient as any).getWalletHistory = async () => {
      call += 1;
      if (call === 1) return { transactions: [] };
      return {
        transactions: [
          {
            txId: 'tx2',
            type: 'offline',
            amount: 5000n,
            recipient: 'xyz',
            status: 'pending',
          },
        ],
      };
    };

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions).toEqual([]);
    });

    await act(async () => {
      await result.current.refresh();
    });

    expect(result.current.transactions.length).toBe(1);
    expect(result.current.transactions[0].txId).toBe('tx2');
  });

  test('throws when transaction data is malformed', async () => {
    (dsmClient as any).getContacts = async () => ({ contacts: [] });
    (dsmClient as any).getWalletHistory = async () => ({
      transactions: [
        {
          txId: 'bad',
          // missing required fields
        },
      ],
    });

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      // Accept either 'malformed transaction' message or the strict typed error
      expect(result.current.error).toMatch(/malformed transaction|transaction.amount has invalid type/);
    });
  });

  test('offline transfer resolves alias via contacts and calls offlineSend', async () => {
    (dsmClient as any).getWalletHistory = async () => ({ transactions: [] });
    (dsmClient as any).getContacts = async () => ({
      contacts: [
        { alias: 'charlie', deviceId: '09'.repeat(16), bleAddress: 'AA:BB:CC:DD:EE:FF' },
      ],
    });
    let offlineArgs: any = null;
    (dsmClient as any).sendOfflineTransfer = async (args: any) => {
      offlineArgs = args;
      return { success: true, message: 'ok' };
    };

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions).toEqual([]);
    });

    let sendResult: boolean | undefined;
    await act(async () => {
      sendResult = await result.current.sendTransfer({
        recipientAlias: 'charlie',
        amount: '5',
        decimals: 0,
        offline: true,
      });
    });

    expect(sendResult).toBe(true);
    expect(offlineArgs).toEqual({
      tokenId: 'ERA',
      to: expect.any(String) as any,
      amount: '5',
      memo: undefined,
      bleAddress: 'AA:BB:CC:DD:EE:FF',
    });
    expect(result.current.error).toBeNull();
  });

  test('maps incoming transaction counterparty to alias', async () => {
    (dsmClient as any).getContacts = async () => ({
      contacts: [
        { alias: 'Alice', genesisHash: 'G', deviceId: '0410610' },
      ],
    });

    (dsmClient as any).getWalletHistory = async () => ({
      transactions: [
        {
          txId: 't_in',
          type: 'offline',
          amountSigned: '5',
          fromDeviceId: new Uint8Array([1, 2, 3, 4]),
          status: 'confirmed',
        },
      ],
    });

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions.length).toBe(1);
    });

    expect(result.current.transactions[0].recipient).toBe('Alice');
  });

  test('maps outgoing transaction counterparty to alias', async () => {
    (dsmClient as any).getContacts = async () => ({
      contacts: [
        { alias: 'Bob', genesisHash: 'G', deviceId: '0410618' },
      ],
    });

    (dsmClient as any).getWalletHistory = async () => ({
      transactions: [
        {
          txId: 't_out',
          type: 'offline',
          amountSigned: '-7',
          toDeviceId: new Uint8Array([1, 2, 3, 5]),
          status: 'confirmed',
        },
      ],
    });

    const { result } = await renderTransactionsHook();

    await waitFor(() => {
      expect(result.current.transactions.length).toBe(1);
    });

    expect(result.current.transactions[0].recipient).toBe('Bob');
  });
});
