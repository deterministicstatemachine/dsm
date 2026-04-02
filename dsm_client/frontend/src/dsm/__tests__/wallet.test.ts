jest.mock('../WebViewBridge', () => ({
  getAllBalancesStrictBridge: jest.fn(),
  getWalletHistoryStrictBridge: jest.fn(),
  getInboxStrictBridge: jest.fn(),
}));

jest.mock('../../domain/mappers', () => ({
  mapTransactions: jest.fn((list: any[]) => list.map((t: any) => ({ txId: t.txId ?? 'mapped', amount: t.amount ?? 0n }))),
}));

import * as pb from '../../proto/dsm_app_pb';
import {
  getAllBalances,
  getWalletBalance,
  getWalletHistory,
  getTransactions,
  getInbox,
  listB0xMessages,
  getTokens,
  getToken,
} from '../wallet';
import {
  getAllBalancesStrictBridge,
  getWalletHistoryStrictBridge,
  getInboxStrictBridge,
} from '../WebViewBridge';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('wallet.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  // ── getAllBalances ──────────────────────────────────────────────────

  describe('getAllBalances', () => {
    test('maps BalancesListResponse fields correctly', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'balancesListResponse',
          value: new pb.BalancesListResponse({
            balances: [
              new pb.BalanceGetResponse({ tokenId: 'ERA', available: 1000n, symbol: 'ERA', decimals: 8, tokenName: 'Era Token' }),
              new pb.BalanceGetResponse({ tokenId: 'dBTC', available: 50n, symbol: 'dBTC', decimals: 8 }),
            ],
          }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getAllBalances();
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        tokenId: 'ERA',
        ticker: 'ERA',
        balance: '1000',
        baseUnits: 1000n,
        decimals: 8,
        symbol: 'ERA',
        tokenName: 'Era Token',
      });
      expect(result[1].tokenId).toBe('dBTC');
      expect(result[1].baseUnits).toBe(50n);
    });

    test('returns empty array for empty balances list', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'balancesListResponse',
          value: new pb.BalancesListResponse({ balances: [] }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getAllBalances();
      expect(result).toEqual([]);
    });

    test('handles missing optional fields with fallback defaults', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'balancesListResponse',
          value: new pb.BalancesListResponse({
            balances: [new pb.BalanceGetResponse({})],
          }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getAllBalances();
      expect(result).toHaveLength(1);
      expect(result[0].tokenId).toBe('ERA');
      expect(result[0].ticker).toBe('ERA');
      expect(result[0].symbol).toBe('ERA');
      expect(result[0].baseUnits).toBe(0n);
      expect(result[0].decimals).toBe(0);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ code: 42, message: 'denied' }) },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getAllBalances()).rejects.toThrow(/DSM native error.*denied/);
    });

    test('throws on unexpected payload case', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'walletHistoryResponse', value: new pb.WalletHistoryResponse() },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getAllBalances()).rejects.toThrow(/Unexpected payload case for balances/);
    });

    test('throws when bridge rejects', async () => {
      (getAllBalancesStrictBridge as jest.Mock).mockRejectedValue(new Error('bridge down'));
      await expect(getAllBalances()).rejects.toThrow('bridge down');
    });
  });

  // ── getWalletBalance ───────────────────────────────────────────────

  describe('getWalletBalance', () => {
    test('returns first balance as string', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'balancesListResponse',
          value: new pb.BalancesListResponse({
            balances: [new pb.BalanceGetResponse({ tokenId: 'ERA', available: 999n })],
          }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      expect(await getWalletBalance()).toBe('999');
    });

    test('returns "0" when balances list is empty', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'balancesListResponse',
          value: new pb.BalancesListResponse({ balances: [] }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      expect(await getWalletBalance()).toBe('0');
    });
  });

  // ── getWalletHistory ───────────────────────────────────────────────

  describe('getWalletHistory', () => {
    test('decodes walletHistoryResponse and maps transactions', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'walletHistoryResponse',
          value: new pb.WalletHistoryResponse({
            transactions: [{ txId: 'tx1', amount: 100n } as any],
          }),
        },
      });
      (getWalletHistoryStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getWalletHistory();
      expect(result.transactions).toBeDefined();
      expect(Array.isArray(result.transactions)).toBe(true);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ code: 1, message: 'history fail' }) },
      });
      (getWalletHistoryStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getWalletHistory()).rejects.toThrow(/DSM native error.*history fail/);
    });

    test('throws on unexpected payload case', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (getWalletHistoryStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getWalletHistory()).rejects.toThrow(/Unexpected payload case for wallet history/);
    });

    test('returns empty transactions when payload serializes as empty message', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'walletHistoryResponse', value: undefined as any },
      });
      (getWalletHistoryStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getWalletHistory();
      expect(result.transactions).toEqual([]);
    });

    test('handles empty transactions list', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'walletHistoryResponse',
          value: new pb.WalletHistoryResponse({ transactions: [] }),
        },
      });
      (getWalletHistoryStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getWalletHistory();
      expect(result.transactions).toEqual([]);
    });
  });

  // ── getTransactions ────────────────────────────────────────────────

  describe('getTransactions', () => {
    test('returns transactions array from wallet history', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'walletHistoryResponse',
          value: new pb.WalletHistoryResponse({ transactions: [] }),
        },
      });
      (getWalletHistoryStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getTransactions();
      expect(Array.isArray(result)).toBe(true);
    });
  });

  // ── getInbox ───────────────────────────────────────────────────────

  describe('getInbox', () => {
    test('maps inbox items correctly', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'inboxResponse',
          value: new pb.InboxResponse({
            items: [
              new pb.InboxItem({ id: 'msg1', preview: 'Hello', senderId: 'alice', tick: 5n, isStaleRoute: false }),
              new pb.InboxItem({ id: 'msg2', preview: 'World', isStaleRoute: true }),
            ],
          }),
        },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getInbox(10);
      expect(result.items).toHaveLength(2);
      expect(result.items[0]).toMatchObject({ id: 'msg1', preview: 'Hello', sender_id: 'alice', isStaleRoute: false });
      expect(result.items[1]).toMatchObject({ id: 'msg2', preview: 'World', isStaleRoute: true });
    });

    test('returns empty items when response has no items', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'inboxResponse',
          value: new pb.InboxResponse({ items: [] }),
        },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getInbox();
      expect(result.items).toEqual([]);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ code: 3, message: 'inbox fail' }) },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getInbox()).rejects.toThrow(/Native error.*inbox fail/);
    });

    test('throws on unexpected payload case', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getInbox()).rejects.toThrow(/Unexpected payload case for inbox/);
    });

    test('returns empty items when payload serializes as empty message', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'inboxResponse', value: undefined as any },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getInbox();
      expect(result.items).toEqual([]);
    });

    test('defaults empty fields in inbox items', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'inboxResponse',
          value: new pb.InboxResponse({
            items: [new pb.InboxItem({})],
          }),
        },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getInbox();
      expect(result.items[0].id).toBe('');
      expect(result.items[0].preview).toBe('');
    });
  });

  // ── listB0xMessages ────────────────────────────────────────────────

  describe('listB0xMessages', () => {
    test('re-maps inbox items to expected shape', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'inboxResponse',
          value: new pb.InboxResponse({
            items: [new pb.InboxItem({ id: 'b0x1', preview: 'hi', senderId: 'bob', tick: 3n, isStaleRoute: true })],
          }),
        },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await listB0xMessages();
      expect(result).toHaveLength(1);
      expect(result[0]).toMatchObject({
        id: 'b0x1',
        preview: 'hi',
        senderId: 'bob',
        tick: 3n,
        isStaleRoute: true,
      });
    });
  });

  // ── getTokens / getToken ───────────────────────────────────────────

  describe('getTokens', () => {
    test('maps balances to token list', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'balancesListResponse',
          value: new pb.BalancesListResponse({
            balances: [
              new pb.BalanceGetResponse({ tokenId: 'ERA', available: 100n, decimals: 8, symbol: 'ERA' }),
            ],
          }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const tokens = await getTokens();
      expect(tokens).toHaveLength(1);
      expect(tokens[0]).toEqual({ tokenId: 'ERA', balance: '100', decimals: 8, symbol: 'ERA' });
    });
  });

  describe('getToken', () => {
    function setupBalances() {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'balancesListResponse',
          value: new pb.BalancesListResponse({
            balances: [
              new pb.BalanceGetResponse({ tokenId: 'ERA', available: 100n, decimals: 8, symbol: 'ERA' }),
              new pb.BalanceGetResponse({ tokenId: 'dBTC', available: 50n, decimals: 8, symbol: 'dBTC' }),
            ],
          }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));
    }

    test('returns matching token by id', async () => {
      setupBalances();
      const token = await getToken('dBTC');
      expect(token).toEqual({ tokenId: 'dBTC', balance: '50', decimals: 8, symbol: 'dBTC' });
    });

    test('returns null for unknown token id', async () => {
      setupBalances();
      const token = await getToken('UNKNOWN');
      expect(token).toBeNull();
    });
  });
});
