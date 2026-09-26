// SPDX-License-Identifier: MIT OR Apache-2.0

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
  getWalletHistory,
  getInbox,
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
              new pb.BalanceGetResponse({ tokenId: 'ERA', available: 1000n, symbol: 'ERA', decimals: 0, tokenName: 'ERA', displayAmount: '1000', protocolDefined: true }),
              new pb.BalanceGetResponse({
                tokenId: 'RIGB',
                available: 100000n,
                symbol: 'RIGB',
                decimals: 2,
                tokenName: 'Rig Bucks',
                displayAmount: '1000.00',
                canonicalTokenId: 'CANON1CAL',
                policyAnchorB32: 'ANCH0R',
                anchorFingerprint: 'ANCH',
                iconUrl: 'dsm:coin:v1:ABC',
                protocolDefined: false,
                genesisSupplyDisplay: '1000.00',
                permissions: { burnEnabled: true, transferable: false },
              }),
            ],
          }),
        },
      });
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getAllBalances();
      expect(result).toEqual([
        // Rust names no canonical id, anchor or icon for this row: absent, not empty.
        {
          tokenId: 'ERA',
          symbol: 'ERA',
          tokenName: 'ERA',
          baseUnits: 1000n,
          decimals: 0,
          displayAmount: '1000',
          canonicalTokenId: undefined,
          policyAnchorB32: undefined,
          anchorFingerprint: undefined,
          iconUrl: undefined,
          // A protocol asset on Rust's word; it states no supply here and no
          // permissions, and neither is filled in.
          protocolDefined: true,
          genesisSupplyDisplay: undefined,
          permissions: undefined,
        },
        {
          tokenId: 'RIGB',
          symbol: 'RIGB',
          tokenName: 'Rig Bucks',
          baseUnits: 100000n,
          decimals: 2,
          displayAmount: '1000.00',
          canonicalTokenId: 'CANON1CAL',
          policyAnchorB32: 'ANCH0R',
          anchorFingerprint: 'ANCH',
          iconUrl: 'dsm:coin:v1:ABC',
          protocolDefined: false,
          genesisSupplyDisplay: '1000.00',
          permissions: { burnEnabled: true, transferable: false },
        },
      ]);
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

    test('a row without the fields Rust always writes is refused, never filled in', async () => {
      const answer = (row: pb.BalanceGetResponse) =>
        frameEnvelope(new pb.Envelope({
          version: 3,
          payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse({ balances: [row] }) },
        }));

      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(answer(new pb.BalanceGetResponse({})));
      await expect(getAllBalances()).rejects.toThrow(/STRICT.*without its token_id/);

      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(
        answer(new pb.BalanceGetResponse({ tokenId: 'RIGB', available: 5n, symbol: 'RIGB', tokenName: 'RIGB' })),
      );
      await expect(getAllBalances()).rejects.toThrow(/STRICT.*RIGB without its display_amount/);

      // A created token without its policy's facts: Rust reads them from the
      // committed bytes or refuses the row, so their absence is not a row.
      (getAllBalancesStrictBridge as jest.Mock).mockResolvedValue(
        answer(new pb.BalanceGetResponse({ tokenId: 'RIGB', available: 5n, symbol: 'RIGB', tokenName: 'RIGB', displayAmount: '5' })),
      );
      await expect(getAllBalances()).rejects.toThrow(/STRICT.*created token RIGB without its policy facts/);
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

  // ── getInbox ───────────────────────────────────────────────────────

  describe('getInbox', () => {
    test('maps inbox items correctly', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'inboxResponse',
          value: new pb.InboxResponse({
            items: [
              new pb.InboxItem({ id: 'msg1', preview: 'Hello', senderId: 'alice', isStaleRoute: false }),
              new pb.InboxItem({ id: 'msg2', preview: 'World', isStaleRoute: true }),
            ],
          }),
        },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getInbox(10);
      expect(result.items).toHaveLength(2);
      expect(result.items[0]).toMatchObject({ id: 'msg1', preview: 'Hello', senderId: 'alice', isStaleRoute: false });
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

    // Rust writes an id and a preview on every item; an item without them is
    // refused, never shown as "" or a stand-in label.
    test('an item without its id or preview is refused, never filled in', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'inboxResponse',
          value: new pb.InboxResponse({ items: [new pb.InboxItem({ id: 'msg1' })] }),
        },
      });
      (getInboxStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await expect(getInbox()).rejects.toThrow('STRICT');
    });
  });

});
