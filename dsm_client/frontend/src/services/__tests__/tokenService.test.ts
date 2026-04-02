// SPDX-License-Identifier: Apache-2.0

jest.mock('../../dsm/index', () => ({
  dsmClient: {
    getAllBalances: jest.fn(),
  },
}));

jest.mock('../../utils/tokenMeta', () => ({
  getTokenDecimals: jest.fn((id: string) => {
    if (!id) return 0;
    const u = id.trim().toUpperCase();
    if (u === 'DBTC' || u === 'BTC') return 8;
    return 0;
  }),
}));

import { getTokenBalance, getTokenMetadata, listTokens, createToken, transferToken } from '../tokenService';
import { dsmClient } from '../../dsm/index';

const mockGetAllBalances = dsmClient.getAllBalances as jest.Mock;

describe('getTokenBalance', () => {
  it('returns zero balance when no matching token found', async () => {
    mockGetAllBalances.mockResolvedValue([]);
    const result = await getTokenBalance('ERA');
    expect(result.tokenId).toBe('ERA');
    expect(result.balance).toBe(0);
    expect(result.symbol).toBe('ERA');
    expect(result.decimals).toBe(0);
  });

  it('returns balance from ledger data', async () => {
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'ERA', balance: '500', symbol: 'ERA' },
    ]);
    const result = await getTokenBalance('ERA');
    expect(result.balance).toBe(500);
    expect(result.symbol).toBe('ERA');
  });

  it('normalizes "era" to match "ERA" case-insensitively', async () => {
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'ERA', balance: '42', symbol: 'ERA' },
    ]);
    const result = await getTokenBalance('era');
    expect(result.balance).toBe(42);
  });

  it('normalizes " era " with whitespace', async () => {
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'ERA', balance: '7', symbol: 'ERA' },
    ]);
    const result = await getTokenBalance(' era ');
    expect(result.balance).toBe(7);
  });

  it('clamps balance exceeding MAX_SAFE_INTEGER', async () => {
    const huge = (BigInt(Number.MAX_SAFE_INTEGER) + 1000n).toString();
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'ERA', balance: huge },
    ]);
    const result = await getTokenBalance('ERA');
    expect(result.balance).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('clamps negative balance below -MAX_SAFE_INTEGER', async () => {
    const negHuge = (-(BigInt(Number.MAX_SAFE_INTEGER) + 1000n)).toString();
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'ERA', balance: negHuge },
    ]);
    const result = await getTokenBalance('ERA');
    expect(result.balance).toBe(-Number.MAX_SAFE_INTEGER);
  });

  it('returns correct decimals for dBTC token', async () => {
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'dBTC', balance: '100000000' },
    ]);
    const result = await getTokenBalance('dBTC');
    expect(result.decimals).toBe(8);
  });
});

describe('getTokenMetadata', () => {
  it('returns ERA metadata', async () => {
    mockGetAllBalances.mockResolvedValue([]);
    const meta = await getTokenMetadata('ERA');
    expect(meta.tokenId).toBe('ERA');
    expect(meta.name).toBe('ERA Token');
    expect(meta.symbol).toBe('ERA');
    expect(meta.decimals).toBe(0);
  });

  it('returns generic metadata for non-ERA token', async () => {
    mockGetAllBalances.mockResolvedValue([]);
    const meta = await getTokenMetadata('CUSTOM');
    expect(meta.tokenId).toBe('CUSTOM');
    expect(meta.name).toBe('CUSTOM');
    expect(meta.symbol).toBe('CUSTOM');
  });
});

describe('listTokens', () => {
  it('returns empty list when no balances', async () => {
    mockGetAllBalances.mockResolvedValue([]);
    const tokens = await listTokens();
    expect(tokens).toEqual([]);
  });

  it('deduplicates tokens by id', async () => {
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'ERA', balance: '10', symbol: 'ERA' },
      { tokenId: 'ERA', balance: '20', symbol: 'ERA' },
      { tokenId: 'dBTC', balance: '5', symbol: 'dBTC' },
    ]);
    const tokens = await listTokens();
    expect(tokens).toHaveLength(2);
    expect(tokens.map((t) => t.tokenId)).toContain('ERA');
    expect(tokens.map((t) => t.tokenId)).toContain('dBTC');
  });

  it('uses presentNameFor and presentSymbolFor', async () => {
    mockGetAllBalances.mockResolvedValue([
      { tokenId: 'ERA', balance: '1' },
    ]);
    const tokens = await listTokens();
    expect(tokens[0].name).toBe('ERA Token');
    expect(tokens[0].symbol).toBe('ERA');
  });
});

describe('createToken / transferToken', () => {
  it('createToken throws strict error', async () => {
    await expect(createToken()).rejects.toThrow(/STRICT/);
  });

  it('transferToken throws strict error', async () => {
    await expect(transferToken()).rejects.toThrow(/STRICT/);
  });
});
