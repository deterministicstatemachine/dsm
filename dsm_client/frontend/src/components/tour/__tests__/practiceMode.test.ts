// SPDX-License-Identifier: Apache-2.0
//! Practice mode stands in for the real client while the tour runs, so it must
//! answer in the shapes the real calls answer. Its offline send answered
//! `{ success }` where the real one answers `{ accepted }`, which is why the
//! send screen read both; and it sent a send naming no token as ERA.

import { dsmClient } from '../../../services/dsmClient';
import { practiceMode, PRACTICE_CONTACT_ALIAS } from '../practiceMode';

const client = dsmClient as unknown as Record<string, (...args: any[]) => Promise<any>>;

describe('practice mode answers as the real calls do', () => {
  beforeEach(() => practiceMode.enter());
  afterEach(() => practiceMode.leave());

  it('lists balances as balance.list rows', async () => {
    const rows = await client.getAllBalances();
    const play = rows.find((r: any) => r.tokenId === 'PLAY');
    expect(play).toEqual(
      expect.objectContaining({ symbol: 'PLAY', baseUnits: 50n, displayAmount: '50', decimals: 0 }),
    );
  });

  it('answers an offline send in the shape sendOfflineTransfer does', async () => {
    const res = await client.sendOfflineTransfer({ tokenId: 'PLAY', to: PRACTICE_CONTACT_ALIAS, amount: '5' });
    expect(res).toEqual({ accepted: true, result: expect.any(String) });
    const rows = await client.getAllBalances();
    expect(rows.find((r: any) => r.tokenId === 'PLAY')).toEqual(
      expect.objectContaining({ baseUnits: 45n, displayAmount: '45' }),
    );
  });

  it('refuses a send that names no token, as Rust does', async () => {
    const offline = await client.sendOfflineTransfer({ tokenId: '', to: PRACTICE_CONTACT_ALIAS, amount: '5' });
    expect(offline).toEqual({ accepted: false, result: expect.stringContaining('names no token') });
    const online = await client.sendOnlineTransferSmart(PRACTICE_CONTACT_ALIAS, '5', undefined, '');
    expect(online).toEqual({ success: false, message: expect.stringContaining('names no token') });
  });
});
