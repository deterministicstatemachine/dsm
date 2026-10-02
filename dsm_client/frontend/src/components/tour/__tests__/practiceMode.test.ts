// SPDX-License-Identifier: Apache-2.0
//! Practice mode stands in for the real client while the tour runs, so it must
//! answer in the shapes the real calls answer. Its offline send answered
//! `{ success }` where the real one answers `{ accepted }`, which is why the
//! send screen read both; and it sent a send naming no token as ERA.
//!
//! Every figure it shows is Rust's: it asks `wallet.amount` to parse what the
//! user typed and to render each balance. Jest runs no Rust, so the bridge here
//! answers from Rust's own record of those answers (fixtures/
//! wallet_amount.ingress.bin), which the dsm_sdk ingress test
//! `wallet_amount_answers_through_the_ingress_as_the_frontend_records_it`
//! writes and holds equal to the live ingress. A request Rust has no recorded
//! answer for is the bridge's error, so these tests pass only on Rust's answers.

import { readFileSync } from 'fs';
import { join } from 'path';
import * as pb from '../../../proto/dsm_app_pb';
import { dsmClient } from '../../../services/dsmClient';
import { practiceMode, PRACTICE_CONTACT_ALIAS, PRACTICE_CONTACT_DEVICE_ID } from '../practiceMode';

const client = dsmClient as unknown as Record<string, (...args: any[]) => Promise<any>>;

type RecordedAnswer = { request: Uint8Array; response: Uint8Array };

/** Rust's record: length-prefixed pairs of an IngressRequest and the IngressResponse the JNI handed back. */
function rustRecord(): RecordedAnswer[] {
  const bytes = new Uint8Array(readFileSync(join(__dirname, 'fixtures/wallet_amount.ingress.bin')));
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const part = (): Uint8Array => {
    const length = view.getUint32(at);
    const out = bytes.slice(at + 4, at + 4 + length);
    at += 4 + length;
    return out;
  };
  const answers: RecordedAnswer[] = [];
  while (at < bytes.length) answers.push({ request: part(), response: part() });
  return answers;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);

/** The app's bridge, answering the native ingress from Rust's record and nothing else. */
function answerFromRustRecord(): void {
  const record = rustRecord();
  window.DsmBridge = {
    sendMessageBin: async (bytes: Uint8Array): Promise<Uint8Array> => {
      const call = pb.BridgeRpcRequest.fromBinary(bytes);
      const payload = call.payload.case === 'bytes' ? call.payload.value.data : new Uint8Array(0);
      const answer = call.method === 'nativeBoundaryIngress'
        ? record.find((recorded) => sameBytes(recorded.request, payload))
        : undefined;
      if (!answer) {
        const message = `Rust has no recorded answer to this ${call.method} request`;
        return new pb.BridgeRpcResponse({ result: { case: 'error', value: { errorCode: 1, message } } }).toBinary();
      }
      return new pb.BridgeRpcResponse({
        result: { case: 'success', value: { data: new Uint8Array(answer.response) } },
      }).toBinary();
    },
  };
}

const eraRow = async () => (await client.getAllBalances()).find((r: any) => r.tokenId === 'ERA');

describe('practice mode answers as the real calls do', () => {
  beforeAll(() => answerFromRustRecord());
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
    const res = await client.sendOfflineTransfer({ tokenId: 'PLAY', to: PRACTICE_CONTACT_DEVICE_ID, amount: '5' });
    expect(res).toEqual({ accepted: true, result: expect.any(String) });
    const rows = await client.getAllBalances();
    expect(rows.find((r: any) => r.tokenId === 'PLAY')).toEqual(
      expect.objectContaining({ baseUnits: 45n, displayAmount: '45' }),
    );
  });

  it('refuses a send that names no token, as Rust does', async () => {
    const offline = await client.sendOfflineTransfer({ tokenId: '', to: PRACTICE_CONTACT_DEVICE_ID, amount: '5' });
    expect(offline).toEqual({ accepted: false, result: expect.stringContaining('names no token') });
    const online = await client.sendOnlineTransferSmart(PRACTICE_CONTACT_DEVICE_ID, '5', undefined, '');
    expect(online).toEqual({ success: false, message: expect.stringContaining('names no token') });
  });

  it('refuses moving offline cash: practice never touches the real allocation', async () => {
    await expect(client.loadOfflineCash('PLAY', '5')).rejects.toThrow(/Practice mode/);
    await expect(client.unloadOfflineCash('PLAY', '5')).rejects.toThrow(/Practice mode/);
  });
});

describe('practice ERA counts as Rust counts ERA', () => {
  beforeAll(() => answerFromRustRecord());
  beforeEach(() => practiceMode.enter());
  afterEach(() => practiceMode.leave());

  it("holds the tour's 1000 ERA at ERA's decimals, and the welcome payment that brought it", async () => {
    expect(await eraRow()).toEqual(
      expect.objectContaining({ symbol: 'ERA', decimals: 2, baseUnits: 100000n, displayAmount: '1000.00' }),
    );
    const { transactions } = await client.getWalletHistory();
    expect(transactions).toEqual([
      expect.objectContaining({ txId: 'practice-welcome', tokenId: 'ERA', amount: 100000n, displayAmount: '1000.00' }),
    ]);
  });

  it("takes the tour's 25 ERA as Rust parses it and shows what is left as Rust renders it", async () => {
    const res = await client.sendOnlineTransferSmart(PRACTICE_CONTACT_DEVICE_ID, '25', undefined, 'ERA');
    expect(res).toEqual(expect.objectContaining({ newBalance: 97500n }));
    expect(await eraRow()).toEqual(expect.objectContaining({ baseUnits: 97500n, displayAmount: '975.00' }));
    const { transactions } = await client.getWalletHistory();
    expect(transactions[0]).toEqual(
      expect.objectContaining({ tokenId: 'ERA', recipient: PRACTICE_CONTACT_ALIAS, amount: -2500n, displayAmount: '-25.00' }),
    );
  });

  it("pays the faucet's 100 ERA as Rust counts it, and says so in Rust's rendering", async () => {
    const res = await client.claimFaucet();
    expect(res).toEqual(expect.objectContaining({ tokensReceived: 10000n, message: 'Practice: claimed 100.00 ERA' }));
    expect(await eraRow()).toEqual(expect.objectContaining({ baseUnits: 110000n, displayAmount: '1100.00' }));
  });

  it("refuses an amount finer than ERA counts, in Rust's words, and takes nothing", async () => {
    const res = await client.sendOnlineTransferSmart(PRACTICE_CONTACT_DEVICE_ID, '1.234', undefined, 'ERA');
    expect(res).toEqual(
      expect.objectContaining({ message: expect.stringContaining('wallet.amount: amount exceeds 2 fractional digits') }),
    );
    expect(res).not.toHaveProperty('newBalance');
    expect(await eraRow()).toEqual(expect.objectContaining({ baseUnits: 100000n, displayAmount: '1000.00' }));
    expect((await client.getWalletHistory()).transactions).toHaveLength(1);
  });

  it('refuses a send of nothing, and takes nothing', async () => {
    const res = await client.sendOfflineTransfer({ tokenId: 'ERA', to: PRACTICE_CONTACT_DEVICE_ID, amount: '0' });
    expect(res).toEqual(expect.objectContaining({ result: 'Enter an amount above zero.' }));
    expect(await eraRow()).toEqual(expect.objectContaining({ baseUnits: 100000n, displayAmount: '1000.00' }));
    expect((await client.getWalletHistory()).transactions).toHaveLength(1);
  });
});
