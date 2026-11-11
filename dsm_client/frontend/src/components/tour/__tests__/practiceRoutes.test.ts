// SPDX-License-Identifier: Apache-2.0
import { join } from 'path';
import { answerFromRustRecord } from '../../../tests/helpers/rustIngressRecord';
import { dsmClient } from '../../../services/dsmClient';
import { routerInvokeBin } from '../../../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../../../dsm/decoding';
import * as sofi from '../../../dsm/sofi';
import * as escrow from '../../../dsm/escrow';
import * as connect from '../../../dsm/connect';
import * as pb from '../../../proto/dsm_app_pb';
import { decodeBase32Crockford } from '../../../utils/textId';
import { practiceMode, PRACTICE_CONTACT_DEVICE_ID, PRACTICE_PLAY_ANCHOR } from '../practiceMode';
import { PRACTICE_CONNECT_CODE, PRACTICE_FIRST_VAULT_ID } from '../practiceRoutes';

const client = dsmClient as unknown as Record<string, (...args: any[]) => Promise<any>>;

const RECORD = join(__dirname, 'fixtures/wallet_amount.ingress.bin');

const held = async (tokenId: string) => (await client.getAllBalances()).find((r: any) => r.tokenId === tokenId);
const anchorOf = async (tokenId: string): Promise<Uint8Array> => decodeBase32Crockford((await held(tokenId)).policyAnchorB32);

describe('the practice wallet carries out the routes the tour walks through', () => {
  beforeAll(() => answerFromRustRecord(RECORD));
  beforeEach(() => practiceMode.enter());
  afterEach(() => practiceMode.leave());

  it('quotes a swap against the practice market and trades it at that quote', async () => {
    const play = decodeBase32Crockford(PRACTICE_PLAY_ANCHOR);
    const era = await anchorOf('ERA');
    const route = await sofi.findRoute({ tokenIn: play, tokenOut: era, amountIn: '10' });
    expect(route.hops).toHaveLength(1);
    // 10 PLAY into 1000 PLAY / 500.00 ERA at 30 bps: 9 whole PLAY after the fee, 445 base units of ERA out.
    expect(route.amountOutDisplay).toBe('4.45');
    const traded = await sofi.trade({ vaultId: route.hops[0].vaultId, tokenIn: play, tokenOut: era, amountIn: '10', minAmountOut: route.amountOutDisplay });
    expect(traded.state).toBe('realized');
    expect((await held('PLAY')).displayAmount).toBe('40');
    expect((await held('ERA')).displayAmount).toBe('1004.45');
  });

  it('leaves a trade void, moving nothing, when it gives less than the least accepted', async () => {
    const play = decodeBase32Crockford(PRACTICE_PLAY_ANCHOR);
    const era = await anchorOf('ERA');
    const route = await sofi.findRoute({ tokenIn: play, tokenOut: era, amountIn: '10' });
    const traded = await sofi.trade({ vaultId: route.hops[0].vaultId, tokenIn: play, tokenOut: era, amountIn: '10', minAmountOut: '5' });
    expect(traded.state).toBe('void');
    expect((await held('PLAY')).displayAmount).toBe('50');
  });

  it('opens a liquidity vault of the user\'s own, lists it, and closes it back into the balance', async () => {
    const play = decodeBase32Crockford(PRACTICE_PLAY_ANCHOR);
    const era = await anchorOf('ERA');
    const made = await sofi.createVault({ tokenA: play, tokenB: era, reserveA: '20', reserveB: '10', feeBps: 30 });
    expect(made.vaultId).toEqual(decodeBase32Crockford(PRACTICE_FIRST_VAULT_ID));
    expect((await held('PLAY')).displayAmount).toBe('30');
    const [vault] = await sofi.vaults();
    expect(vault).toEqual(expect.objectContaining({ symbolA: 'PLAY', symbolB: 'ERA', reserveADisplay: '20', reserveBDisplay: '10.00', status: 'active' }));
    expect((await sofi.close(made.vaultId)).state).toBe('realized');
    expect((await held('PLAY')).displayAmount).toBe('50');
    expect((await held('ERA')).displayAmount).toBe('1000.00');
    expect((await sofi.vaults())[0].status).toBe('retired');
  });

  it('locks an escrow stake, decides it, and releases it to the party it pays', async () => {
    const play = decodeBase32Crockford(PRACTICE_PLAY_ANCHOR);
    const me = await escrow.party();
    const alice = decodeBase32Crockford(PRACTICE_CONTACT_DEVICE_ID);
    const win = new TextEncoder().encode('I win');
    const lose = new TextEncoder().encode('alice wins');
    const locked = await escrow.lock({
      external: new TextEncoder().encode('alice and I bet on the match'),
      token: play,
      amountEntered: '5',
      outcomes: [
        { outcome: win, decidedBy: [me.deviceId], pays: me.deviceId },
        { outcome: lose, decidedBy: [me.deviceId], pays: alice },
      ],
    });
    expect((await held('PLAY')).displayAmount).toBe('45');
    const [vault] = await escrow.vaults();
    expect(vault.outcomes.every((o) => o.decidedByThisDevice)).toBeTruthy();
    expect(vault.outcomes[0].paysThisDevice).toBeTruthy();
    expect(vault.outcomes[1].paysThisDevice).toBeFalsy();
    await expect(escrow.release(locked.vaultId)).rejects.toThrow('no outcome is decided yet');
    expect((await escrow.decide(locked.vaultId, win)).state).toBe('final');
    expect((await escrow.release(locked.vaultId)).state).toBe('realized');
    expect((await held('PLAY')).displayAmount).toBe('50');
  });

  it('connects the practice app, puts what the grant does not cover in waiting, and disconnects', async () => {
    const offer = await connect.preview(PRACTICE_CONNECT_CODE);
    expect(offer.scopeLines).toEqual(['Send this app: up to 5 PLAY a time, 15 PLAY in all', 'Prove what you own of PLAY']);
    const session = await connect.approve(offer.offerDigest);
    expect(session.connected).toBeTruthy();
    const [waiting] = await connect.pending();
    expect(waiting.reason).toBe('8 PLAY is above the 5 PLAY the grant allows per request');
    const decided = await connect.respond(waiting.sessionId, waiting.seq, 'approve');
    expect(decided.outcome).toBe('carriedOut');
    expect((await held('PLAY')).displayAmount).toBe('42');
    expect(await connect.pending()).toEqual([]);
    const ended = await connect.disconnect(session.sessionId);
    expect(ended.connected).toBeFalsy();
  });

  it('answers nothing once the tour has ended: the call goes to Rust', async () => {
    practiceMode.leave();
    await expect(connect.preview(PRACTICE_CONNECT_CODE)).rejects.toThrow('Rust has no recorded answer');
  });

  it('keeps a real application\'s code from Rust, in practice', async () => {
    await expect(connect.preview('dsm:connect/v1:RAA')).rejects.toThrow('Practice mode');
  });

  it('creates a token, burning practice ERA, under a practice policy anchor', async () => {
    const body = new pb.TokenCreateRequest({ ticker: 'mine', alias: 'Mine', decimals: 0, genesisSupplyEntered: '1000' }).toBinary();
    const pack = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(body) }).toBinary();
    const env = decodeFramedEnvelopeV3(await routerInvokeBin('token.create', new Uint8Array(pack)));
    if (env.payload.case !== 'tokenCreateResponse') throw new Error(`token.create answered ${env.payload.case}`);
    expect(env.payload.value.success).toBeTruthy();
    expect(env.payload.value.ticker).toBe('MINE');
    expect((await held('MINE')).displayAmount).toBe('1000');
    expect((await held('ERA')).displayAmount).toBe('990.00');
  });
});
