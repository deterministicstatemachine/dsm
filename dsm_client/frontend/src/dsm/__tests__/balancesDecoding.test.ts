import { decodeBalancesListResponseStrict } from '../decoding';
import { BalancesListResponse, BalanceGetResponse, Envelope, Error as PbError } from '../../proto/dsm_app_pb';

describe('decodeBalancesListResponseStrict', () => {
  test('decodes Envelope-wrapped BalancesListResponse bytes', () => {
    const resp = new BalancesListResponse({
      balances: [new BalanceGetResponse({ tokenId: 'ERA', available: 7n, locked: 0n })],
    });
    const env = new Envelope({
      version: 3,
      payload: { case: 'balancesListResponse', value: resp }
    });
    // Add framing byte (0x03) as done by bridge
    const framed = new Uint8Array([0x03, ...env.toBinary()]);
    const out = decodeBalancesListResponseStrict(framed);
    expect(out.decodedVia).toBe('envelope');
    expect(out.response.balances.length).toBe(1);
    expect(out.response.balances[0].tokenId).toBe('ERA');
    expect(out.response.balances[0].available).toBe(7n);
  });

  test('throws on Error Envelope (fail-closed)', () => {
    const env = new Envelope({
      version: 3,
      payload: { case: 'error', value: new PbError({ code: 77, message: 'nope' }) }
    });
    // Add framing byte
    const framed = new Uint8Array([0x03, ...env.toBinary()]);
    expect(() => decodeBalancesListResponseStrict(framed)).toThrow(/Native error:.*nope/);
  });
});
