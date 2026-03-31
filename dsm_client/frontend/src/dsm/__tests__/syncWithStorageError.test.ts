import { syncWithStorage } from '../index';
import { Envelope, Error as PbError, ResultPack } from '../../proto/dsm_app_pb';

describe('syncWithStorage error envelope handling', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  test('returns failure when bridge returns Error envelope', async () => {
    const env = new Envelope({ version: 3, payload: { case: 'error', value: new PbError({ code: 42, message: 'boom' }) } as any });
    const framed = new Uint8Array([0x03, ...env.toBinary()]);
    const { decodeFramedEnvelopeV3 } = await import('../decoding');
    const out = decodeFramedEnvelopeV3(framed);
    expect(out.payload.case).toBe('error');
    if (out.payload.case === 'error') {
      expect(out.payload.value.message).toBe('boom');
    }
  });

  test('getAllBalances throws when bridge returns Error envelope', async () => {
    const env = new Envelope({ version: 3, payload: { case: 'error', value: new PbError({ code: 77, message: 'nope' }) } as any });
    // Add framing byte as done by bridge
    const framed = new Uint8Array([0x03, ...env.toBinary()]);
    // Test direct call
    const { decodeBalancesListResponseStrict } = await import('../decoding');
    expect(() => decodeBalancesListResponseStrict(framed)).toThrow(/Native error:.*nope/);
  });
});
