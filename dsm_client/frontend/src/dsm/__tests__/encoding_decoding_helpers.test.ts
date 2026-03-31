/// <reference types="jest" />
// Local aliases for Jest globals to satisfy TS when @types/jest is not picked up.
// Runtime uses Jest-provided globals.
declare const describe: any;
declare const it: any;
declare const expect: any;

import * as pb from '../../proto/dsm_app_pb';
import { decodeFramedEnvelopeV3, encodeEnvelope } from '../decoding';

describe('encoding/decoding helpers parity', () => {
  it('encodeEnvelope matches native toBinary and decodeFramedEnvelopeV3 round-trips via framing', () => {
    const headers = new pb.Headers({ deviceId: new Uint8Array(32), genesisHash: new Uint8Array(32), chainTip: new Uint8Array(32) } as any);
    const env = new pb.Envelope({ version: 3, headers } as any);
    const direct = env.toBinary();
    const encoded = encodeEnvelope(env);
    expect(encoded).toEqual(direct);
    // Wrap with 0x03 framing for canonical decode path
    const framed = new Uint8Array([0x03, ...encoded]);
    const decoded = decodeFramedEnvelopeV3(framed);
    expect(decoded.version).toBe(3);
    expect(decoded.headers?.deviceId?.length).toBe(32);
  });

  it('decodeFramedEnvelopeV3 surfaces envelope error payload', () => {
    const err = new pb.Error({ code: 7, message: 'boom' });
    const env = new pb.Envelope({ version: 3, payload: { case: 'error', value: err } as any } as any);
    const framed = new Uint8Array([0x03, ...env.toBinary()]);
    const out = decodeFramedEnvelopeV3(framed);
    expect(out.payload.case).toBe('error');
    if (out.payload.case === 'error') {
      expect(out.payload.value.message).toBe('boom');
    }
  });

  it('decodeFramedEnvelopeV3 decodes framed storage sync response envelope', () => {
    const resp = new pb.StorageSyncResponse({ success: true, pulled: 1, processed: 2, pushed: 3, errors: [] });
    const env = new pb.Envelope({
      version: 3,
      payload: { case: 'storageSyncResponse', value: resp } as any,
    } as any);
    const framed = new Uint8Array([0x03, ...env.toBinary()]);
    const decoded = decodeFramedEnvelopeV3(framed);
    expect(decoded.payload.case).toBe('storageSyncResponse');
    if (decoded.payload.case === 'storageSyncResponse') {
      expect(decoded.payload.value.success).toBe(true);
      expect(decoded.payload.value.pulled).toBe(1);
      expect(decoded.payload.value.processed).toBe(2);
      expect(decoded.payload.value.pushed).toBe(3);
    }
  });

});
