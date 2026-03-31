/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// Local declarations since tests are excluded from tsconfig type-check.
declare const describe: any;
declare const test: any;
declare const expect: any;

import * as pb from './dsm_app_pb';
import { extractGenesisCreated, extractSystemGenesisResponse } from './util';

describe('proto util', () => {
  test('extractGenesisCreated supports ES oneof {case, value}', () => {
    const gc = new pb.GenesisCreated({ sessionId: 'sess-1', threshold: 1 });
    const env: any = new pb.Envelope({
      version: 3,
      payload: { case: 'genesisCreatedResponse', value: gc },
    });
    const out = extractGenesisCreated(env as pb.Envelope);
    expect(out).toBeInstanceOf(pb.GenesisCreated);
    expect(out.sessionId).toBe('sess-1');
  });

  test('extractGenesisCreated rejects non-canonical generator shapes', () => {
    const env: any = {
      payload: { legacyShape: 'genesisCreatedResponse' },
    };
    expect(() => extractGenesisCreated(env as pb.Envelope)).toThrow(/no genesisCreatedResponse/i);
  });

  test('extractGenesisCreated throws when missing', () => {
    const env: any = { payload: { case: 'somethingElse' } };
    expect(() => extractGenesisCreated(env as pb.Envelope)).toThrow(/no genesisCreatedResponse/i);
  });

  test('extractSystemGenesisResponse decodes from UniversalRx', () => {
    const resp = new pb.SystemGenesisResponse({ publicKey: new Uint8Array([1, 2, 3]) });
    const body = resp.toBinary();
    const env: any = {
      payload: {
        case: 'universalRx',
        value: { results: [{ result: { body } }] },
      },
    };
    const out = extractSystemGenesisResponse(env as pb.Envelope);
    expect(out).toBeInstanceOf(pb.SystemGenesisResponse);
    expect(out.publicKey).toBeInstanceOf(Uint8Array);
    expect(Array.from(out.publicKey)).toEqual([1, 2, 3]);
  });

  test('extractSystemGenesisResponse decodes from BatchEnvelope with first inner', () => {
    const resp = new pb.SystemGenesisResponse({ publicKey: new Uint8Array([7]) });
    const body = resp.toBinary();
    const innerEnv: any = {
      payload: {
        case: 'universalRx',
        value: { results: [{ result: { body } }] },
      },
    };
    const env: any = { payload: { case: 'batchEnvelope', value: { envelopes: [innerEnv] } } };
    const out = extractSystemGenesisResponse(env as pb.Envelope);
    expect(Array.from(out.publicKey)).toEqual([7]);
  });

  test('extractSystemGenesisResponse throws when first result has error', () => {
    const env: any = {
      payload: { case: 'universalRx', value: { results: [{ error: { message: 'boom' } }] } },
    };
    expect(() => extractSystemGenesisResponse(env as pb.Envelope)).toThrow(/boom/);
  });

  test('extractSystemGenesisResponse throws when missing body', () => {
    const env: any = {
      payload: { case: 'universalRx', value: { results: [{ result: {} }] } },
    };
    expect(() => extractSystemGenesisResponse(env as pb.Envelope)).toThrow(/missing result body/i);
  });

  test('extractSystemGenesisResponse throws when payload is not universalRx', () => {
    const env: any = { payload: { case: 'notRx', value: {} } };
    expect(() => extractSystemGenesisResponse(env as pb.Envelope)).toThrow(/no universalRx/i);
  });
});
