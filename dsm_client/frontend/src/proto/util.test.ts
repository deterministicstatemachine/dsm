/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// Local declarations since tests are excluded from tsconfig type-check.
declare const describe: any;
declare const test: any;
declare const expect: any;

import * as pb from './dsm_app_pb';
import { extractGenesisCreated } from './util';

describe('proto util', () => {
  test('extractGenesisCreated supports ES oneof {case, value}', () => {
    const gc = new pb.GenesisCreated({ networkId: 'dsm-testnet', locale: 'en-US' });
    const env: any = new pb.Envelope({
      version: 3,
      payload: { case: 'genesisCreatedResponse', value: gc },
    });
    const out = extractGenesisCreated(env as pb.Envelope);
    expect(out).toBeInstanceOf(pb.GenesisCreated);
    expect(out.networkId).toBe('dsm-testnet');
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
});
