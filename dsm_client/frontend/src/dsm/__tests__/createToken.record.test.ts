// SPDX-License-Identifier: Apache-2.0
// createToken tells Rust's refusal from a call Rust never answered. A refusal
// is a result that did not succeed, with Rust's reason; an unanswered call
// throws, because the creation may have committed while it ran and the wizard
// asks again. The bridge answers from Rust's own record (ingress.rs,
// token_check_answers_through_the_ingress_as_the_wizard_records_it).

import { join } from 'path';
import * as pb from '../../proto/dsm_app_pb';
import { answerFromRustRecord, readRustRecord } from '../../tests/helpers/rustIngressRecord';
import { createToken, type TokenCreateDetails } from '../policies';

const RECORD = join(__dirname, '../../components/__tests__/fixtures/token_check.ingress.bin');

/** The token.create request Rust's record holds, as the wizard's details. */
function recordedCreation(): TokenCreateDetails {
  for (const { request } of readRustRecord(RECORD)) {
    const op = pb.IngressRequest.fromBinary(request).operation;
    if (op.case === 'routerInvoke' && op.value.method === 'token.create') {
      const r = pb.TokenCreateRequest.fromBinary(pb.ArgPack.fromBinary(op.value.args).body);
      return {
        ticker: r.ticker,
        alias: r.alias,
        decimals: r.decimals,
        genesisSupply: r.genesisSupplyEntered,
        burnEnabled: r.burnEnabled,
        transferable: r.transferable,
        threshold: r.threshold,
      };
    }
  }
  throw new Error('the record holds no token.create');
}

describe('createToken', () => {
  beforeEach(() => {
    answerFromRustRecord(RECORD);
  });

  it("answers Rust's refusal as a creation that did not succeed, in Rust's words", async () => {
    const res = await createToken(recordedCreation());
    expect(res.success).toBeFalsy();
    expect(res.message).toContain('ticker: a ticker is 2 to 8 characters, not 1');
  });

  it('throws when Rust never answered, so the caller asks again', async () => {
    await expect(createToken({ ...recordedCreation(), ticker: 'ZZ' })).rejects.toThrow(/no recorded answer/);
  });
});
