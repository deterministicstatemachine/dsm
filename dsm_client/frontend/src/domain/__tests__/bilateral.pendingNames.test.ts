// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-18, SA-159: the counterparty alias a pending bilateral step
// carries is shown as every name is, without what renders as nothing; an
// alias of nothing else is no alias.

import * as pb from '../../proto/dsm_app_pb';
import { decodeOfflinePendingList } from '../bilateral';

const HANGUL_FILLER = '\u3164';
const RLO = '\u202E';

function framed(payload: pb.Envelope['payload']): Uint8Array {
  const env = new pb.Envelope({ version: 3, payload }).toBinary();
  const out = new Uint8Array(1 + env.length);
  out[0] = 0x03;
  out.set(env, 1);
  return out;
}

function step(fill: number, counterpartyAlias: string): pb.OfflineBilateralTransaction {
  return new pb.OfflineBilateralTransaction({
    id: `step-${fill}`,
    senderId: new Uint8Array(32).fill(fill),
    recipientId: new Uint8Array(32).fill(0x0A),
    commitmentHash: new Uint8Array(32).fill(fill + 1),
    phase: pb.OfflineBilateralPhase.OFFLINE_PHASE_PENDING_USER_ACTION,
    direction: pb.OfflineBilateralDirection.OFFLINE_DIRECTION_INCOMING,
    amount: 100n,
    displayAmount: '1.00',
    tokenId: 'ERA',
    counterpartyAlias,
  });
}

describe('pending bilateral steps (SA-159)', () => {
  it('carries the counterparty alias without its fillers and controls, and none that is nothing else', async () => {
    const bytes = framed({
      case: 'offlineBilateralPendingListResponse',
      value: new pb.OfflineBilateralPendingListResponse({
        transactions: [step(0x01, `bob${HANGUL_FILLER}`), step(0x03, `${RLO}bob`), step(0x05, `${HANGUL_FILLER}\uFFA0`)],
      }),
    });
    const steps = await decodeOfflinePendingList(bytes);
    expect(steps.map((s) => s.counterpartyAlias)).toEqual(['bob', 'bob', undefined]);
  });
});
