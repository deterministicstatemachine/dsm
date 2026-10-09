// SPDX-License-Identifier: MIT OR Apache-2.0

import * as pb from '../proto/dsm_app_pb';
import { routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import type { StorageMember, StorageMemberAnswer, StorageStatus } from './types';
import { encodeBase32Crockford } from '../utils/textId';

/**
 * The storage set this device's traffic uses, and what each member answered
 * when asked for its latest ByteCommit (SDK `storage.status`). The SDK names
 * the set and reads the members; this only renders what it reports.
 */
export async function getStorageStatus(): Promise<StorageStatus> {
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(new pb.StorageStatusRequest().toBinary()) });
  const resBytes = await routerQueryBin('storage.status', new Uint8Array(arg.toBinary()));
  if (!resBytes || resBytes.length === 0) {
    throw new Error('getStorageStatus: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`getStorageStatus: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'storageStatusResponse') {
    throw new Error(`getStorageStatus: unexpected payload ${env.payload.case}`);
  }

  const resp = env.payload.value;
  return {
    networkId: resp.networkId,
    storageSetIdB32: encodeBase32Crockford(resp.storageSetId),
    members: resp.members.map(toStorageMember),
    completedSyncs: resp.completedSyncs,
    databaseBytes: resp.databaseBytes,
  };
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

function toStorageMember(m: pb.StorageMemberStatus): StorageMember {
  const memberId = utf8.decode(m.memberId);
  return {
    memberId,
    registerIncarnationB32: encodeBase32Crockford(m.registerIncarnationId),
    endpoint: m.endpoint,
    answer: toMemberAnswer(memberId, m.answer),
    answeredAs: m.answeredAs === undefined ? undefined : utf8.decode(m.answeredAs),
  };
}

function toMemberAnswer(memberId: string, answer: pb.StorageMemberStatus['answer']): StorageMemberAnswer {
  switch (answer.case) {
    case 'latest': {
      const commit = answer.value.commit;
      if (!commit) {
        throw new Error(`getStorageStatus: member ${memberId} answered a ByteCommit the SDK did not include`);
      }
      return {
        kind: 'latest',
        cycle: commit.cycleIndex,
        bytesUsed: commit.bytesUsed,
        rootB32: encodeBase32Crockford(commit.smtRoot),
        parentB32: encodeBase32Crockford(commit.parentDigest),
        digestB32: encodeBase32Crockford(answer.value.digest),
      };
    }
    case 'noCycle':
      return { kind: 'noCycle' };
    case 'unanswered':
      return { kind: 'unanswered', why: answer.value };
    default:
      throw new Error(`getStorageStatus: member ${memberId} carries no answer`);
  }
}
