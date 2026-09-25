// SPDX-License-Identifier: MIT OR Apache-2.0

import * as pb from '../proto/dsm_app_pb';
import { syncWithStorageStrictBridge, routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import type { StorageMember, StorageMemberAnswer, StorageStatus } from './types';
import { bytesToBase32CrockfordPrefix, encodeBase32Crockford } from '../utils/textId';
import { emitWalletRefresh } from './events';
import logger from '../utils/logger';

export async function syncWithStorage(params?: { pullInbox?: boolean; pushPending?: boolean; limit?: number }): Promise<{ success: boolean; processed?: number; pulled?: number; pushed?: number; errors?: string[]; message?: string }> {
  const _params = { pullInbox: true, pushPending: false, limit: 50, ...params };
  try {
    const protobufBytes = await syncWithStorageStrictBridge({
      pullInbox: _params.pullInbox,
      pushPending: _params.pushPending,
      limit: _params.limit,
    });

    if (protobufBytes.length === 0) {
      return { success: false, message: 'Empty response from bridge' };
    }

    logger.debug('[DSM:syncWithStorage] Response bytes metadata', {
      length: protobufBytes.length,
      headB32: bytesToBase32CrockfordPrefix(protobufBytes, 8),
    });

    // CANONICAL PATH: All bridge responses are FramedEnvelopeV3
    let env: pb.Envelope;
    try {
      env = decodeFramedEnvelopeV3(protobufBytes);
    } catch (e) {
      logger.error('[DSM:syncWithStorage] Failed to decode FramedEnvelopeV3:', e);
      return { success: false, message: `Decode failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    // Check for error envelope
    if (env.payload.case === 'error') {
      const err = env.payload.value;
      logger.warn('[DSM:syncWithStorage] Bridge returned Error envelope:', err.message);
      return { success: false, processed: 0, pulled: 0, pushed: 0, message: `Sync failed: ${err.message || 'unknown error'}` };
    }

    // Extract StorageSyncResponse from envelope
    if (env.payload.case !== 'storageSyncResponse') {
      logger.error('[DSM:syncWithStorage] Unexpected payload.case:', env.payload.case);
      return { success: false, message: `Unexpected response type: ${env.payload.case}` };
    }

    const syncResponse = env.payload.value;
    if (!syncResponse) {
      logger.warn('[DSM:syncWithStorage] Null storageSyncResponse payload');
      return { success: false, processed: 0, pulled: 0, pushed: 0, message: 'Sync failed: null response' };
    }

    logger.debug('[DSM:syncWithStorage] Result', {
      success: syncResponse.success,
      pulled: syncResponse.pulled,
      processed: syncResponse.processed,
      pushed: syncResponse.pushed,
      errors: syncResponse.errors,
    });

    // Trigger balance refresh on the receiver side after items are ingested.
    // SQLite was already credited by the Rust storage.sync handler; the UI
    // just needs to read the new value.
    const processed = syncResponse.processed ?? 0;
    const result = {
      success: syncResponse.success,
      pulled: syncResponse.pulled,
      processed: syncResponse.processed,
      pushed: syncResponse.pushed,
      errors: syncResponse.errors,
      message: syncResponse.errors.length > 0 ? syncResponse.errors[0] : undefined,
    };
    if (processed > 0) {
      try { emitWalletRefresh({ source: 'storage.sync' }); } catch {}
    }
    return result;
  } catch (e) {
    logger.warn('Bridge syncWithStorage failed:', e);
    return { success: false, message: e instanceof Error ? e.message : 'Bridge call failed' };
  }
}

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
