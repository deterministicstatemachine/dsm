/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/dsm/dlv.ts
// SPDX-License-Identifier: Apache-2.0
// DLV (Deterministic Limbo Vault) lifecycle helpers.
// All calls go through the normal AppRouter protobuf envelope path:
//   TypeScript → appRouterInvokeBin → MessagePort → Kotlin → JNI → Rust

import * as pb from '../proto/dsm_app_pb';
import { appRouterInvokeBin } from './WebViewBridge';
import { decodeBase32Crockford, encodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';

/**
 * Create a DLV (Deterministic Limbo Vault) from a serialised DlvCreateV3 proto.
 *
 * @param params.lock      Base32 Crockford encoding of the DlvCreateV3 proto bytes.
 * @param params.condition Optional Base32 Crockford encoding of a DlvOpenV3 proto for
 *                         the matching unlock condition (currently stored for future use).
 * @returns { success, id?, error? } — `id` is the vault_id as Base32 Crockford.
 */
export async function createCustomDlv(params: {
  lock: string;
  condition?: string;
}): Promise<{ success: boolean; id?: string; error?: string }> {
  try {
    const lockB32 = typeof params?.lock === 'string' ? params.lock.trim() : '';
    if (!lockB32) return { success: false, error: 'DLV create payload (lock) required' };

    const lockBytes = decodeBase32Crockford(lockB32);
    if (!lockBytes || lockBytes.length === 0) {
      return { success: false, error: 'decoded DlvCreateV3 bytes empty' };
    }

    // Validate that the payload decodes as a DlvCreateV3 proto.
    const create = pb.DlvCreateV3.fromBinary(lockBytes);
    if (!create.deviceId || create.deviceId.length !== 32) {
      return { success: false, error: 'DlvCreateV3.device_id must be 32 bytes' };
    }
    if (!create.policyDigest || create.policyDigest.length !== 32) {
      return { success: false, error: 'DlvCreateV3.policy_digest must be 32 bytes' };
    }
    if (!create.precommit || create.precommit.length !== 32) {
      return { success: false, error: 'DlvCreateV3.precommit must be 32 bytes' };
    }
    if (!create.vaultId || create.vaultId.length !== 32) {
      return { success: false, error: 'DlvCreateV3.vault_id must be 32 bytes' };
    }

    // Pack the DlvCreateV3 bytes into an ArgPack for transport.
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(lockBytes),
    });

    const resBytes = await appRouterInvokeBin('dlv.create', new Uint8Array(argPack.toBinary()));
    const env = decodeFramedEnvelopeV3(resBytes);

    if (env.payload.case === 'error') {
      return { success: false, error: env.payload.value.message || 'dlv.create failed' };
    }

    if (env.payload.case === 'appStateResponse') {
      const vaultIdB32 = env.payload.value.value ?? encodeBase32Crockford(create.vaultId);
      return { success: true, id: vaultIdB32 };
    }

    return {
      success: false,
      error: `Unexpected response payload: ${env.payload.case}`,
    };
  } catch (e: any) {
    return { success: false, error: e?.message || 'createCustomDlv failed' };
  }
}
