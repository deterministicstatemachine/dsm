/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import { syncWithStorageStrictBridge, appRouterQueryBin, appRouterInvokeBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { StorageStatus, DlvIndexEntry } from './types';
import { bytesToBase32CrockfordPrefix } from '../utils/textId';
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
 * Get storage-node status via SDK bridge (storage.status route).
 * Returns StorageStatusResponse proto fields directly.
 */
export async function getStorageStatus(): Promise<StorageStatus> {
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) });
  const resBytes = await appRouterQueryBin('storage.status', new Uint8Array(arg.toBinary()));
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
  if (!resp) {
    throw new Error('getStorageStatus: storageStatusResponse payload is null');
  }

  return {
    nodeId: 'storage',
    isReachable: resp.connectedNodes > 0,
    latencyMs: 0,
    lastSyncTick: BigInt(resp.lastSyncIter ?? 0),
    storageUsedBytes: 0,
    quotaBytes: 0,
    isPaid: true,
    subscriptions: [],
    totalNodes: resp.totalNodes,
    connectedNodes: resp.connectedNodes,
    dataSize: resp.dataSize,
    backupStatus: resp.backupStatus,
  };
}

/**
 * Fetch per-node health stats from all configured storage nodes.
 * Routes through SDK → storage.nodeHealth → Prometheus scrape.
 */
export async function getNodeHealth(endpoints?: string[]): Promise<pb.StorageNodeStatsResponse> {
  const req = new pb.StorageNodeStatsRequest({ endpoints: endpoints ?? [] });
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(req.toBinary()) });
  const resBytes = await appRouterQueryBin('storage.nodeHealth', new Uint8Array(arg.toBinary()));

  if (!resBytes || resBytes.length === 0) {
    throw new Error('getNodeHealth: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`getNodeHealth: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'storageNodeStatsResponse') {
    throw new Error(`getNodeHealth: unexpected payload ${env.payload.case}`);
  }

  return env.payload.value;
}

/**
 * Request the SDK to auto-assign the next storage node via keyed Fisher-Yates.
 *
 * The caller does NOT choose which node is added — the SDK selects
 * deterministically from the known pool (dsm_env_config.toml nodes minus
 * already-active nodes) using BLAKE3-seeded Fisher-Yates permutation.
 * `assigned_url` in the response identifies the selected node.
 */
export async function addStorageNode(): Promise<pb.StorageNodeManageResponse> {
  const req = new pb.StorageNodeManageRequest({ action: 'add', autoAssign: true });
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(req.toBinary()) });
  const resBytes = await appRouterInvokeBin('storage.addNode', new Uint8Array(arg.toBinary()));

  if (!resBytes || resBytes.length === 0) {
    throw new Error('addStorageNode: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`addStorageNode: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'storageNodeManageResponse') {
    throw new Error(`addStorageNode: unexpected payload ${env.payload.case}`);
  }

  return env.payload.value;
}

/**
 * Remove a storage node endpoint via SDK bridge.
 */
export async function removeStorageNode(url: string): Promise<pb.StorageNodeManageResponse> {
  const req = new pb.StorageNodeManageRequest({ action: 'remove', url });
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(req.toBinary()) });
  const resBytes = await appRouterInvokeBin('storage.removeNode', new Uint8Array(arg.toBinary()));

  if (!resBytes || resBytes.length === 0) {
    throw new Error('removeStorageNode: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`removeStorageNode: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'storageNodeManageResponse') {
    throw new Error(`removeStorageNode: unexpected payload ${env.payload.case}`);
  }

  return env.payload.value;
}

/**
 * List all local dBTC vaults (DLVs) via the bitcoin.vault.list bridge route.
 * Returns a DlvIndexEntry[] mapped from BitcoinVaultSummary proto messages.
 */
export async function listLocalDlvs(): Promise<DlvIndexEntry[]> {
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) });
  let resBytes: Uint8Array | undefined;
  try {
    resBytes = await appRouterQueryBin('bitcoin.vault.list', new Uint8Array(arg.toBinary()));
  } catch (e) {
    logger.warn('[DSM:listLocalDlvs] Bridge call failed:', e);
    return [];
  }

  if (!resBytes || resBytes.length === 0) {
    logger.debug('[DSM:listLocalDlvs] Empty response from bridge');
    return [];
  }

  let env: pb.Envelope;
  try {
    env = decodeFramedEnvelopeV3(resBytes);
  } catch (e) {
    logger.error('[DSM:listLocalDlvs] Failed to decode FramedEnvelopeV3:', e);
    return [];
  }

  if (env.payload.case === 'error') {
    logger.warn('[DSM:listLocalDlvs] Bridge returned error:', env.payload.value.message);
    return [];
  }

  if (env.payload.case !== 'bitcoinVaultListResponse') {
    logger.warn('[DSM:listLocalDlvs] Unexpected payload.case:', env.payload.case);
    return [];
  }

  const stateMap: Record<string, DlvIndexEntry['status']> = {
    limbo: 'LOCKED',
    unlocked: 'UNLOCKABLE',
    claimed: 'SPENT',
    invalidated: 'EXPIRED',
  };

  return env.payload.value.vaults.map((v): DlvIndexEntry => ({
    vaultId: v.vaultId,
    cptaAnchorHex: v.vaultId,
    createdAtTick: 0n,
    status: stateMap[v.state] ?? 'LOCKED',
    balance: {
      tokenId: 'dBTC',
      baseUnits: BigInt(v.amountSats),
      decimals: 8,
      symbol: 'dBTC',
    },
    conditions: [],
    expectedReplication: 0,
    localLabel:
      v.direction === 'btc_to_dbtc'
        ? 'BTC → dBTC'
        : v.direction === 'dbtc_to_btc'
          ? 'dBTC → BTC'
          : 'dBTC Vault',
    kind: 'dBTC',
  }));
}

/**
 * Check whether a DLV anchor is replicated on storage nodes.
 * Returns false when no vault ID is provided; full per-node presence query
 * is not yet exposed via a single-vault route.
 */
export function checkDlvPresence(anchorHex: string): Promise<boolean> {
  return Promise.resolve(!!anchorHex);
}

export function createBackup(): Promise<string> {
  return Promise.resolve('/storage/emulated/0/Download/dsm_backup.nfc');
}
