jest.mock('../WebViewBridge', () => ({
  syncWithStorageStrictBridge: jest.fn(),
  routerQueryBin: jest.fn(),
  routerInvokeBin: jest.fn(),
}));

jest.mock('../events', () => ({
  emitWalletRefresh: jest.fn(),
}));

import * as pb from '../../proto/dsm_app_pb';
import {
  syncWithStorage,
  getStorageStatus,
  getNodeHealth,
  addStorageNode,
  removeStorageNode,
  createBackup,
} from '../storage';
import { syncWithStorageStrictBridge, routerQueryBin, routerInvokeBin } from '../WebViewBridge';
import { emitWalletRefresh } from '../events';

function frameEnvelope(envelope: pb.Envelope): Uint8Array {
  const bytes = envelope.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

describe('storage.ts', () => {
  beforeEach(() => jest.clearAllMocks());

  // ── syncWithStorage ────────────────────────────────────────────────

  describe('syncWithStorage', () => {
    test('returns success with sync stats', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageSyncResponse',
          value: new pb.StorageSyncResponse({
            success: true,
            pulled: 3,
            processed: 2,
            pushed: 1,
            errors: [],
          }),
        },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await syncWithStorage();
      expect(result.success).toBe(true);
      expect(result.pulled).toBe(3);
      expect(result.processed).toBe(2);
      expect(result.pushed).toBe(1);
    });

    test('emits wallet refresh when processed > 0', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageSyncResponse',
          value: new pb.StorageSyncResponse({ success: true, processed: 5, errors: [] }),
        },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await syncWithStorage();
      expect(emitWalletRefresh).toHaveBeenCalledWith({ source: 'storage.sync' });
    });

    test('does not emit wallet refresh when processed is 0', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageSyncResponse',
          value: new pb.StorageSyncResponse({ success: true, processed: 0, errors: [] }),
        },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await syncWithStorage();
      expect(emitWalletRefresh).not.toHaveBeenCalled();
    });

    test('returns failure for empty response bytes', async () => {
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(new Uint8Array(0));

      const result = await syncWithStorage();
      expect(result.success).toBe(false);
      expect(result.message).toBe('Empty response from bridge');
    });

    test('returns failure on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ code: 5, message: 'sync denied' }) },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await syncWithStorage();
      expect(result.success).toBe(false);
      expect(result.message).toMatch(/sync denied/);
    });

    test('returns failure on unexpected payload case', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await syncWithStorage();
      expect(result.success).toBe(false);
      expect(result.message).toMatch(/Unexpected response type/);
    });

    test('returns failure on decode error', async () => {
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(new Uint8Array([0xFF, 0x01]));

      const result = await syncWithStorage();
      expect(result.success).toBe(false);
      expect(result.message).toMatch(/Decode failed/);
    });

    test('returns failure when bridge throws', async () => {
      (syncWithStorageStrictBridge as jest.Mock).mockRejectedValue(new Error('network error'));

      const result = await syncWithStorage();
      expect(result.success).toBe(false);
      expect(result.message).toBe('network error');
    });

    test('merges default params', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageSyncResponse',
          value: new pb.StorageSyncResponse({ success: true, errors: [] }),
        },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      await syncWithStorage({ pullInbox: false });
      const call = (syncWithStorageStrictBridge as jest.Mock).mock.calls[0][0];
      expect(call.pullInbox).toBe(false);
      expect(call.pushPending).toBe(false);
      expect(call.limit).toBe(50);
    });

    test('includes first error in message when errors array is non-empty', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageSyncResponse',
          value: new pb.StorageSyncResponse({ success: true, processed: 0, errors: ['partial fail'] }),
        },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await syncWithStorage();
      expect(result.message).toBe('partial fail');
    });

    test('returns failure for null storageSyncResponse', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'storageSyncResponse', value: undefined as any },
      });
      (syncWithStorageStrictBridge as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await syncWithStorage();
      expect(result.success).toBe(false);
    });
  });

  // ── getStorageStatus ───────────────────────────────────────────────

  describe('getStorageStatus', () => {
    test('maps StorageStatusResponse fields', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageStatusResponse',
          value: new pb.StorageStatusResponse({
            connectedNodes: 3,
            totalNodes: 5,
            lastSyncIter: 42n,
            dataSize: '1.2GB',
            backupStatus: 'ok',
          }),
        },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getStorageStatus();
      expect(status.nodeId).toBe('storage');
      expect(status.isReachable).toBe(true);
      expect(status.lastSyncTick).toBe(42n);
      expect(status.totalNodes).toBe(5);
      expect(status.connectedNodes).toBe(3);
      expect(status.dataSize).toBe('1.2GB');
      expect(status.backupStatus).toBe('ok');
      expect(status.isPaid).toBe(true);
    });

    test('isReachable is false when connectedNodes is 0', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: {
          case: 'storageStatusResponse',
          value: new pb.StorageStatusResponse({ connectedNodes: 0 }),
        },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const status = await getStorageStatus();
      expect(status.isReachable).toBe(false);
    });

    test('throws on empty response', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(getStorageStatus()).rejects.toThrow(/empty response/);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'denied' }) },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));
      await expect(getStorageStatus()).rejects.toThrow(/denied/);
    });

    test('throws on unexpected payload', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'balancesListResponse', value: new pb.BalancesListResponse() },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));
      await expect(getStorageStatus()).rejects.toThrow(/unexpected payload/);
    });
  });

  // ── getNodeHealth ──────────────────────────────────────────────────

  describe('getNodeHealth', () => {
    test('returns storageNodeStatsResponse payload', async () => {
      const statsResp = new pb.StorageNodeStatsResponse();
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'storageNodeStatsResponse', value: statsResp },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await getNodeHealth();
      expect(result).toBeDefined();
    });

    test('throws on empty response', async () => {
      (routerQueryBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(getNodeHealth()).rejects.toThrow(/empty response/);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'health err' }) },
      });
      (routerQueryBin as jest.Mock).mockResolvedValue(frameEnvelope(env));
      await expect(getNodeHealth()).rejects.toThrow(/health err/);
    });
  });

  // ── addStorageNode / removeStorageNode ─────────────────────────────

  describe('addStorageNode', () => {
    test('returns storageNodeManageResponse payload', async () => {
      const manageResp = new pb.StorageNodeManageResponse({ success: true, assignedUrl: 'https://node1.example.com' });
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'storageNodeManageResponse', value: manageResp },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await addStorageNode();
      expect(result.success).toBe(true);
    });

    test('throws on empty response', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(addStorageNode()).rejects.toThrow(/empty response/);
    });

    test('throws on error envelope', async () => {
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'error', value: new pb.Error({ message: 'add failed' }) },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));
      await expect(addStorageNode()).rejects.toThrow(/add failed/);
    });
  });

  describe('removeStorageNode', () => {
    test('returns storageNodeManageResponse on success', async () => {
      const manageResp = new pb.StorageNodeManageResponse({ success: true });
      const env = new pb.Envelope({
        version: 3,
        payload: { case: 'storageNodeManageResponse', value: manageResp },
      });
      (routerInvokeBin as jest.Mock).mockResolvedValue(frameEnvelope(env));

      const result = await removeStorageNode('https://node1.example.com');
      expect(result.success).toBe(true);
    });

    test('throws on empty response', async () => {
      (routerInvokeBin as jest.Mock).mockResolvedValue(new Uint8Array(0));
      await expect(removeStorageNode('url')).rejects.toThrow(/empty response/);
    });
  });

  describe('createBackup', () => {
    test('rejects with not-implemented (NFC ring is the primary backup mechanism)', async () => {
      await expect(createBackup()).rejects.toThrow(/not implemented/i);
    });
  });
});
