/// <reference types="jest" />
/* eslint-disable @typescript-eslint/no-explicit-any */
// Tests for storageNodeService

const mockGetPreference = jest.fn(async () => null);
const mockSetPreference = jest.fn(async () => {});
const mockGetNodeHealth = jest.fn();
const mockAddStorageNode = jest.fn();
const mockRemoveStorageNode = jest.fn();

jest.mock('../../dsm/WebViewBridge', () => ({
  getPreference: (...args: any[]) => mockGetPreference(...args),
  setPreference: (...args: any[]) => mockSetPreference(...args),
}));

jest.mock('../../dsm/storage', () => ({
  getNodeHealth: (...args: any[]) => mockGetNodeHealth(...args),
  addStorageNode: (...args: any[]) => mockAddStorageNode(...args),
  removeStorageNode: (...args: any[]) => mockRemoveStorageNode(...args),
}));

import { storageNodeService } from '../storageNodeService';
import type { StorageNodesConfig, NodeHealthMetrics } from '../../types/storage';
import { displayOnlyNumberToNumber } from '../../types/storage';
import { getStorageNodesConfig } from '../../config/storageReplicaSet';
const mockFetch = jest.fn();


describe('storageNodeService', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockGetNodeHealth.mockReset();
    mockAddStorageNode.mockReset();
    mockRemoveStorageNode.mockReset();
    globalThis.fetch = mockFetch as any;

    // Reset service state for each test
    (storageNodeService as any).configOverride = null;
    (storageNodeService as any).healthCache.clear();
    (storageNodeService as any).lastHealthCheck = 0;
    (storageNodeService as any).errorLog = [];
    (storageNodeService as any).errorCounter = 0;
  });

  describe('config management', () => {
    it('should return default config when none stored', () => {
      const config = storageNodeService.getNodesConfig();
      expect(config.nodes).toHaveLength(getStorageNodesConfig().nodes.length);
      expect(config.retryPolicy.maxRetries).toBe(3);
    });

    it('setNodesConfig persists protobuf config under the canonical nodes key', async () => {
      const customConfig: StorageNodesConfig = {
        nodes: [
          { url: 'http://node1:8080', isPrimary: false, name: 'node-1', region: 'us-east-1' },
          { url: 'http://node2:8081', isPrimary: false },
        ],
        retryPolicy: { maxRetries: 5, backoffMs: 200 },
        verificationQuorum: 2,
      };

      storageNodeService.setNodesConfig(customConfig);
      const cfg = storageNodeService.getNodesConfig();
      expect(cfg.nodes).toHaveLength(2);
      expect(cfg.retryPolicy.maxRetries).toBe(5);
      expect(cfg.verificationQuorum).toBe(2);
      expect(cfg.nodes[0].name).toBe('node-1');
      expect(cfg.nodes[0].region).toBe('us-east-1');
      await Promise.resolve();
      expect(mockSetPreference).toHaveBeenCalledWith('storage.nodes.config.v1', expect.any(String));
    });

    it('exportConfig returns base32 protobuf payload', () => {
      const out = storageNodeService.exportConfig();
      expect(typeof out).toBe('string');
      expect(out.length).toBeGreaterThan(0);
    });

    it('selectNodesForAddr returns deterministic k nodes', () => {
      const a = storageNodeService.selectNodesForAddr('ADDR1', 3);
      const b = storageNodeService.selectNodesForAddr('ADDR1', 3);
      expect(a).toEqual(b);
      expect(a.length).toBe(3);
      // Different addr should produce different ordering in general
      const c = storageNodeService.selectNodesForAddr('ADDR2', 3);
      const d = storageNodeService.selectNodesForAddr('ADDR2', 3);
      expect(c).toEqual(d);
    });

    it('importConfig accepts base32 protobuf payload', () => {
      const payload = storageNodeService.exportConfig();
      const result = storageNodeService.importConfig(payload);
      expect(result.success).toBe(true);
    });

    it('round-trips node metadata through export/import', () => {
      storageNodeService.setNodesConfig({
        nodes: [
          { url: 'https://node-a.example', isPrimary: false, name: 'node-a', region: 'eu-west-1' },
        ],
        retryPolicy: { maxRetries: 4, backoffMs: 150 },
        verificationQuorum: 1,
      });

      const encoded = storageNodeService.exportConfig();
      (storageNodeService as any).configOverride = null;
      const imported = storageNodeService.importConfig(encoded);
      const cfg = storageNodeService.getNodesConfig();

      expect(imported.success).toBe(true);
      expect(cfg.nodes[0].name).toBe('node-a');
      expect(cfg.nodes[0].region).toBe('eu-west-1');
    });
  });

  describe('node health checks', () => {
    it('should check single node health (healthy)', async () => {
      mockGetNodeHealth.mockResolvedValueOnce({
        nodes: [{
          url: 'http://localhost:8080',
          status: 'healthy',
          latencyMs: 12,
          lastError: '',
          objectsPutTotal: 0n,
          objectsGetTotal: 0n,
          bytesWrittenTotal: 0n,
          bytesReadTotal: 0n,
          cleanupRunsTotal: 0n,
          replicationFailures: 0n,
        }],
      });

      const health = await storageNodeService.checkNodeHealth('http://localhost:8080');

      expect(health.url).toBe('http://localhost:8080');
      expect(health.status).toBe('healthy');
      expect(displayOnlyNumberToNumber(health.latencyMs!)).toBe(12);
    });

    it('should detect degraded node (non-200 response)', async () => {
      mockGetNodeHealth.mockResolvedValueOnce({
        nodes: [{
          url: 'http://localhost:8080',
          status: 'degraded',
          latencyMs: 0,
          lastError: '503 Service Unavailable',
          objectsPutTotal: 0n,
          objectsGetTotal: 0n,
          bytesWrittenTotal: 0n,
          bytesReadTotal: 0n,
          cleanupRunsTotal: 0n,
          replicationFailures: 0n,
        }],
      });

      const health = await storageNodeService.checkNodeHealth('http://localhost:8080');

      expect(health.status).toBe('degraded');
      expect(health.lastError).toContain('503');
    });

    it('should detect down node (fetch error)', async () => {
      mockGetNodeHealth.mockRejectedValueOnce(new Error('Connection refused'));

      const health = await storageNodeService.checkNodeHealth('http://localhost:8080');

      expect(health.status).toBe('down');
      expect(health.lastError).toContain('Connection refused');
    });

    it('should check all nodes in parallel', async () => {
      const config = storageNodeService.getNodesConfig();
      mockGetNodeHealth.mockResolvedValueOnce({
        nodes: config.nodes.map((node, index) => ({
          url: node.url,
          status: index === 0 ? 'healthy' : index === 1 ? 'degraded' : 'down',
          latencyMs: index === 0 ? 7 : 0,
          lastError: index === 1 ? '503 Service Unavailable' : index >= 2 ? 'timeout' : '',
          name: (node as any).name || '',
          region: (node as any).region || '',
          objectsPutTotal: 0n,
          objectsGetTotal: 0n,
          bytesWrittenTotal: 0n,
          bytesReadTotal: 0n,
          cleanupRunsTotal: 0n,
          replicationFailures: 0n,
        })),
      });

      const results = await storageNodeService.checkAllNodesHealth();

      expect(results).toHaveLength(config.nodes.length);
      expect(results[0].status).toBe('healthy');
      expect(results[1].status).toBe('degraded');
      expect(results[2].status).toBe('down');
    });

    it('should cache health results', async () => {
      const config = storageNodeService.getNodesConfig();
      mockGetNodeHealth.mockResolvedValue({
        nodes: config.nodes.map((node) => ({
          url: node.url,
          status: 'healthy',
          latencyMs: 5,
          lastError: '',
          name: (node as any).name || '',
          region: (node as any).region || '',
          objectsPutTotal: 0n,
          objectsGetTotal: 0n,
          bytesWrittenTotal: 0n,
          bytesReadTotal: 0n,
          cleanupRunsTotal: 0n,
          replicationFailures: 0n,
        })),
      });

      await storageNodeService.checkAllNodesHealth();
      const cached = storageNodeService.getCachedHealth();

      expect(cached).toHaveLength(config.nodes.length);
      expect(cached.every((h) => typeof h.lastPing === 'number' && displayOnlyNumberToNumber(h.lastPing!) === 0)).toBe(true);
    });

    it('keeps configured ordering when bridge returns nodes out of order', async () => {
      storageNodeService.setNodesConfig({
        nodes: [
          { url: 'http://node-a:8080', isPrimary: false, name: 'A' },
          { url: 'http://node-b:8080', isPrimary: false, name: 'B' },
        ],
        retryPolicy: { maxRetries: 3, backoffMs: 100 },
        verificationQuorum: 1,
      });

      mockGetNodeHealth.mockResolvedValueOnce({
        nodes: [
          { url: 'http://node-b:8080', status: 'healthy', latencyMs: 9, lastError: '', objectsPutTotal: 0n, objectsGetTotal: 0n, bytesWrittenTotal: 0n, bytesReadTotal: 0n, cleanupRunsTotal: 0n, replicationFailures: 0n },
          { url: 'http://node-a:8080', status: 'degraded', latencyMs: 3, lastError: 'slow', objectsPutTotal: 0n, objectsGetTotal: 0n, bytesWrittenTotal: 0n, bytesReadTotal: 0n, cleanupRunsTotal: 0n, replicationFailures: 0n },
        ],
      });

      const results = await storageNodeService.checkAllNodesHealth();

      expect(results.map((r) => r.url)).toEqual(['http://node-a:8080', 'http://node-b:8080']);
      expect(results[0].name).toBe('A');
      expect(results[1].name).toBe('B');
    });
  });

  describe('node management', () => {
    it('updates local config after add node succeeds', async () => {
      storageNodeService.setNodesConfig({
        nodes: [{ url: 'http://node1:8080', isPrimary: false }],
        retryPolicy: { maxRetries: 3, backoffMs: 100 },
        verificationQuorum: 1,
      });
      mockAddStorageNode.mockResolvedValueOnce({
        success: true,
        error: '',
        assignedUrl: 'http://node2:8080',
        currentEndpoints: ['http://node1:8080', 'http://node2:8080'],
      });

      const result = await storageNodeService.addNode();
      const cfg = storageNodeService.getNodesConfig();

      expect(result.success).toBe(true);
      expect(result.assignedUrl).toBe('http://node2:8080');
      expect(cfg.nodes).toHaveLength(2);
      expect(cfg.nodes[1].url).toBe('http://node2:8080');
    });

    it('updates local config after remove node succeeds', async () => {
      storageNodeService.setNodesConfig({
        nodes: [
          { url: 'http://node1:8080', isPrimary: false, name: 'node-1' },
          { url: 'http://node2:8080', isPrimary: false, name: 'node-2' },
        ],
        retryPolicy: { maxRetries: 3, backoffMs: 100 },
        verificationQuorum: 1,
      });
      mockRemoveStorageNode.mockResolvedValueOnce({
        success: true,
        error: '',
        currentEndpoints: ['http://node2:8080'],
      });

      const result = await storageNodeService.removeNode('http://node1:8080');
      const cfg = storageNodeService.getNodesConfig();

      expect(result.success).toBe(true);
      expect(cfg.nodes).toHaveLength(1);
      expect(cfg.nodes[0].url).toBe('http://node2:8080');
      expect(cfg.nodes[0].name).toBe('node-2');
    });
  });

  describe('object operations', () => {
    it('should get object from first available node', async () => {
      const mockData = new Uint8Array([1, 2, 3, 4]);
      mockFetch.mockResolvedValueOnce({
        ok: true,
        arrayBuffer: async () => mockData.buffer,
        headers: { get: (k: string) => (k === 'Content-Type' ? 'application/octet-stream' : null) },
      });

      const result = await storageNodeService.getObject('test/key');

      expect(result).not.toBeNull();
      expect(result!.data).toEqual(mockData);
      expect(result!.contentType).toBe('application/octet-stream');
    });

    it('should return null for missing object', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

      const result = await storageNodeService.getObject('missing/key');

      expect(result).toBeNull();
    });

  });

  describe('diagnostics', () => {
    it('should collect full diagnostics bundle', async () => {
      const config = storageNodeService.getNodesConfig();
      mockGetNodeHealth.mockResolvedValue({
        nodes: config.nodes.map((node) => ({
          url: node.url,
          status: 'healthy',
          latencyMs: 9,
          lastError: '',
          name: (node as any).name || '',
          region: (node as any).region || '',
          objectsPutTotal: 0n,
          objectsGetTotal: 0n,
          bytesWrittenTotal: 0n,
          bytesReadTotal: 0n,
          cleanupRunsTotal: 0n,
          replicationFailures: 0n,
        })),
      });

      const bundle = await storageNodeService.collectDiagnostics();

      expect(bundle.tick).toBe(0);
      expect(bundle.nodesConfig).toBeDefined();
      expect(bundle.nodeHealth).toHaveLength(config.nodes.length);
      expect(bundle.systemInfo.platform).toBeDefined();
    });

    it('exportDiagnostics returns protobuf data', async () => {
      const config = storageNodeService.getNodesConfig();
      mockGetNodeHealth.mockResolvedValue({
        nodes: config.nodes.map((node) => ({
          url: node.url,
          status: 'healthy',
          latencyMs: 9,
          lastError: '',
          name: (node as any).name || '',
          region: (node as any).region || '',
          objectsPutTotal: 0n,
          objectsGetTotal: 0n,
          bytesWrittenTotal: 0n,
          bytesReadTotal: 0n,
          cleanupRunsTotal: 0n,
          replicationFailures: 0n,
        })),
      });
      const bundle = await storageNodeService.collectDiagnostics();
      const result = storageNodeService.exportDiagnostics(bundle);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBeGreaterThan(0);

      const decoded = (require('../../proto/dsm_app_pb') as typeof import('../../proto/dsm_app_pb')).DiagnosticsExport.fromBinary(result);
      expect(decoded.nodeHealth.length).toBe(config.nodes.length);
    });
  });
});
