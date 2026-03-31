/* eslint-disable @typescript-eslint/no-explicit-any */
// Storage node service: node health, object operations, deterministic placement
// Per spec: nodes are index-only mirrors. No primaries, no failover.

import * as pb from '../proto/dsm_app_pb';
import type {
  StorageNodeEndpoint,
  NodeHealthMetrics,
  StorageNodesConfig,
  ObjectMetadata,
  DiagnosticsBundle,
} from '../types/storage';
import { asDisplayOnlyNumber } from '../types/storage';
import { decodeBase32Crockford, encodeBase32Crockford } from '../utils/textId';
import { getPreference, setPreference } from '../dsm/WebViewBridge';
import {
  StorageReplicaSetConfig,
  StorageNodeEndpointProto,
  StorageNodeAuthProto,
  StorageNodeAuthType,
} from '../proto/dsm_app_pb';

import { getStorageNodesConfig } from '../config/storageReplicaSet';
import { getNodeHealth, addStorageNode, removeStorageNode } from '../dsm/storage';

const DEFAULT_NODES_CONFIG: StorageNodesConfig = getStorageNodesConfig();

const NODES_CONFIG_PREF_KEY = 'storage.nodes.config.v1';

class StorageNodeService {
  private healthCache: Map<string, NodeHealthMetrics> = new Map();
  private lastHealthCheck: number = 0;
  private errorLog: string[] = [];
  private errorCounter: number = 0;
  private readonly MAX_ERRORS = 100;
  private configOverride: StorageNodesConfig | null = null;
  private configLoadInFlight: Promise<void> | null = null;

  // ========== Error logging ==========

  private logError(operation: string, error: string, context?: string): void {
    const unix_ts = this.errorCounter++;
    const logEntry = `[${unix_ts}] ${operation}: ${error}${context ? ` (${context})` : ''}`;
    this.errorLog.push(logEntry);
    if (this.errorLog.length > this.MAX_ERRORS) {
      this.errorLog = this.errorLog.slice(-this.MAX_ERRORS);
    }
  }

  // ========== Config persistence ==========

  getNodesConfig(): StorageNodesConfig {
    return this.configOverride ?? DEFAULT_NODES_CONFIG;
  }

  setNodesConfig(config: StorageNodesConfig): void {
    const normalized = this.normalizeConfig(config);
    this.configOverride = normalized;
    void this.persistConfig(normalized);
  }

  exportConfig(): string {
    const cfg = this.getNodesConfig();
    const bytes = this.encodeConfig(cfg);
    return encodeBase32Crockford(bytes);
  }

  importConfig(encoded: string): { success: boolean; error?: string } {
    try {
      const bytes = decodeBase32Crockford(String(encoded || '').trim());
      if (!bytes || bytes.length === 0) {
        return { success: false, error: 'StorageNodeService.importConfig: empty payload' };
      }
      const cfg = this.decodeConfig(bytes);
      const normalized = this.normalizeConfig(cfg);
      this.configOverride = normalized;
      void this.persistConfig(normalized);
      return { success: true };
    } catch (e: any) {
      return { success: false, error: e?.message || 'StorageNodeService.importConfig: decode failed' };
    }
  }

  private normalizeConfig(config: StorageNodesConfig): StorageNodesConfig {
    const nodes = Array.isArray(config.nodes) ? config.nodes.filter((n) => n && n.url) : [];
    return {
      nodes: nodes.map((n) => ({ ...n, isPrimary: false })), // all nodes are equal mirrors
      retryPolicy: {
        maxRetries: Number(config.retryPolicy?.maxRetries ?? DEFAULT_NODES_CONFIG.retryPolicy.maxRetries),
        backoffMs: Number(config.retryPolicy?.backoffMs ?? DEFAULT_NODES_CONFIG.retryPolicy.backoffMs),
      },
      verificationQuorum: Number(config.verificationQuorum ?? DEFAULT_NODES_CONFIG.verificationQuorum ?? 1),
    };
  }

  private encodeConfig(config: StorageNodesConfig): Uint8Array {
    const nodes = (config.nodes || []).map((n) => {
      const auth = n.auth
        ? new StorageNodeAuthProto({
            type:
              n.auth.type === 'bearer'
                ? StorageNodeAuthType.STORAGE_NODE_AUTH_BEARER
                : n.auth.type === 'basic'
                  ? StorageNodeAuthType.STORAGE_NODE_AUTH_BASIC
                  : StorageNodeAuthType.STORAGE_NODE_AUTH_NONE,
            token: n.auth.token || '',
            username: n.auth.username || '',
            password: n.auth.password || '',
          })
        : undefined;

      return new StorageNodeEndpointProto({
        url: n.url,
        isPrimary: false,
        name: n.name || '',
        region: n.region || '',
        auth,
        tlsCert: n.tls?.cert || '',
      });
    });

    // Reuse the existing proto message shape; unused fields remain at defaults.
    const proto = new StorageReplicaSetConfig({
      nodes,
      primaryNode: '',
      readFailoverEnabled: false,
      writeStrategy: '',
      retryMax: Number(config.retryPolicy?.maxRetries ?? 3),
      retryBackoffMs: Number(config.retryPolicy?.backoffMs ?? 100),
      verificationQuorum: Number(config.verificationQuorum ?? 1),
    });

    return proto.toBinary();
  }

  private decodeConfig(bytes: Uint8Array): StorageNodesConfig {
    const proto = StorageReplicaSetConfig.fromBinary(bytes);
    const nodes: StorageNodeEndpoint[] = (proto.nodes || []).map((n) => {
      const authType = n.auth?.type ?? StorageNodeAuthType.STORAGE_NODE_AUTH_UNSPECIFIED;
      const auth = n.auth
        ? {
            type:
              authType === StorageNodeAuthType.STORAGE_NODE_AUTH_BEARER
                ? 'bearer'
                : authType === StorageNodeAuthType.STORAGE_NODE_AUTH_BASIC
                  ? 'basic'
                  : 'none',
            token: n.auth?.token || undefined,
            username: n.auth?.username || undefined,
            password: n.auth?.password || undefined,
          }
        : undefined;

      const tls = n.tlsCert ? { cert: n.tlsCert || undefined } : undefined;

      return {
        url: n.url,
        isPrimary: false, // all nodes are equal
        name: n.name || undefined,
        region: n.region || undefined,
        auth,
        tls,
      } as StorageNodeEndpoint;
    });

    return {
      nodes,
      retryPolicy: {
        maxRetries: Number(proto.retryMax || 3),
        backoffMs: Number(proto.retryBackoffMs || 100),
      },
      verificationQuorum: Number(proto.verificationQuorum || 1),
    };
  }

  private async persistConfig(config: StorageNodesConfig): Promise<void> {
    try {
      const bytes = this.encodeConfig(config);
      const payload = encodeBase32Crockford(bytes);
      await setPreference(NODES_CONFIG_PREF_KEY, payload);
    } catch (e) {
      console.warn('[StorageNodeService] Failed to persist config:', e);
    }
  }

  private async loadPersistedConfig(): Promise<void> {
    if (this.configLoadInFlight) return this.configLoadInFlight;
    this.configLoadInFlight = (async () => {
      try {
        const raw = await getPreference(NODES_CONFIG_PREF_KEY);
        if (!raw) return;
        const bytes = decodeBase32Crockford(raw);
        if (!bytes || bytes.length === 0) return;
        const cfg = this.decodeConfig(bytes);
        this.configOverride = this.normalizeConfig(cfg);
      } catch (e) {
        console.warn('[StorageNodeService] Failed to load persisted config:', e);
      }
    })().finally(() => {
      this.configLoadInFlight = null;
    });
    return this.configLoadInFlight;
  }

  // ========== Node health (routed through SDK bridge) ==========

  async checkNodeHealth(url: string): Promise<NodeHealthMetrics> {
    try {
      const resp = await getNodeHealth([url]);
      const node = resp.nodes.find(n => n.url === url);
      if (!node) {
        return { url, status: 'down', lastPing: asDisplayOnlyNumber(0), lastError: 'Not in response' };
      }
      return this.statsToMetrics(node);
    } catch (e: any) {
      const errorMsg = e?.message ?? 'unknown error';
      this.logError('checkNodeHealth', errorMsg, url);
      return { url, status: 'down', lastPing: asDisplayOnlyNumber(0), lastError: errorMsg };
    }
  }

  async checkAllNodesHealth(): Promise<NodeHealthMetrics[]> {
    try {
      // Pass configured endpoints so the Rust side probes exactly these URLs.
      // Without this, the SDK falls back to its internal registry which may
      // have different endpoints, causing URL mismatch in orderHealthMetrics.
      const config = this.getNodesConfig();
      const urls = config.nodes.map(n => n.url);
      const resp = await getNodeHealth(urls.length > 0 ? urls : undefined);
      const healthMetrics = this.orderHealthMetrics(resp.nodes ?? []);
      healthMetrics.forEach(m => this.healthCache.set(m.url, m));
      this.lastHealthCheck = 0;
      return healthMetrics;
    } catch (e: any) {
      this.logError('checkAllNodesHealth', e?.message ?? 'Bridge call failed');
      const config = this.getNodesConfig();
      return config.nodes.map(n => ({
        url: n.url,
        status: 'down' as const,
        lastPing: asDisplayOnlyNumber(0),
        lastError: e?.message ?? 'Bridge call failed',
      }));
    }
  }

  private orderHealthMetrics(nodes: pb.StorageNodeStats[]): NodeHealthMetrics[] {
    const statsByUrl = new Map(nodes.map((node) => [node.url, node]));
    const configured = this.getNodesConfig().nodes;

    const ordered = configured.map((cfgNode) => {
      const stats = statsByUrl.get(cfgNode.url);
      if (stats) {
        return this.statsToMetrics(stats, cfgNode);
      }
      return {
        url: cfgNode.url,
        name: cfgNode.name,
        region: cfgNode.region,
        status: 'down' as const,
        lastPing: asDisplayOnlyNumber(0),
        lastError: 'Not in response',
      };
    });

    const extras = nodes
      .filter((node) => !configured.some((cfgNode) => cfgNode.url === node.url))
      .map((node) => this.statsToMetrics(node));

    return [...ordered, ...extras];
  }

  private statsToMetrics(node: pb.StorageNodeStats, configuredNode?: StorageNodeEndpoint): NodeHealthMetrics {
    return {
      url: node.url,
      name: node.name || configuredNode?.name || undefined,
      region: node.region || configuredNode?.region || undefined,
      status: (node.status as 'healthy' | 'degraded' | 'down') || 'down',
      lastPing: asDisplayOnlyNumber(0),
      latencyMs: asDisplayOnlyNumber(Number(node.latencyMs ?? 0)),
      lastError: node.lastError || undefined,
      objectsPutTotal: asDisplayOnlyNumber(Number(node.objectsPutTotal ?? 0)),
      objectsGetTotal: asDisplayOnlyNumber(Number(node.objectsGetTotal ?? 0)),
      bytesWrittenTotal: asDisplayOnlyNumber(Number(node.bytesWrittenTotal ?? 0)),
      bytesReadTotal: asDisplayOnlyNumber(Number(node.bytesReadTotal ?? 0)),
      cleanupRunsTotal: asDisplayOnlyNumber(Number(node.cleanupRunsTotal ?? 0)),
      replicationFailures: asDisplayOnlyNumber(Number(node.replicationFailures ?? 0)),
    };
  }

  private reconcileCurrentEndpoints(currentEndpoints: string[], additions?: Record<string, Pick<StorageNodeEndpoint, 'name' | 'region'>>): void {
    const existing = new Map(this.getNodesConfig().nodes.map((node) => [node.url, node]));
    const normalizedEndpoints = currentEndpoints.filter((url) => typeof url === 'string' && url.length > 0);
    const nextNodes = normalizedEndpoints.map((url) => {
      const current = existing.get(url);
      const added = additions?.[url];
      return {
        url,
        isPrimary: false,
        name: current?.name ?? added?.name,
        region: current?.region ?? added?.region,
        tls: current?.tls,
        auth: current?.auth,
      } as StorageNodeEndpoint;
    });

    const nextConfig = this.normalizeConfig({
      ...this.getNodesConfig(),
      nodes: nextNodes,
    });
    this.configOverride = nextConfig;
    void this.persistConfig(nextConfig);
  }

  // ========== Node management (add/remove via SDK bridge) ==========

  async addNode(): Promise<{ success: boolean; error?: string; assignedUrl?: string; currentEndpoints: string[] }> {
    try {
      const resp = await addStorageNode();
      if (resp.success && resp.assignedUrl) {
        this.reconcileCurrentEndpoints(resp.currentEndpoints, {
          [resp.assignedUrl]: {},
        });
      }
      return {
        success: resp.success,
        error: resp.error || undefined,
        assignedUrl: resp.assignedUrl || undefined,
        currentEndpoints: resp.currentEndpoints,
      };
    } catch (e: any) {
      return { success: false, error: e?.message ?? 'Bridge call failed', currentEndpoints: [] };
    }
  }

  async removeNode(url: string): Promise<{ success: boolean; error?: string; currentEndpoints: string[] }> {
    try {
      const resp = await removeStorageNode(url);
      if (resp.success) {
        this.reconcileCurrentEndpoints(resp.currentEndpoints);
        this.healthCache.delete(url);
      }
      return { success: resp.success, error: resp.error || undefined, currentEndpoints: resp.currentEndpoints };
    } catch (e: any) {
      return { success: false, error: e?.message ?? 'Bridge call failed', currentEndpoints: [] };
    }
  }

  getCachedHealth(): NodeHealthMetrics[] {
    return Array.from(this.healthCache.values());
  }

  // ========== Object browser ==========

  async listObjects(nodeUrl: string, prefix?: string): Promise<ObjectMetadata[]> {
    try {
      const url = new URL(`${nodeUrl.replace(/\/$/, '')}/api/v2/object/list`);
      if (prefix) url.searchParams.set('prefix', prefix);
      url.searchParams.set('limit', '200');
      const resp = await fetch(url.toString(), {
        method: 'GET',
        headers: this.buildHeaders({ url: nodeUrl, isPrimary: false }),
      });
      if (!resp.ok) {
        return [];
      }
      const bytes = new Uint8Array(await resp.arrayBuffer());
      const decoded = pb.ObjectListResponseV1.fromBinary(bytes);
      return decoded.items.map((item) => ({
        key: item.key,
        size: Number(item.sizeBytes ?? 0),
        nodes: [nodeUrl],
      }));
    } catch {
      return [];
    }
  }

  async getObject(key: string): Promise<{ data: Uint8Array; contentType?: string } | null> {
    const config = this.getNodesConfig();
    const node = config.nodes[0]; // use first available node
    if (!node) return null;

    const controller = new AbortController();
    try {
      const resp = await fetch(`${node.url}/api/v2/object/get/${encodeURIComponent(key)}`, {
        method: 'GET',
        headers: this.buildHeaders(node),
        signal: controller.signal,
      });
      if (!resp.ok) return null;

      const arrayBuffer = await resp.arrayBuffer();
      if (!arrayBuffer) {
        this.logError('getObject', 'Empty response buffer', key);
        return null;
      }

      const data = new Uint8Array(arrayBuffer);
      const contentType = resp.headers.get('Content-Type') ?? undefined;
      return { data, contentType };
    } catch (e: any) {
      const errorMsg = e?.message ?? 'unknown error';
      this.logError('getObject', errorMsg, key);
      return null;
    }
  }

  private buildHeaders(node: StorageNodeEndpoint): Record<string, string> {
    const headers: Record<string, string> = {};
    if (node.auth) {
      if (node.auth.type === 'bearer' && node.auth.token) {
        headers['Authorization'] = `Bearer ${node.auth.token}`;
      } else if (node.auth.type === 'basic' && node.auth.username && node.auth.password) {
        const b64 = btoa(`${node.auth.username}:${node.auth.password}`);
        headers['Authorization'] = `Basic ${b64}`;
      }
    }
    return headers;
  }

  // ========== Diagnostics ==========

  async collectDiagnostics(): Promise<DiagnosticsBundle> {
    const health = await this.checkAllNodesHealth();
    const config = this.getNodesConfig();
    return {
      tick: 0,
      nodesConfig: config,
      nodeHealth: health,
      recentErrors: this.errorLog.slice(),
      mode: 'production',
      systemInfo: {
        platform: navigator.platform,
        version: navigator.userAgent,
      },
    };
  }

  exportDiagnostics(bundle: DiagnosticsBundle): Uint8Array {
    const config = bundle.nodesConfig;

    const protoConfig = new pb.StorageReplicaSetConfig({
      nodes: config.nodes.map(node => new pb.StorageNodeEndpointProto({
        url: node.url,
        isPrimary: false,
        name: node.name || '',
        region: node.region || '',
        auth: node.auth ? new pb.StorageNodeAuthProto({
          type: node.auth.type === 'bearer'
            ? pb.StorageNodeAuthType.STORAGE_NODE_AUTH_BEARER
            : node.auth.type === 'basic'
              ? pb.StorageNodeAuthType.STORAGE_NODE_AUTH_BASIC
              : pb.StorageNodeAuthType.STORAGE_NODE_AUTH_NONE,
          token: node.auth.token || '',
          username: node.auth.username || '',
          password: node.auth.password || '',
        }) : undefined,
        tlsCert: node.tls?.cert || '',
      })),
      primaryNode: '',
      readFailoverEnabled: false,
      writeStrategy: '',
      retryMax: config.retryPolicy?.maxRetries || 3,
      retryBackoffMs: config.retryPolicy?.backoffMs || 100,
      verificationQuorum: config.verificationQuorum || 1,
    });

    const nodeHealth = bundle.nodeHealth.map(h => new pb.NodeHealthEntry({
      url: h.url,
      status: h.status,
      lastError: h.lastError || '',
      name: h.name || '',
      region: h.region || '',
      latencyMs: displayOnlyNumberToNumberOrZero(h.latencyMs),
      objectsPutTotal: BigInt(displayOnlyNumberToNumberOrZero(h.objectsPutTotal)),
      objectsGetTotal: BigInt(displayOnlyNumberToNumberOrZero(h.objectsGetTotal)),
      bytesWrittenTotal: BigInt(displayOnlyNumberToNumberOrZero(h.bytesWrittenTotal)),
      bytesReadTotal: BigInt(displayOnlyNumberToNumberOrZero(h.bytesReadTotal)),
    }));

    const exportProto = new pb.DiagnosticsExport({
      replicaSetConfig: protoConfig,
      nodeHealth,
      recentErrors: bundle.recentErrors,
      mode: bundle.mode,
      platform: bundle.systemInfo.platform,
      version: bundle.systemInfo.version,
    });

    return exportProto.toBinary();
  }

  // ========== Initialization ==========

  private _initialized = false;

  async init(): Promise<void> {
    if (this._initialized) {
      if (this.configLoadInFlight) {
        await this.configLoadInFlight;
      }
      return;
    }
    this._initialized = true;
    await this.loadPersistedConfig();
  }

  // ========== Deterministic node selection (Fisher-Yates via seeded PRNG, spec §5) ==========

  private seedFromAddr(addr: string): number {
    let h = 5381;
    for (let i = 0; i < addr.length; i++) {
      h = ((h << 5) + h) ^ addr.charCodeAt(i);
      h = h >>> 0;
    }
    return h >>> 0;
  }

  private mulberry32(seed: number): () => number {
    return function () {
      let t = seed += 0x6D2B79F5;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  deterministicShuffle<T>(items: T[], seedStr: string): T[] {
    const out = items.slice();
    const seed = this.seedFromAddr(seedStr);
    const rand = this.mulberry32(seed);
    for (let i = out.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      const tmp = out[i];
      out[i] = out[j];
      out[j] = tmp;
    }
    return out;
  }

  selectNodesForAddr(addr: string, k: number): string[] {
    const cfg = this.getNodesConfig();
    const urls = cfg.nodes.map(n => n.url);
    const shuffled = this.deterministicShuffle(urls, addr);
    return shuffled.slice(0, Math.max(0, Math.min(k, shuffled.length)));
  }
}

export const storageNodeService = new StorageNodeService();

function displayOnlyNumberToNumberOrZero(value?: number): number {
  return typeof value === 'number' ? value : 0;
}
