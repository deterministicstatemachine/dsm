/* eslint-disable @typescript-eslint/no-explicit-any */
// Storage node types for management UI

export type NodeHealth = 'healthy' | 'degraded' | 'down' | 'unknown';

// Display-only numbers (UI only). Must never participate in protocol logic.
export type DisplayOnlyNumber = number & { readonly __displayOnlyBrand: unique symbol };
export const asDisplayOnlyNumber = (n: number): DisplayOnlyNumber => n as DisplayOnlyNumber;
export const displayOnlyNumberToNumber = (n: DisplayOnlyNumber): number => n as number;

export interface StorageNodeEndpoint {
  url: string;
  isPrimary: boolean;
  name?: string;       // human-readable label (e.g. "dsm-node-1")
  region?: string;     // AWS region (e.g. "us-east-1")
  tls?: {
    cert?: string;
  };
  auth?: {
    type: 'bearer' | 'basic' | 'none';
    token?: string;
    username?: string;
    password?: string;
  };
}

export interface NodeHealthMetrics {
  url: string;
  name?: string;
  region?: string;
  status: NodeHealth;
  lastPing?: DisplayOnlyNumber; // UI-only tick
  latencyMs?: DisplayOnlyNumber;
  lastError?: string;
  uptime?: DisplayOnlyNumber; // seconds (UI-only)
  version?: string;
  storageUsed?: DisplayOnlyNumber; // bytes (UI-only)
  storageTotal?: DisplayOnlyNumber; // bytes (UI-only)
  // Prometheus metrics (display-only)
  objectsPutTotal?: DisplayOnlyNumber;
  objectsGetTotal?: DisplayOnlyNumber;
  bytesWrittenTotal?: DisplayOnlyNumber;
  bytesReadTotal?: DisplayOnlyNumber;
  cleanupRunsTotal?: DisplayOnlyNumber;
  replicationFailures?: DisplayOnlyNumber;
}

/** Storage nodes config — per spec, nodes are equal mirrors. No primary, no failover. */
export interface StorageNodesConfig {
  nodes: StorageNodeEndpoint[];
  retryPolicy: {
    maxRetries: number;
    backoffMs: number;
  };
  /** Number of nodes that must successfully verify retrieval (spec K=3) */
  verificationQuorum?: number;
}

export interface ObjectMetadata {
  key: string;
  size: number;
  contentType?: string;
  lastModified?: DisplayOnlyNumber;
  nodes: string[]; // URLs where this object exists
}

export interface DiagnosticsBundle {
  tick: number;
  nodesConfig: StorageNodesConfig;
  nodeHealth: NodeHealthMetrics[];
  sdkHealthCache?: any;
  recentErrors: string[];
  mode: StorageNodeMode;
  systemInfo: {
    platform: string;
    version: string;
  };
}

export type StorageNodeMode = 'production';

export type FeatureFlag = 'dev-only' | 'production' | 'hidden';

export interface StorageFeatureFlags {
  objectBrowser: FeatureFlag;
  destructiveOps: FeatureFlag;
  policyEditor: FeatureFlag;
  evidenceViewer: FeatureFlag;
}
