/* eslint-disable @typescript-eslint/no-explicit-any */
// Centralized storage node configuration for the frontend.
// Single source of truth: `dsm_network_config.json` (checked-in bootstrap config)
//
// IMPORTANT:
// - This is UI/runtime configuration (not protocol).
// - Keep it deterministic: no wall-clock time usage.
// - Per spec: nodes are equal mirrors. No primary, no failover, no write strategy.

import type { StorageNodesConfig } from '../types/storage';

function mustGetNetJson(): any {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require('../../dsm_network_config.json');
}

/**
 * Build StorageNodesConfig from the network config.
 *
 * Uses production_nodes[] from config. If none configured,
 * returns an empty node list.
 *
 * Per spec: all nodes are equal mirrors. No primary/failover concept.
 */
export function getStorageNodesConfig(): StorageNodesConfig {
  const netJson = mustGetNetJson();
  const sc = netJson?.storage_nodes ?? netJson?.storage_cluster ?? {};

  const prodNodes: Array<{ endpoint?: string; url?: string; name?: string; region?: string }> =
    Array.isArray(sc?.production_nodes) ? sc.production_nodes : [];

  const nodes = prodNodes
    .map((n) => ({
      url: String(n?.endpoint ?? n?.url ?? ''),
      isPrimary: false, // no primaries — all nodes are equal mirrors
      name: n?.name ? String(n.name) : undefined,
      region: n?.region ? String(n.region) : undefined,
    }))
    .filter((n) => n.url.length > 0);

  return {
    nodes,
    retryPolicy: { maxRetries: 3, backoffMs: 100 },
    verificationQuorum: 1,
  };
}
