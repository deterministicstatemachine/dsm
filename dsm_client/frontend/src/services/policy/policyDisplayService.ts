/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/policy/policyDisplayService.ts
// SPDX-License-Identifier: Apache-2.0
// Policy display helpers to keep raw bytes and proto concerns out of UI.

import { shortId, prettyAnchor } from '../../utils/anchorDisplay';

type Hash32Bytes = Uint8Array & { readonly length: 32 };
type Hash32Like =
  | { v?: Uint8Array | null; value?: Uint8Array | null }
  | Uint8Array
  | null
  | undefined;

export interface PolicyRecord {
  alias?: string;
  name?: string;
  ticker?: string;
  id?: string;
  policyId?: string;
  tokenGenesis?: string;
  policy_bytes?: Uint8Array | null;
  metadata?: {
    ticker?: string;
    alias?: string;
    decimals?: number;
    maxSupply?: string;
  };
  policy_hash?: Hash32Like;
  policyHash?: Hash32Like;
  policy_commit?: Uint8Array | null;
  policyCommit?: Uint8Array | null;
}

export interface PolicyDisplayEntry {
  label: string;
  shortId: string;
  prettyAnchor: string;
  ticker?: string;
  alias?: string;
  decimals?: number;
  maxSupply?: string;
}

function isUint8Array32(x: unknown): x is Hash32Bytes {
  return x instanceof Uint8Array && x.length === 32;
}

function resolvePolicyId(p: PolicyRecord): string {
  const alias = p.alias ?? p.name ?? p.ticker ?? p.id ?? p.policyId ?? p.tokenGenesis ?? '';
  return typeof alias === 'string' ? alias.trim() : '';
}

function extractFromHash32(h: Hash32Like): Hash32Bytes | null {
  if (!h) return null;
  if (isUint8Array32(h)) return h;
  const v = (h as { v?: unknown; value?: unknown }).v ?? (h as { value?: unknown }).value;
  return isUint8Array32(v) ? (v as Hash32Bytes) : null;
}

function extractAnchorBytes(policy: PolicyRecord): Hash32Bytes | null {
  const h1 = extractFromHash32(policy.policy_hash);
  if (h1) return h1;
  const h2 = extractFromHash32(policy.policyHash);
  if (h2) return h2;
  if (isUint8Array32(policy.policy_commit)) return policy.policy_commit as Hash32Bytes;
  if (isUint8Array32(policy.policyCommit)) return policy.policyCommit as Hash32Bytes;
  return null;
}

function coercePolicyArray(x: unknown): PolicyRecord[] {
  if (Array.isArray(x)) return x as PolicyRecord[];
  if (x && typeof x === 'object' && Array.isArray((x as { policies?: unknown }).policies)) {
    return (x as { policies: unknown[] }).policies as PolicyRecord[];
  }
  return [];
}

export function mapPoliciesToDisplayEntries(policies: unknown): PolicyDisplayEntry[] {
  const list = coercePolicyArray(policies);
  const out: PolicyDisplayEntry[] = [];
  for (const p of list) {
    const bytes = extractAnchorBytes(p);
    if (!bytes) continue;
    const meta = p.metadata;
    const id = resolvePolicyId(p);
    const label = meta?.ticker || id || shortId(bytes);
    out.push({
      label,
      shortId: shortId(bytes),
      prettyAnchor: prettyAnchor(bytes),
      ticker: meta?.ticker,
      alias: meta?.alias,
      decimals: meta?.decimals,
      maxSupply: meta?.maxSupply,
    });
  }
  return out;
}
