// SPDX-License-Identifier: Apache-2.0
// Pending bilateral proposal persistence (UI-only).
//
// Requirements:
// - Deterministic: no wall-clock markers.
// - Bytes-only boundary: this module only stores UI metadata + Base32 strings.
// - Bounded: cap number of pending items.

import * as pb from '../proto/dsm_app_pb';
import { encodeBase32Crockford } from '../utils/textId';
import { getPendingBilateralListStrict } from '../dsm/index';


export type PendingBilateralStatus =
  | 'pending'
  | 'verified'
  | 'hash_mismatch'
  | 'accepted'
  | 'committed'
  | 'failed'
  | 'rejected';

export type PendingBilateralDirection = 'incoming' | 'outgoing';

export interface PendingBilateralRecordV1 {
  version: 1;
  // Stable id, derived from commitment (base32) and counterparty device id (base32)
  id: string;
  commitmentHashB32: string;
  counterpartyDeviceIdB32: string;
  // Optional
  bleAddress?: string;
  amount?: string;
  tokenId?: string;
  memo?: string;
  // Optional display alias (may be resolved later)
  counterpartyAlias?: string;
  direction?: PendingBilateralDirection;
  // Status and verification hint
  status: PendingBilateralStatus;
  verificationStatus?: 'verified' | 'failed' | 'pending';
  // Monotone counter for UI ordering only.
  seq: number;
}

// In-memory cache synced exclusively from native authoritative queries.
// No local persistence, no optimistic updates.
let __nativeStateItems: PendingBilateralRecordV1[] = [];
let __nativeSeq = 1;
const listeners = new Set<() => void>();

function normalizeB32(s: unknown): string {
  const out = String(s ?? '').trim();
  return out.toUpperCase();
}

export function makePendingId(commitmentHashB32: string, counterpartyDeviceIdB32: string): string {
  return `${normalizeB32(commitmentHashB32)}:${normalizeB32(counterpartyDeviceIdB32)}`;
}

function notifyListeners() {
  listeners.forEach((l) => l());
}

export function subscribeToPendingBilateral(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

type PersistedStateV1 = {
  v: 1;
  nextSeq: number;
  items: PendingBilateralRecordV1[];
};

const MAX_ITEMS = 100;

// Internal state for tests only.
let __inMemoryStateForTests: PersistedStateV1 | null = null;

function emptyState(): PersistedStateV1 {
  return { v: 1, nextSeq: 1, items: [] };
}

export function loadPendingBilateral(): PendingBilateralRecordV1[] {
  // Production: Return the in-memory cache derived from native events.
  if (process.env.NODE_ENV !== 'test') {
      return __nativeStateItems;
  }
  // In test, if native sync is installed, return the native state
  if (window.__DSM_PENDING_BILATERAL_STORE_SYNC__) {
    return __nativeStateItems;
  }
  return (__inMemoryStateForTests ?? emptyState()).items.slice();
}

function mapStatusFromNative(args: {
  status: pb.OfflineBilateralTransactionStatus;
  phase?: string;
}): PendingBilateralStatus {
  switch (args.status) {
    case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_CONFIRMED:
      return 'committed';
    case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_FAILED:
      return 'failed';
    case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_REJECTED:
      return 'rejected';
    case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_IN_PROGRESS:
      return args.phase === 'accepted' ? 'accepted' : 'pending';
    case pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING:
      return 'pending';
    default:
      return 'pending';
  }
}

function parseSeq(value?: string): number {
  if (!value) return 0;
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

export async function refreshPendingBilateralFromNative(): Promise<void> {
  const { transactions } = await getPendingBilateralListStrict();
  const next: PendingBilateralRecordV1[] = [];

  for (const tx of transactions) {
    const metadata = tx.metadata || {};
    const phase = String(metadata.phase || '');
    const direction = (String(metadata.direction || 'incoming') as PendingBilateralDirection) || 'incoming';
    const counterpartyAlias = String(metadata.counterpartyAlias || '').trim();
    const amount = String(metadata.amount || '').trim();
    const tokenId = String(metadata.tokenId || 'ERA').trim() || 'ERA';
    const bleAddress = String(metadata.senderBleAddress || '').trim() || undefined;

    const commitmentHashB32 = encodeBase32Crockford(tx.commitmentHash || new Uint8Array());
    if (!commitmentHashB32) continue;

    const counterpartyBytes = direction === 'incoming' ? tx.senderId : tx.recipientId;
    const counterpartyDeviceIdB32 = encodeBase32Crockford(counterpartyBytes || new Uint8Array());
    if (!counterpartyDeviceIdB32) continue;

    const id = makePendingId(commitmentHashB32, counterpartyDeviceIdB32);
    const seq = parseSeq(String(metadata.createdAtStep || '')) || __nativeSeq++;

    next.push({
      version: 1,
      id,
      commitmentHashB32,
      counterpartyDeviceIdB32,
      amount: amount || '0',
      tokenId: tokenId || 'ERA',
      counterpartyAlias: counterpartyAlias || undefined,
      status: mapStatusFromNative({ status: tx.status, phase }),
      direction,
      seq,
      verificationStatus: undefined,
      bleAddress,
      memo: undefined,
    });
  }

  __nativeStateItems = next;
  notifyListeners();
}

function saveState(state: PersistedStateV1): void {
  if (process.env.NODE_ENV === 'test') {
    __inMemoryStateForTests = {
      v: 1,
      nextSeq: state.nextSeq,
      items: state.items.slice(),
    };
    return;
  }
}

function loadState(): PersistedStateV1 {
  if (process.env.NODE_ENV === 'test') {
    return __inMemoryStateForTests ?? emptyState();
  }
  return emptyState();
}

export function upsertPendingBilateral(input: Omit<PendingBilateralRecordV1, 'version' | 'id' | 'seq'> & {
  commitmentHashB32: string;
  counterpartyDeviceIdB32: string;
}): PendingBilateralRecordV1 {
  if (process.env.NODE_ENV !== 'test') {
      const { commitmentHashB32, counterpartyDeviceIdB32, ...rest } = input;
      const id = makePendingId(normalizeB32(commitmentHashB32), normalizeB32(counterpartyDeviceIdB32));
      return {
        version: 1,
        id,
        commitmentHashB32: normalizeB32(commitmentHashB32),
        counterpartyDeviceIdB32: normalizeB32(counterpartyDeviceIdB32),
        bleAddress: rest.bleAddress,
        amount: rest.amount,
        tokenId: rest.tokenId,
        memo: rest.memo,
        counterpartyAlias: rest.counterpartyAlias,
        status: rest.status,
        verificationStatus: rest.verificationStatus,
        direction: rest.direction,
        seq: 0,
      };
  }

  const state = loadState();
  const commitmentHashB32 = normalizeB32(input.commitmentHashB32);
  const counterpartyDeviceIdB32 = normalizeB32(input.counterpartyDeviceIdB32);
  const id = makePendingId(commitmentHashB32, counterpartyDeviceIdB32);

  const existing = state.items.find((x) => x.id === id);
  let rec: PendingBilateralRecordV1;
  if (existing) {
    rec = {
      ...existing,
      ...input,
      version: 1,
      id,
      commitmentHashB32,
      counterpartyDeviceIdB32,
      seq: existing.seq,
    };
    state.items = state.items.filter((x) => x.id !== id);
  } else {
    rec = {
      version: 1,
      id,
      commitmentHashB32,
      counterpartyDeviceIdB32,
      bleAddress: input.bleAddress,
      amount: input.amount,
      tokenId: input.tokenId,
      memo: input.memo,
      counterpartyAlias: input.counterpartyAlias,
      status: input.status,
      verificationStatus: input.verificationStatus,
      seq: state.nextSeq,
    };
    state.nextSeq += 1;
  }

  state.items.push(rec);

  if (state.items.length > MAX_ITEMS) {
    state.items.sort((a, b) => a.seq - b.seq);
    state.items = state.items.slice(state.items.length - MAX_ITEMS);
  }

  saveState(state);
  // Also update native state if installed
  if (process.env.NODE_ENV === 'test' && window.__DSM_PENDING_BILATERAL_STORE_SYNC__) {
    __nativeStateItems = __nativeStateItems.filter(x => x.id !== rec.id);
    __nativeStateItems.push(rec);
    notifyListeners();
  }
  return rec;
}

export function removePendingBilateralById(id: string): void {
  if (process.env.NODE_ENV !== 'test') {
       __nativeStateItems = __nativeStateItems.filter(x => x.id !== id);
       notifyListeners();
       return;
  }
  const state = loadState();
  const next = state.items.filter((x) => x.id !== id);
  if (next.length === state.items.length) return;
  state.items = next;
  saveState(state);
}

export function updatePendingBilateralStatus(id: string, status: PendingBilateralStatus): void {
  if (process.env.NODE_ENV !== 'test') return;
  const state = loadState();
  let updated = false;
  state.items = state.items.map((item) => {
    if (item.id !== id) return item;
    updated = true;
    return { ...item, status };
  });
  if (!updated) return;
  saveState(state);
}

export function clearPendingBilateral(): void {
  if (process.env.NODE_ENV === 'test') {
    __inMemoryStateForTests = emptyState();
    __nativeStateItems = [];
    __nativeSeq = 1;
    return;
  }
  // disabled
}
