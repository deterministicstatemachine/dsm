// SPDX-License-Identifier: Apache-2.0
// The recovery pipeline's routes (tombstone, succession, propagate, acknowledgements,
// resume, activation, dBTC reconciliation), as RecoveryPipelineScreen drives them. The SDK
// answers each with an AppStateResponse whose value is `key=value` pairs; a missing key is
// the SDK's fault and is reported, never filled in.

import { routerInvokeBin, routerQueryBin } from '../../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';

export type PipelineResult = {
  phase: string;
  tombstoneHash: string;
  pushed: number;
  failed: number;
  total: number;
};

export type AckStatus = SyncProgress & {
  newAcks: number;
};

export type SyncProgress = {
  synced: number;
  total: number;
  pending: string[];
};

export type ResumeResult = {
  resumed: number;
};

function extractAppStateValue(resBytes: Uint8Array): string {
  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    const msg = env.payload.value.message || `Error code ${env.payload.value.code}`;
    throw new Error(msg);
  }
  if (env.payload.case !== 'appStateResponse') {
    throw new Error(`Unexpected payload: ${env.payload.case}`);
  }
  const value = env.payload.value.value;
  if (value === undefined) {
    throw new Error('the SDK answered with an AppStateResponse that carries no value');
  }
  return value;
}

/**
 * `key=value` pairs separated by commas. A value may itself hold commas (the SDK joins the
 * pending counterparty ids with them), so a part without `=` continues the value before it.
 */
function parseKeyValuePairs(value: string): Map<string, string> {
  const pairs = new Map<string, string>();
  let last: string | undefined;
  for (const part of value.split(',')) {
    const idx = part.indexOf('=');
    if (idx <= 0) {
      if (last !== undefined) pairs.set(last, `${pairs.get(last)},${part.trim()}`);
      continue;
    }
    last = part.slice(0, idx).trim();
    pairs.set(last, part.slice(idx + 1).trim());
  }
  return pairs;
}

function field(pairs: Map<string, string>, route: string, key: string): string {
  const value = pairs.get(key);
  if (value === undefined) {
    throw new Error(`${route}: the SDK's answer has no ${key}`);
  }
  return value;
}

function count(pairs: Map<string, string>, route: string, key: string): number {
  const text = field(pairs, route, key);
  const n = Number.parseInt(text, 10);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error(`${route}: ${key} is not a count: ${text}`);
  }
  return n;
}

export async function getRecoveryPhase(): Promise<string> {
  const res = await routerQueryBin('recovery.phase');
  return extractAppStateValue(res) || 'none';
}

export async function executePipeline(): Promise<PipelineResult> {
  const route = 'recovery.executePipeline';
  const pairs = parseKeyValuePairs(extractAppStateValue(await routerInvokeBin(route, new Uint8Array(0))));
  return {
    phase: field(pairs, route, 'phase'),
    tombstoneHash: field(pairs, route, 'tombstone_hash'),
    pushed: count(pairs, route, 'pushed'),
    failed: count(pairs, route, 'failed'),
    total: count(pairs, route, 'total'),
  };
}

export async function getSyncProgress(): Promise<SyncProgress> {
  const route = 'recovery.syncStatus';
  const pairs = parseKeyValuePairs(extractAppStateValue(await routerQueryBin(route)));
  const pending = field(pairs, route, 'pending');
  return {
    synced: count(pairs, route, 'synced'),
    total: count(pairs, route, 'total'),
    pending: pending === '' ? [] : pending.split(','),
  };
}

/**
 * One poll of the counterparties' tombstone acknowledgements: the SDK checks each pending
 * counterparty's posted acknowledgement and marks the ones it finds. When none was pending
 * it answers without a count of new ones, having checked nothing. The progress that results
 * is then read back; every counterparty has acknowledged when nothing is pending.
 */
export async function pollAcks(): Promise<AckStatus> {
  const route = 'recovery.pollAcks';
  const pairs = parseKeyValuePairs(extractAppStateValue(await routerInvokeBin(route, new Uint8Array(0))));
  const newAcks = pairs.has('new_acks') ? count(pairs, route, 'new_acks') : 0;
  return { newAcks, ...(await getSyncProgress()) };
}

export async function resumeAll(): Promise<ResumeResult> {
  const route = 'recovery.resumeAll';
  const pairs = parseKeyValuePairs(extractAppStateValue(await routerInvokeBin(route, new Uint8Array(0))));
  return { resumed: count(pairs, route, 'resumed') };
}

/**
 * Identity activation: gathers every counterparty's posted, genesis-authenticated evidence
 * and assembles the cross-relationship succession (build_and_activate_recovery in the SDK).
 * Returns the SDK's status string; `assembled;awaiting-go-live:…` is an assembled succession
 * whose recording waits on go-live.
 */
export async function activateRecovery(): Promise<string> {
  return extractAppStateValue(await routerInvokeBin('recovery.activate', new Uint8Array(0)));
}

/**
 * dBTC bearer-asset reconciliation after recovery. Returns the SDK's status string:
 * `dbtc-state=<label>`, or `dbtc-locked;awaiting-enumeration:<reason>` while the evidence is
 * incomplete and dBTC stays locked.
 */
export async function reconcileDbtc(): Promise<string> {
  return extractAppStateValue(await routerInvokeBin('recovery.reconcileDbtc', new Uint8Array(0)));
}

/** The SDK's final cleanup once every counterparty has resumed; an error envelope throws. */
export async function completeRecovery(): Promise<void> {
  extractAppStateValue(await routerInvokeBin('recovery.completeResume', new Uint8Array(0)));
}
