/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/services/recovery/nfcRecoveryService.ts
// SPDX-License-Identifier: Apache-2.0
// NFC recovery helpers (capsule preview + decrypt) to keep byte handling out of UI.

import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';
import { decryptRecoveryCapsuleStrict, appRouterInvokeBin, appRouterQueryBin } from '../../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';
import { AppStateRequest, ArgPack, Codec } from '../../proto/dsm_app_pb';
import _logger from '../../utils/logger';

function toBytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(data) as Uint8Array<ArrayBuffer>;
}

export function capsuleBytesToBase32(capsuleBytes: Uint8Array): string {
  return encodeBase32Crockford(capsuleBytes);
}

export function capsulePreviewFromBase32(base32: string, maxBytes = 20): string {
  const bytes = decodeBase32Crockford(base32);
  const shown = bytes.slice(0, Math.min(maxBytes, bytes.length));
  return `${encodeBase32Crockford(shown)}${bytes.length > shown.length ? '…' : ''}`;
}

export async function decryptCapsuleFromBase32(params: {
  capsuleBase32: string;
  mnemonic: string;
}): Promise<any> {
  const capsuleBytes = decodeBase32Crockford(String(params.capsuleBase32 || '').trim());
  const keyText = String(params.mnemonic || '').trim();
  if (!keyText) throw new Error('Mnemonic key required.');
  const keyBytes = new TextEncoder().encode(keyText);
  return decryptRecoveryCapsuleStrict(capsuleBytes, keyBytes);
}

// ---------------------------------------------------------------------------
// Recovery route helpers — all go through the normal message spine:
// TS → appRouterInvokeBin/appRouterQueryBin → MessagePort → Kotlin → JNI → Rust
// ---------------------------------------------------------------------------

/** Pack a string value into an ArgPack(AppStateRequest) for recovery routes. */
function packStringArg(value: string): Uint8Array {
  const req = new AppStateRequest({ key: 'recovery', value });
  return new ArgPack({ codec: Codec.PROTO, body: toBytes(req.toBinary()) }).toBinary();
}

/** Extract the `value` field from an AppStateResponse envelope. */
function extractAppStateValue(resBytes: Uint8Array): string {
  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    const msg = env.payload.value.message || `Error code ${env.payload.value.code}`;
    throw new Error(msg);
  }
  if (env.payload.case !== 'appStateResponse') {
    throw new Error(`Unexpected payload: ${env.payload.case}`);
  }
  return env.payload.value.value ?? '';
}

/** Generate a 24-word BIP-39 mnemonic (crypto in Rust, never TS). */
export async function generateMnemonic(): Promise<string> {
  const res = await appRouterInvokeBin('recovery.generateMnemonic', new Uint8Array(0));
  return extractAppStateValue(res);
}

/** Enable NFC backup: derives key, creates first capsule. */
export async function enableNfcBackup(mnemonic: string): Promise<string> {
  const res = await appRouterInvokeBin('recovery.enable', packStringArg(mnemonic));
  return extractAppStateValue(res);
}

/** Disable NFC backup: clears cached key, keeps configured=true. */
export async function disableNfcBackup(): Promise<string> {
  const res = await appRouterInvokeBin('recovery.disable', new Uint8Array(0));
  return extractAppStateValue(res);
}

/** Query recovery status: enabled, configured, capsule count, last index. */
export async function getNfcBackupStatus(): Promise<{
  enabled: boolean;
  configured: boolean;
  capsuleCount: number;
  lastCapsuleIndex: number;
}> {
  const res = await appRouterQueryBin('recovery.status');
  const val = extractAppStateValue(res);
  // Parse "enabled=true,configured=true,capsule_count=5,last_capsule_index=5"
  const pairs = Object.fromEntries(
    val.split(',').map((kv) => { const [k, v] = kv.split('='); return [k, v]; }),
  );
  return {
    enabled: pairs['enabled'] === 'true',
    configured: pairs['configured'] === 'true',
    capsuleCount: parseInt(pairs['capsule_count'] ?? '0', 10),
    lastCapsuleIndex: parseInt(pairs['last_capsule_index'] ?? '0', 10),
  };
}

/** Create a new recovery capsule from current state. */
export async function createCapsule(mnemonic: string): Promise<Uint8Array> {
  const res = await appRouterInvokeBin('recovery.createCapsule', packStringArg(mnemonic));
  // Response is NfcRecoveryCapsule envelope — return raw bytes
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'createCapsule failed');
  }
  if (env.payload.case === 'nfcRecoveryCapsule') {
    return env.payload.value.payload;
  }
  throw new Error(`Unexpected payload: ${env.payload.case}`);
}

/** Create tombstone receipt (revoke old device). */
export async function createTombstone(mnemonic: string): Promise<string> {
  const res = await appRouterInvokeBin('recovery.tombstone', packStringArg(mnemonic));
  return extractAppStateValue(res);
}

/** Create succession receipt (bind new device). */
export async function createSuccession(mnemonic: string): Promise<string> {
  const res = await appRouterInvokeBin('recovery.succession', packStringArg(mnemonic));
  return extractAppStateValue(res);
}

/** Resume recovery (gated on full tombstone sync). */
export async function resumeRecovery(mnemonic: string): Promise<string> {
  const res = await appRouterInvokeBin('recovery.resume', packStringArg(mnemonic));
  return extractAppStateValue(res);
}

/** Get tombstone sync progress: synced/total counts + pending device IDs. */
export async function getSyncStatus(): Promise<{
  synced: number;
  total: number;
  pending: string[];
}> {
  const res = await appRouterQueryBin('recovery.syncStatus');
  const val = extractAppStateValue(res);
  // Parse "synced=4,total=7,pending=DEVID1,DEVID2"
  const parts = val.split(',');
  let synced = 0;
  let total = 0;
  const pending: string[] = [];
  for (const part of parts) {
    if (part.startsWith('synced=')) synced = parseInt(part.slice(7), 10);
    else if (part.startsWith('total=')) total = parseInt(part.slice(6), 10);
    else if (part.startsWith('pending=')) {
      const ids = part.slice(8);
      if (ids) pending.push(...ids.split(','));
    }
  }
  return { synced, total, pending };
}

/** Query latest capsule metadata for dashboard display (no decryption). */
export async function getCapsulePreview(): Promise<{
  capsuleIndex: number;
  smtRoot: string;
  createdTick: number;
  counterpartyCount: number;
} | null> {
  try {
    const res = await appRouterQueryBin('recovery.capsulePreview');
    const val = extractAppStateValue(res);
    if (!val || val === 'none') return null;
    // Parse "capsule_index=5,smt_root=ABC123...,created_tick=42,counterparty_count=3"
    const pairs = Object.fromEntries(
      val.split(',').map((kv) => { const [k, v] = kv.split('='); return [k, v]; }),
    );
    return {
      capsuleIndex: parseInt(pairs['capsule_index'] ?? '0', 10),
      smtRoot: pairs['smt_root'] ?? '',
      createdTick: parseInt(pairs['created_tick'] ?? '0', 10),
      counterpartyCount: parseInt(pairs['counterparty_count'] ?? '0', 10),
    };
  } catch {
    return null;
  }
}

/**
 * Trigger NFC write flow. Launches Android NFC write activity.
 *
 * NO business logic here — just calls the route.
 * Rust must have a pending capsule from earlier createCapsule() call.
 * Kotlin will check preconditions and launch NfcWriteActivity.
 */
export async function writeToNfcRing(): Promise<void> {
  // Call route (no args - Rust has pending capsule already)
  const res = await appRouterInvokeBin('nfc.ring.write', new Uint8Array(0));

  // Check response (first byte after reqId: 1 = success, 0 = error)
  // Note: appRouterInvokeBin strips the reqId, so res[0] is the status byte
  const decoded = decodeFramedEnvelopeV3(res);
  if (decoded.payload.case === 'error') {
    throw new Error(decoded.payload.value.message || 'NFC write failed');
  }

  // Success - activity launched
}
