// SPDX-License-Identifier: Apache-2.0

import { decodeBase32Crockford, encodeBase32Crockford } from '../../utils/textId';
import { appRouterInvokeBin, appRouterQueryBin } from '../../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../../dsm/decoding';
import {
  AppStateRequest,
  ArgPack,
  Codec,
  NfcRecoveryCapsule,
  type RecoveryCapsuleDecryptResponse,
} from '../../proto/dsm_app_pb';

export type NfcBackupStatus = {
  enabled: boolean;
  configured: boolean;
  pendingCapsule: boolean;
  capsuleCount: number;
  lastCapsuleIndex: number;
};

export type CapsulePreview = {
  capsuleIndex: number;
  smtRoot: string;
  createdTick: number;
  counterpartyCount: number;
} | null;

export type DecryptedCapsulePreview = {
  smtRoot: string;
  rollupHash: string;
  capsuleVersion: number;
  capsuleFlags: number;
  logicalTime: number;
  capsuleIndex: number;
  counterpartyCount: number;
  counterparties: string[];
  chainTips: Array<{
    counterpartyId: string;
    height: number;
    headHash: string;
  }>;
};

function toBytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(data) as Uint8Array<ArrayBuffer>;
}

function packStringArg(value: string): Uint8Array {
  const req = new AppStateRequest({ key: 'recovery', value });
  return new ArgPack({ codec: Codec.PROTO, body: toBytes(req.toBinary()) }).toBinary();
}

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

function parseKeyValuePairs(value: string): Record<string, string> {
  const pairs: Record<string, string> = {};
  for (const part of value.split(',')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) pairs[key] = val;
  }
  return pairs;
}

function encodeHash(bytes?: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return 'UNKNOWN';
  return encodeBase32Crockford(bytes);
}

function decodeMetadata(metaData: Uint8Array): {
  capsuleVersion: number;
  capsuleFlags: number;
  logicalTime: number;
  capsuleIndex: number;
} {
  if (!(metaData instanceof Uint8Array) || metaData.length < 20) {
    return {
      capsuleVersion: 0,
      capsuleFlags: 0,
      logicalTime: 0,
      capsuleIndex: 0,
    };
  }

  const view = new DataView(metaData.buffer, metaData.byteOffset, metaData.byteLength);
  const logicalTime = Number(view.getBigUint64(4, true));
  const capsuleIndex = Number(view.getBigUint64(12, true));

  return {
    capsuleVersion: view.getUint16(0, true),
    capsuleFlags: view.getUint16(2, true),
    logicalTime: Number.isSafeInteger(logicalTime) ? logicalTime : 0,
    capsuleIndex: Number.isSafeInteger(capsuleIndex) ? capsuleIndex : 0,
  };
}

function normalizeMnemonic(mnemonic: string): string {
  const trimmed = String(mnemonic || '').trim();
  if (trimmed.split(/\s+/).length < 12) {
    throw new Error('Mnemonic must be at least 12 words.');
  }
  return trimmed;
}

function assertCapsuleBytes(capsuleBytes: Uint8Array): void {
  if (!(capsuleBytes instanceof Uint8Array) || capsuleBytes.length === 0) {
    throw new Error('Recovery capsule payload was empty.');
  }
}

function mapDecryptResponse(
  response: RecoveryCapsuleDecryptResponse,
): DecryptedCapsulePreview {
  const metadata = decodeMetadata(response.metaData);
  return {
    smtRoot: encodeHash(response.globalRoot?.v),
    rollupHash: encodeHash(response.receiptRollup?.v),
    capsuleVersion: metadata.capsuleVersion,
    capsuleFlags: metadata.capsuleFlags,
    logicalTime: metadata.logicalTime,
    capsuleIndex: metadata.capsuleIndex,
    counterpartyCount: response.chainTips.length,
    counterparties: response.chainTips
      .filter((tip) => tip.counterpartyDeviceId.length === 32)
      .map((tip) => encodeBase32Crockford(tip.counterpartyDeviceId)),
    chainTips: response.chainTips
      .filter((tip) => tip.counterpartyDeviceId.length === 32)
      .map((tip) => ({
        counterpartyId: encodeBase32Crockford(tip.counterpartyDeviceId),
        height: Number(tip.height),
        headHash: encodeHash(tip.headHash?.v),
      })),
  };
}

export function capsuleBytesToBase32(capsuleBytes: Uint8Array): string {
  return encodeBase32Crockford(capsuleBytes);
}

export function capsulePreviewFromBase32(base32: string, maxBytes = 20): string {
  const bytes = decodeBase32Crockford(base32);
  const shown = bytes.slice(0, Math.min(maxBytes, bytes.length));
  return `${encodeBase32Crockford(shown)}${bytes.length > shown.length ? '…' : ''}`;
}

export async function generateMnemonic(): Promise<string> {
  const res = await appRouterInvokeBin('recovery.generateMnemonic', new Uint8Array(0));
  return extractAppStateValue(res);
}

export async function enableNfcBackup(mnemonic: string): Promise<void> {
  const res = await appRouterInvokeBin('recovery.enable', packStringArg(normalizeMnemonic(mnemonic)));
  extractAppStateValue(res);
}

export async function disableNfcBackup(): Promise<void> {
  const res = await appRouterInvokeBin('recovery.disable', new Uint8Array(0));
  extractAppStateValue(res);
}

export async function cacheRecoveryMnemonic(mnemonic: string): Promise<void> {
  const res = await appRouterInvokeBin(
    'recovery.cacheMnemonic',
    packStringArg(normalizeMnemonic(mnemonic)),
  );
  extractAppStateValue(res);
}

export async function getNfcBackupStatus(): Promise<NfcBackupStatus> {
  const res = await appRouterQueryBin('recovery.status');
  const pairs = parseKeyValuePairs(extractAppStateValue(res));
  return {
    enabled: pairs.enabled === 'true',
    configured: pairs.configured === 'true',
    pendingCapsule: pairs.pending === 'true',
    capsuleCount: parseInt(pairs.capsule_count ?? '0', 10),
    lastCapsuleIndex: parseInt(pairs.last_capsule_index ?? '0', 10),
  };
}

export async function createCapsule(mnemonic: string): Promise<Uint8Array> {
  const res = await appRouterInvokeBin(
    'recovery.createCapsule',
    packStringArg(normalizeMnemonic(mnemonic)),
  );
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'createCapsule failed');
  }
  if (env.payload.case !== 'nfcRecoveryCapsule') {
    throw new Error(`Unexpected payload: ${env.payload.case}`);
  }
  return env.payload.value.payload;
}

export async function decryptCapsuleBytes(
  capsuleBytes: Uint8Array,
  mnemonic: string,
): Promise<DecryptedCapsulePreview> {
  assertCapsuleBytes(capsuleBytes);
  await cacheRecoveryMnemonic(normalizeMnemonic(mnemonic));

  const req = new NfcRecoveryCapsule({
    payload: toBytes(capsuleBytes),
  });
  const res = await appRouterInvokeBin('recovery.decryptCapsule', req.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'decryptCapsule failed');
  }
  if (env.payload.case !== 'recoveryCapsuleDecryptResponse') {
    throw new Error(`Unexpected payload: ${env.payload.case}`);
  }

  return mapDecryptResponse(env.payload.value);
}

export async function inspectCapsuleBytes(
  capsuleBytes: Uint8Array,
  mnemonic: string,
): Promise<DecryptedCapsulePreview> {
  assertCapsuleBytes(capsuleBytes);
  await cacheRecoveryMnemonic(normalizeMnemonic(mnemonic));

  const req = new NfcRecoveryCapsule({
    payload: toBytes(capsuleBytes),
  });
  const res = await appRouterInvokeBin('recovery.inspectCapsule', req.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'inspectCapsule failed');
  }
  if (env.payload.case !== 'recoveryCapsuleDecryptResponse') {
    throw new Error(`Unexpected payload: ${env.payload.case}`);
  }

  return mapDecryptResponse(env.payload.value);
}

export async function decryptCapsuleFromBase32(params: {
  capsuleBase32: string;
  mnemonic: string;
}): Promise<DecryptedCapsulePreview> {
  const capsuleBytes = decodeBase32Crockford(String(params.capsuleBase32 || '').trim());
  return decryptCapsuleBytes(capsuleBytes, normalizeMnemonic(params.mnemonic));
}

export async function getCapsulePreview(): Promise<CapsulePreview> {
  try {
    const res = await appRouterQueryBin('recovery.capsulePreview');
    const val = extractAppStateValue(res);
    if (!val || val === 'none') return null;
    const pairs = parseKeyValuePairs(val);
    return {
      capsuleIndex: parseInt(pairs.capsule_index ?? '0', 10),
      smtRoot: pairs.smt_root ?? '',
      createdTick: parseInt(pairs.created_tick ?? '0', 10),
      counterpartyCount: parseInt(pairs.counterparty_count ?? '0', 10),
    };
  } catch {
    return null;
  }
}

export async function readNfcRing(): Promise<void> {
  const res = await appRouterInvokeBin('nfc.ring.read', new Uint8Array(0));
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'NFC read failed');
  }
}

export async function stopNfcRead(): Promise<void> {
  try {
    await appRouterInvokeBin('nfc.ring.stopRead', new Uint8Array(0));
  } catch {
    // Best-effort teardown — ignore errors.
  }
}

export async function writeToNfcRing(): Promise<void> {
  const res = await appRouterInvokeBin('nfc.ring.write', new Uint8Array(0));
  const env = decodeFramedEnvelopeV3(res);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'NFC write failed');
  }
}
