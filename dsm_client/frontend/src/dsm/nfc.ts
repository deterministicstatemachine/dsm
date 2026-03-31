// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// DSM NFC DOMAIN — envelope-based frontend surface for NFC ring backup
// ============================================================================
//
// Rust is authoritative for all recovery state and protocol decisions.
// TypeScript only issues app-router protobuf requests and listens for
// Rust-authored envelopes relayed through Kotlin's hardware transport.

import { bridgeEvents } from '../bridge/bridgeEvents';
import * as EventBridge from './EventBridge';
import {
  getNfcBackupStatus,
  writeToNfcRing,
} from '../services/recovery/nfcRecoveryService';
import { logger } from '../utils/logger';

const TAG = '[NFC]';

export async function isNfcBackupEnabled(): Promise<boolean> {
  try {
    const status = await getNfcBackupStatus();
    return status.enabled;
  } catch {
    return false;
  }
}

export async function hasPendingCapsule(): Promise<boolean> {
  try {
    const status = await getNfcBackupStatus();
    return status.pendingCapsule;
  } catch {
    return false;
  }
}

export async function startNfcWrite(): Promise<void> {
  try {
    await writeToNfcRing();
    logger.info(TAG, 'NFC write session authorized via Rust');
  } catch (e) {
    logger.error(TAG, 'Failed to start NFC write:', e);
    throw e;
  }
}

export type NfcBackupWrittenHandler = () => void;
export type NfcCapsuleReceivedHandler = (payload: Uint8Array) => void;

export function onBackupWritten(handler: NfcBackupWrittenHandler): () => void {
  return bridgeEvents.on('nfc.backupWritten', handler);
}

export function onCapsuleReceived(handler: NfcCapsuleReceivedHandler): () => void {
  return EventBridge.on('nfc-recovery-capsule', handler);
}
