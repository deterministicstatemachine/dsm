// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// DSM NFC DOMAIN — TypeScript surface for NFC ring backup
// ============================================================================
//
// NFC backup writes an encrypted recovery capsule to an NTAG216 ring.
// Rust owns all capsule creation, NDEF formatting, and crypto.
// Kotlin operates NFC hardware (reader mode, tag write).
// TypeScript triggers the flow and listens for completion events.
//
// Flow:
//   1. TS calls startNfcWrite() → bridge RPC "nfcStartWrite"
//   2. Kotlin launches NfcWriteActivity (enableReaderMode)
//   3. Kotlin gets capsule from Rust (getPendingRecoveryCapsule)
//   4. Kotlin gets NDEF bytes from Rust (prepareNfcWritePayload)
//   5. Kotlin writes bytes to NFC tag (hardware op)
//   6. Kotlin tells Rust write succeeded (clearPendingRecoveryCapsule)
//   7. Kotlin vibrates (state committed event)
//   8. Kotlin dispatches "nfc.backup_written" event → TS
//
// Read flow (NfcRecoveryActivity):
//   1. Android NFC dispatch detects application/vnd.dsm.recovery tag
//   2. Kotlin reads NDEF, sends raw bytes to Rust (createNfcRecoveryCapsuleEnvelope)
//   3. Rust decrypts, dispatches envelope via BleEventRelay
//   4. TS receives "nfc-recovery-capsule" event with payload
//
// ============================================================================

import { bridgeEvents } from '../bridge/bridgeEvents';
import * as EventBridge from './EventBridge';
import { callBin } from './WebViewBridge';
import { logger } from '../utils/logger';

const TAG = '[NFC]';

// ─── Bridge calls ───────────────────────────────────────────────────────────

/**
 * Check if NFC backup is enabled in the Rust core.
 * @returns true if the user has enabled NFC ring backup
 */
export async function isNfcBackupEnabled(): Promise<boolean> {
  try {
    const res = await callBin('nfcIsBackupEnabled', new Uint8Array(0));
    return res.length > 0 && res[0] !== 0;
  } catch {
    return false;
  }
}

/**
 * Check if a recovery capsule is pending (Rust created it, not yet written to tag).
 * @returns true if there is a capsule ready to write
 */
export async function hasPendingCapsule(): Promise<boolean> {
  try {
    const res = await callBin('nfcHasPendingCapsule', new Uint8Array(0));
    return res.length > 0 && res[0] !== 0;
  } catch {
    return false;
  }
}

/**
 * Trigger an NFC write session.
 * Kotlin launches reader mode and waits for tag detection.
 * On successful write: device vibrates, "nfc.backupWritten" event fires.
 * On failure: nothing happens. User taps again.
 */
export async function startNfcWrite(): Promise<void> {
  try {
    await callBin('nfcStartWrite', new Uint8Array(0));
    logger.info(TAG, 'NFC write session started');
  } catch (e) {
    logger.error(TAG, 'Failed to start NFC write:', e);
    throw e;
  }
}

// ─── Event subscriptions ────────────────────────────────────────────────────

export type NfcBackupWrittenHandler = () => void;
export type NfcCapsuleReceivedHandler = (payload: Uint8Array) => void;

/**
 * Subscribe to NFC backup write completion.
 * Fires when Kotlin confirms the tag write committed (vibration fired).
 * @returns unsubscribe function
 */
export function onBackupWritten(handler: NfcBackupWrittenHandler): () => void {
  return bridgeEvents.on('nfc.backupWritten', handler);
}

/**
 * Subscribe to NFC recovery capsule received (tag was read).
 * Payload is the raw encrypted capsule bytes from the tag.
 * @returns unsubscribe function
 */
export function onCapsuleReceived(handler: NfcCapsuleReceivedHandler): () => void {
  return EventBridge.on('nfc-recovery-capsule', handler);
}
