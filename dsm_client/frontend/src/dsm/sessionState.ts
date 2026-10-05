// SPDX-License-Identifier: Apache-2.0
// Rust's session snapshot (session_manager's compute_snapshot), as the session
// store holds it. It arrives two ways: published by Kotlin on the event bus,
// and as the answer to every session.* route.

import * as pb from '../proto/dsm_app_pb';
import { decodeFramedEnvelopeV3 } from './decoding';
import type { NativeSessionReport, NativeSessionSnapshot } from '../runtime/nativeSessionTypes';

/** The snapshot an envelope carries. An error envelope throws Rust's message. */
export function sessionSnapshotOf(env: pb.Envelope): NativeSessionReport {
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message);
  }
  if (env.payload.case !== 'sessionStateResponse') {
    throw new Error(`decodeSessionState: unexpected payload case '${env.payload.case}'`);
  }
  const session = env.payload.value;
  // Rust fills every nested status on every snapshot. A snapshot missing one
  // is malformed, never read as a status that is off, and is refused rather
  // than filled in.
  const lock = session.lockStatus;
  const hardware = session.hardwareStatus;
  const ble = hardware?.ble;
  const qr = hardware?.qr;
  if (!lock || !hardware || !ble || !qr) {
    throw new Error('decodeSessionState: the snapshot lacks its lock or hardware status');
  }
  return {
    phase: session.phase as NativeSessionSnapshot['phase'],
    identity_status: session.identityStatus as NativeSessionSnapshot['identity_status'],
    env_config_status: session.envConfigStatus as NativeSessionSnapshot['env_config_status'],
    lock_status: {
      enabled: lock.enabled,
      locked: lock.locked,
      // Rust spells the method itself ("none" when there is no lock).
      method: lock.method as NativeSessionSnapshot['lock_status']['method'],
      lock_on_pause: lock.lockOnPause,
      tries: {
        misses_left: lock.missesLeft,
        phrase_required: lock.phraseRequired,
      },
    },
    hardware_status: {
      app_foreground: hardware.appForeground,
      ble: {
        enabled: ble.enabled,
        permissions_granted: ble.permissionsGranted,
        scanning: ble.scanning,
        advertising: ble.advertising,
      },
      qr: {
        available: qr.available,
        active: qr.active,
        camera_permission: qr.cameraPermission,
      },
    },
    // Rust sends an empty string for no error.
    fatal_error: session.fatalError || null,
    wallet_refresh_hint: Number(session.walletRefreshHint),
  };
}

/** Session state as it arrives envelope-wrapped from Rust: [0x03][Envelope(SessionStateResponse)]. */
export function decodeSessionState(bytes: Uint8Array): NativeSessionReport {
  return sessionSnapshotOf(decodeFramedEnvelopeV3(bytes));
}
