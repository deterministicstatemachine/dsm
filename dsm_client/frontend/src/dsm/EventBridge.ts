/* eslint-disable @typescript-eslint/no-explicit-any */
// path: dsm_client/frontend/src/dsm/EventBridge.ts
// SPDX-License-Identifier: Apache-2.0
// Unified event bridge for native -> WebView push notifications.
// Kotlin dispatches CustomEvent("dsm-event-bin", { detail: { topic, payload: Uint8Array } })
// We expose a tiny pub/sub with binary payloads (Uint8Array), bytes-only.
// Special case: topic="ble.envelope.bin" => parsed as Envelope; callers should subscribe via EventBridge.on('ble.envelope.bin')

import * as pb from '../proto/dsm_app_pb';
import { decodeFramedEnvelopeV3 } from './decoding';
import { decodeNativeHostEventToLegacyTopic } from './NativeHostBridge';
import { dispatchNativeQrScannerActive } from './qrScannerState';
import { bytesToBase32CrockfordPrefix, encodeBase32Crockford } from '../utils/textId';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { emitDeterministicSafetyIfPresent } from '../utils/deterministicSafety';
import logger from '../utils/logger';
import type { NativeSessionSnapshot } from '../runtime/nativeSessionTypes';

export type DsmEventHandler = (payload: Uint8Array) => void;

// Internal subscription registry
const topicSubs: Map<string, Set<DsmEventHandler>> = new Map();

function ensureTopic(topic: string): Set<DsmEventHandler> {
  let set = topicSubs.get(topic);
  if (!set) {
    set = new Set<DsmEventHandler>();
    topicSubs.set(topic, set);
  }
  return set;
}

export function on(topic: string, handler: DsmEventHandler): () => void {
  ensureTopic(topic).add(handler);
  return () => off(topic, handler);
}

export function once(topic: string, handler: DsmEventHandler): () => void {
  const wrapped: DsmEventHandler = (p) => {
    try { handler(p); } finally { off(topic, wrapped); }
  };
  return on(topic, wrapped);
}

export function off(topic: string, handler: DsmEventHandler): void {
  const set = topicSubs.get(topic);
  if (set) set.delete(handler);
}

// Allow tests or internal publishers to inject events without DOM
export function emit(topic: string, payload: Uint8Array): void {
  const set = topicSubs.get(topic);
  if (!set || set.size === 0) return;

  // Copy payload once (defensive) and snapshot handlers to avoid mutation during iteration.
  const copy = new Uint8Array(payload);
  const handlers = [...set];
  for (let i = 0; i < handlers.length; i++) {
    try { handlers[i](copy); } catch (_) { /* swallow */ }
  }
}

// Re-dispatch a genesis lifecycle topic on the DOM `dsm-event-bin` channel so
// that `addDsmEventListener` subscribers (e.g. `useGenesisFlow`) receive it.
// The existing `dsm-event-bin` listener in this file will also call the
// internal `emit()` on the `topicSubs` bus for any `EventBridge.on('genesis.*')`
// subscribers, so both buses stay in sync.
function dispatchGenesisTopic(topic: string, payload: Uint8Array): void {
  if (typeof window === 'undefined') return;
  try {
    window.dispatchEvent(
      new CustomEvent('dsm-event-bin', {
        detail: { topic, payload: new Uint8Array(payload) },
      }),
    );
  } catch (e) {
    try { logger.warn('[EventBridge] dispatchGenesisTopic failed', e); } catch {}
  }
}

function emitGenesisLifecycleFromEnvelope(bytes: Uint8Array): boolean {
  const env = decodeFramedEnvelopeV3(bytes);
  if (env.payload.case !== 'genesisLifecycle') return false;
  const lifecycle = env.payload.value;
  switch (lifecycle.kind) {
    case pb.GenesisLifecycleEvent_Kind.GENESIS_KIND_STARTED:
      dispatchGenesisTopic('genesis.started', new Uint8Array(0));
      return true;
    case pb.GenesisLifecycleEvent_Kind.GENESIS_KIND_SECURING_DEVICE:
      dispatchGenesisTopic('genesis.securing-device', new Uint8Array(0));
      return true;
    case pb.GenesisLifecycleEvent_Kind.GENESIS_KIND_SECURING_PROGRESS:
      dispatchGenesisTopic(
        'genesis.securing-device-progress',
        new Uint8Array([lifecycle.progress & 0xff]),
      );
      return true;
    case pb.GenesisLifecycleEvent_Kind.GENESIS_KIND_SECURING_COMPLETE:
      dispatchGenesisTopic('genesis.securing-device-complete', new Uint8Array(0));
      return true;
    case pb.GenesisLifecycleEvent_Kind.GENESIS_KIND_SECURING_ABORTED:
      dispatchGenesisTopic('genesis.securing-device-aborted', new Uint8Array(0));
      return true;
    case pb.GenesisLifecycleEvent_Kind.GENESIS_KIND_OK:
      dispatchGenesisTopic('genesis.ok', new Uint8Array(0));
      return true;
    case pb.GenesisLifecycleEvent_Kind.GENESIS_KIND_ERROR:
      dispatchGenesisTopic('genesis.error', new Uint8Array(0));
      return true;
    default:
      return false;
  }
}

function decodeSessionState(bytes: Uint8Array): NativeSessionSnapshot {
  // Session state arrives envelope-wrapped from Rust: [0x03][Envelope(SessionStateResponse)]
  // Invariant #1: Envelope v3 only — sole wire container.
  const env = decodeFramedEnvelopeV3(bytes);
  const payload: any = env.payload; // eslint-disable-line @typescript-eslint/no-explicit-any
  if (payload?.case !== 'sessionStateResponse') {
    throw new Error(`decodeSessionState: unexpected payload case '${payload?.case}'`);
  }
  const session = payload.value as pb.AppSessionStateProto;
  return {
    received: true,
    phase: session.phase as NativeSessionSnapshot['phase'],
    identity_status: session.identityStatus as NativeSessionSnapshot['identity_status'],
    env_config_status: session.envConfigStatus as NativeSessionSnapshot['env_config_status'],
    lock_status: {
      enabled: session.lockStatus?.enabled ?? false,
      locked: session.lockStatus?.locked ?? false,
      method: (session.lockStatus?.method || 'none') as NativeSessionSnapshot['lock_status']['method'],
      lock_on_pause: session.lockStatus?.lockOnPause ?? true,
    },
    hardware_status: {
      app_foreground: session.hardwareStatus?.appForeground ?? true,
      ble: {
        enabled: session.hardwareStatus?.ble?.enabled ?? false,
        permissions_granted: session.hardwareStatus?.ble?.permissionsGranted ?? false,
        scanning: session.hardwareStatus?.ble?.scanning ?? false,
        advertising: session.hardwareStatus?.ble?.advertising ?? false,
      },
      qr: {
        available: session.hardwareStatus?.qr?.available ?? true,
        active: session.hardwareStatus?.qr?.active ?? false,
        camera_permission: session.hardwareStatus?.qr?.cameraPermission ?? false,
      },
    },
    fatal_error: session.fatalError || null,
    wallet_refresh_hint: Number(session.walletRefreshHint ?? 0),
  };
}

export function initializeEventBridge(): void {
  if (typeof window === 'undefined') return; // SSR safety
  const anyWin = window as any;
  if (anyWin.__DSM_EVENT_BRIDGE_INSTALLED__) return;

  // Deterministic throttle state for identity envelopes (emit 1 in N, per device)
  const lastIdentityEmitByDevice: Map<string, number> = new Map();

  // Deterministic throttle for wallet.refresh from BLE envelopes.
  // Without this, every BLE envelope matching bilateral patterns
  // triggers a full balance+history refresh (~50 calls/sec).

  window.addEventListener('dsm-native-host-event-bin', (ev: Event) => {
    try {
      const detail = (ev as CustomEvent<{ payload?: unknown }>).detail;
      const raw = detail?.payload;
      const bytes = raw instanceof Uint8Array ? raw : raw instanceof ArrayBuffer ? new Uint8Array(raw) : null;
      if (!bytes) return;
      const mapped = decodeNativeHostEventToLegacyTopic(bytes);
      if (!mapped) return;
      window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: mapped }));
    } catch (err) {
      try { logger.warn('[EventBridge] Malformed dsm-native-host-event-bin', err); } catch {}
    }
  });

  window.addEventListener('dsm-event-bin', (ev: Event) => {
    try {
      const e: any = ev as any;
      const detail = e?.detail ?? {};
      const topic: string = String(detail.topic ?? '');
      const raw = detail.payload;
      const bytes = raw instanceof Uint8Array ? raw : raw instanceof ArrayBuffer ? new Uint8Array(raw) : null;
      if (!bytes) return;

      if (topic.startsWith('genesis.')) {
        emit(topic, bytes);
        return;
      }

      if (topic === 'canonical.envelope.bin') {
        try {
          if (emitGenesisLifecycleFromEnvelope(bytes)) {
            return;
          }
        } catch (e) {
          logger.warn('[EventBridge] canonical envelope decode failed:', e);
        }
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm.deterministicSafety') {
        try {
          const msg = new TextDecoder().decode(bytes);
          emitDeterministicSafetyIfPresent(msg);
        } catch {
          // ignore
        }
        return;
      }

      // --- Lifecycle events from Kotlin (previously evaluateJavascript, now binary) ---
      // Re-dispatch as DOM CustomEvents so existing hooks work.

      if (topic === 'session.state') {
        try {
          const snapshot = decodeSessionState(bytes);
          bridgeEvents.emit('session.state', snapshot);
        } catch (e) {
          logger.warn('[EventBridge] session.state decode failed:', e);
        }
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm-bridge-ready') {
        try { window.dispatchEvent(new Event('dsm-bridge-ready')); } catch (e) { logger.warn('[EventBridge] dsm-bridge-ready dispatch failed:', e); }
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm-identity-ready') {
        // Straight to the bus. This used to be a `document` event that the
        // adapter re-emitted, and that `getIdentity`'s wake-up listened for on
        // `window`, where it never arrived.
        bridgeEvents.emit('identity.ready', undefined as never);
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm-app-pause') {
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm-biometric-result') {
        // Payload: [0x01] = success, [0x00][u16 BE errorCode][UTF-8 message] = error
        try {
          const success = bytes.length > 0 && bytes[0] === 0x01;
          const detail: { success: boolean; errorCode?: number; error?: string } = { success };
          if (!success && bytes.length >= 3) {
            detail.errorCode = (bytes[1] << 8) | bytes[2];
            detail.error = bytes.length > 3 ? new TextDecoder().decode(bytes.subarray(3)) : '';
          }
          window.dispatchEvent(new CustomEvent('dsm-biometric-result', { detail }));
        } catch {}
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm-env-config-error') {
        // Payload: UTF-8 "type|message" or "type|message|help"
        try {
          const text = new TextDecoder().decode(bytes);
          const parts = text.split('|');
          bridgeEvents.emit('env.config.error', { message: parts[1] || 'Environment configuration error' });
        } catch {}
        emit(topic, bytes);
        return;
      }

      if (topic === 'qr_scan_result') {
        // Payload: UTF-8 encoded QR text (empty = cancelled)
        try {
          dispatchNativeQrScannerActive(false);
          const qrText = new TextDecoder().decode(bytes);
          window.dispatchEvent(new CustomEvent('dsm-event', {
            detail: { topic: 'qr_scan_result', payloadText: qrText },
          }));
        } catch {}
        emit(topic, bytes);
        return;
      }

      if (topic === 'ble-dev-automation') {
        // Payload: UTF-8 "ok:advertising=true,scanning=true" or "error:reason"
        try {
          const text = new TextDecoder().decode(bytes);
          const isError = text.startsWith('error:');
          const detail: Record<string, unknown> = {};
          if (isError) {
            detail.error = text.substring(6);
            detail.advertising = false;
            detail.scanning = false;
          } else {
            // Parse "ok:advertising=true,scanning=false"
            const kvPart = text.startsWith('ok:') ? text.substring(3) : text;
            for (const pair of kvPart.split(',')) {
              const [k, v] = pair.split('=');
              if (k && v !== undefined) {
                detail[k.trim()] = v.trim() === 'true';
              }
            }
          }
          window.dispatchEvent(new CustomEvent('ble-dev-automation', { detail }));
        } catch {}
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm-wallet-refresh') {
        bridgeEvents.emit('wallet.refresh', { source: 'native' });
        emit(topic, bytes);
        return;
      }

      // Inbox sync result pushed from Rust inbox_poller (Invariant #7 compliant).
      // Payload is StorageSyncResponse protobuf bytes.
      if (topic === 'inbox.updated') {
        let resp: pb.StorageSyncResponse;
        try {
          resp = pb.StorageSyncResponse.fromBinary(bytes);
        } catch (e) {
          // No counts are known from bytes that do not decode: none are announced.
          logger.error('[EventBridge] inbox.updated payload does not decode:', e);
          return;
        }
        bridgeEvents.emit('inbox.updated', { newItems: resp.processed, source: 'rust_poller' });
        // Also trigger wallet refresh if items were processed.
        if (resp.processed > 0) {
          bridgeEvents.emit('wallet.refresh', { source: 'inbox.sync' });
        }
        emit(topic, bytes);
        return;
      }

      // Pairing completion relay from native.
      // Payload is expected to be counterparty device_id bytes (32 bytes).
      if (topic === 'dsm-contact-ble-updated') {
        if (bytes.length !== 32) {
          // An update names the device it is about; this one names none.
          logger.error(`[EventBridge] dsm-contact-ble-updated carries ${bytes.length} bytes, not a 32-byte device id`);
          return;
        }
        bridgeEvents.emit('contact.bleUpdated', {
          bleAddress: undefined,
          deviceId: encodeBase32Crockford(bytes),
        });
        emit(topic, bytes);
        return;
      }

      // Special-case: bilateral.event TRANSFER_COMPLETE -> refresh wallet state
      if (topic === 'bilateral.event') {
        try {
          const note = pb.BilateralEventNotification.fromBinary(bytes);

          // The SDK marks a rejection that must be reconciled online by this status.
          const needsReconcile = note.status === 'needs_online_reconcile';

          if (needsReconcile) {
            try {
              bridgeEvents.emit('wallet.refresh', { source: 'bilateral.reconcile_status' });
            } catch {}
          }

          // The event type says a transfer completed; a status string is free text.
          const isComplete = note.eventType === pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE;

          if (isComplete) {
            try { logger.debug('[BilateralTransfer] TRANSFER_COMPLETE - refreshing wallet state'); } catch {}
            try { bridgeEvents.emit('wallet.refresh', { source: 'bilateral.transfer_complete' }); } catch {}
            // For the reactions that are not reloads: the toast and the credit sound.
            try { bridgeEvents.emit('bilateral.transferComplete', undefined as any); } catch {}
          }
        } catch (e) {
          logger.error('[EventBridge] Failed to parse bilateral event:', e);
          // ignore malformed bilateral event
        }
      }

      // Throttle BLE identity envelopes to reduce UI spam
      if (topic === 'ble.envelope.bin') {
        try {
          const env = decodeFramedEnvelopeV3(bytes);
          const p: any = env?.payload ?? env;

          if (p?.case === 'appStateResponse' && p.value?.key === 'nfc.backup_written') {
            try { bridgeEvents.emit('nfc.backupWritten', undefined as any); } catch {}
            emit('nfc.backup_written', bytes);
            return;
          }

          // BLE state events -> parse BleEvent oneof and emit to bridgeEvents
          const bleEvent: any = (p?.case === 'bleEvent' ? p.value : p?.bleEvent);
          if (bleEvent?.ev) {
            const evCase = bleEvent.ev.case;
            if (evCase === 'identityObserved') {
              const obs = bleEvent.ev.value as pb.BleIdentityObserved;
              const addr = typeof obs?.address === 'string' ? obs.address : '';
              const dev = obs?.deviceId instanceof Uint8Array ? obs.deviceId : undefined;
              const gen = obs?.genesisHash instanceof Uint8Array ? obs.genesisHash : undefined;
              if (addr && dev && dev.length === 32) {
                const deviceIdB32 = encodeBase32Crockford(dev);
                const genesisB32 = gen && gen.length === 32 ? encodeBase32Crockford(gen) : undefined;
                try {
                  bridgeEvents.emit('contact.bleMapped', {
                    address: addr,
                    deviceId: deviceIdB32,
                    genesisHash: genesisB32,
                  });
                } catch {}
              }
            } else if (evCase === 'deviceFound') {
              const info = bleEvent.ev.value as pb.BleDeviceInfo;
              try {
                bridgeEvents.emit('ble.deviceFound', {
                  address: info?.address ?? '', name: info?.name ?? '', rssi: info?.rssi ?? 0,
                });
              } catch {}
            } else if (evCase === 'scanStarted') {
              try { bridgeEvents.emit('ble.scanStarted', undefined as any); } catch {}
            } else if (evCase === 'scanStopped') {
              try { bridgeEvents.emit('ble.scanStopped', undefined as any); } catch {}
            } else if (evCase === 'deviceConnected') {
              const info = bleEvent.ev.value as pb.BleDeviceInfo;
              try { bridgeEvents.emit('ble.deviceConnected', { address: info?.address ?? '' }); } catch {}
            } else if (evCase === 'deviceDisconnected') {
              const info = bleEvent.ev.value as pb.BleDeviceInfo;
              try { bridgeEvents.emit('ble.deviceDisconnected', { address: info?.address ?? '' }); } catch {}
            } else if (evCase === 'connectionFailed') {
              try { bridgeEvents.emit('ble.connectionFailed', { reason: String(bleEvent.ev.value ?? '') }); } catch {}
            } else if (evCase === 'pairingStatus') {
              const ps = bleEvent.ev.value as pb.PairingStatusUpdate;
              const devId = ps?.deviceId instanceof Uint8Array && ps.deviceId.length === 32
                ? encodeBase32Crockford(ps.deviceId)
                : '';
              try {
                bridgeEvents.emit('ble.pairingStatus', {
                  deviceId: devId,
                  status: ps?.status ?? '',
                  message: ps?.message ?? '',
                  bleAddress: ps?.bleAddress || undefined,
                });
              } catch {}
              // contact.bleMapped is NOT emitted here — let the periodic contact
              // refresh (ContactsContext) detect bleAddress from the backend.
              // This ensures pairing is bilateral: both devices must have their
              // backend confirm the link before the UI shows "Paired!".
            } else if (evCase === 'blePermission') {
              const bpe = bleEvent.ev.value as pb.BlePermissionEvent;
              try { bridgeEvents.emit('ble.permission.error', { message: bpe?.operation ?? '' }); } catch {}
            }
          }
          
          // NFC recovery capsule: Envelope payload field 96 dispatched via Rust JNI.
          const nfcCapsule: any = (p?.case === 'nfcRecoveryCapsule' ? p.value : p?.nfcRecoveryCapsule);
          if (nfcCapsule?.payload instanceof Uint8Array && nfcCapsule.payload.length > 0) {
            emit('nfc-recovery-capsule', nfcCapsule.payload as Uint8Array);
            return; // handled; do not fall through
          }

          // A bilateral prepare response over BLE is not a wallet change and
          // announces none: the wallet changes at TRANSFER_COMPLETE, which
          // `bilateral.event` announces. This used to emit a `wallet.refresh`
          // claiming `bilateral.transfer_complete` on one prepare response in
          // eight.
          
          // Check for identity-like payload without depending on a specific generated type name
          const identity: any = (p?.case === 'bilateralIdentityExchange' ? p.value : p?.bilateralIdentityExchange);
          if (identity && identity.deviceId instanceof Uint8Array) {
            // Extract device ID from identity payload for throttling key
            const idBytes: Uint8Array = identity.deviceId as Uint8Array;
            const deviceId = bytesToBase32CrockfordPrefix(idBytes, 8);
            // Deterministic throttling: emit only every Nth identity per device.
            // (No wall-clock; avoids time-based behavior differences.)
            const last = lastIdentityEmitByDevice.get(deviceId) ?? 0;
            const next = (last + 1) | 0;
            const EMIT_EVERY = 4; // emit 1 in 4 identity envelopes per device
            lastIdentityEmitByDevice.set(deviceId, next);
            if ((next % EMIT_EVERY) !== 1) {
              return;
            }
            // Bounded memory: keep last 100 device counters
            if (lastIdentityEmitByDevice.size > 100) {
              const keys = Array.from(lastIdentityEmitByDevice.keys()).slice(0, 20);
              keys.forEach(k => lastIdentityEmitByDevice.delete(k));
            }
          }
        } catch {
          // Not an identity envelope or parse failed; allow through
        }
      }

      emit(topic, bytes);
    } catch (err) {
      // ignore malformed events
      try { logger.warn('[EventBridge] Malformed dsm-event-bin', err); } catch {}
    }
  });

  // Drain any events that arrived before this listener was attached.
  // index.html buffers early events in __DSM_EVENT_BUFFER__ because the
  // webpack bundle (this code) loads after the inline MessagePort handler.
  const buffer = anyWin.__DSM_EVENT_BUFFER__;
  if (Array.isArray(buffer)) {
    anyWin.__DSM_EVENT_BUFFER__ = null; // Stop buffering, prevent memory leak
    for (const evt of buffer) {
      window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: evt }));
    }
  }

  anyWin.__DSM_EVENT_BRIDGE_INSTALLED__ = true;
}
