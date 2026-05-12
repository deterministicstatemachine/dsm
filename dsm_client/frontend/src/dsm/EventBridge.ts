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

// Typed result for parseBleEnvelope
export interface OfflineTransferParseResult {
  offlineTransferPayload: Uint8Array;
}
export interface BleDeviceFoundResult {
  address: string;
  name: string;
  rssi: number;
}
export interface BleErrorResult {
  error: { code: number; message: string };
}
export interface BleConnectionResult {
  connected?: boolean;
  disconnected?: boolean;
}
export type BleParseResult = BleDeviceFoundResult | BleErrorResult | BleConnectionResult;
export type EnvelopeParseResult = OfflineTransferParseResult | BleParseResult | { rawEnvelope: Uint8Array } | null;

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

// Parse Envelope from "ble.envelope.bin" and extract BLE/offline transfer metadata
export function parseBleEnvelope(bytes: Uint8Array): EnvelopeParseResult {
  try {
    const env = decodeFramedEnvelopeV3(bytes);
    const p: any = env?.payload ?? env;

    // Direct DsmBtMessage (BLE error or other BT layer message) handling first
    const btMsg = (p?.case === 'dsmBtMessage' ? p.value : p?.dsmBtMessage) as pb.DsmBtMessage | undefined;
    if (btMsg && btMsg.messageType === pb.BtMessageType.BTMSG_TYPE_ERROR) {
      try {
        // Payload is a serialized BleTransactionError
        const err = pb.BleTransactionError.fromBinary(btMsg.payload);
        return {
          error: {
            code: typeof err.errorCode === 'number' ? err.errorCode : 0,
            message: typeof err.message === 'string' ? err.message : '',
          },
        };
      } catch {
        // Fall through if payload malformed
      }
    }

    // BLE UniversalRx parsing (type-safe)
    const rx = (p?.case === 'universalRx' ? p.value : p?.universalRx) as pb.UniversalRx | undefined;
    if (rx && Array.isArray(rx.results) && rx.results.length > 0) {
      const first = rx.results[0];
      const pack = first?.result;
      if (pack?.body instanceof Uint8Array && pack.body.length > 0) {
        try {
          const resp = pb.BleCommandResponse.fromBinary(pack.body);
          // BLE response discriminated union parsing
          if (resp && typeof resp === 'object') {
            if ('deviceFound' in resp && resp.deviceFound) {
              const df = resp.deviceFound as { address?: string; name?: string; rssi?: number };
              return {
                address: typeof df.address === 'string' ? df.address : '',
                name: typeof df.name === 'string' ? df.name : '',
                rssi: typeof df.rssi === 'number' ? df.rssi : 0,
              };
            }
            if ('error' in resp && resp.error) {
              const err = resp.error as { code?: number; message?: string };
              return {
                error: {
                  code: typeof err.code === 'number' ? err.code : 0,
                  message: typeof err.message === 'string' ? err.message : '',
                },
              };
            }
            if ('connected' in resp && resp.connected) {
              return { connected: true };
            }
            if ('disconnected' in resp && resp.disconnected) {
              return { disconnected: true };
            }
          }
          return { rawEnvelope: pack.body };
        } catch {
          // Not a BleCommandResponse, fall through
        }
      }
    }

    // Offline bilateral transfer detection (wallet.receive invoke in UniversalTx)
    const uTx = (p?.case === 'universalTx' ? p.value : p?.universalTx) as pb.UniversalTx | undefined;
    if (uTx && Array.isArray(uTx.ops) && uTx.ops.length > 0) {
      const op = uTx.ops[0];
      // Correct offline transfer detection logic
      if (op?.kind?.case === 'invoke') {
        const invoke = op.kind.value as pb.Invoke;
        if (invoke?.method === 'wallet.receive') {
          const argPack = invoke.args;
          if (argPack?.body instanceof Uint8Array && argPack.body.length > 0) {
            try {
              pb.BilateralTransferRequest.fromBinary(argPack.body);
              return { offlineTransferPayload: argPack.body };
            } catch {
              // not a bilateral request
            }
          }
        }
      }
      return { rawEnvelope: bytes };
    }
    return { rawEnvelope: bytes };
  } catch {
    return null;
  }
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
  let bleWalletRefreshCounter = 0;
  const BLE_WALLET_REFRESH_EVERY = 8; // emit 1 in 8 BLE-triggered refreshes

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
          window.dispatchEvent(new CustomEvent('dsm-session-state', { detail: snapshot }));
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
        try { document.dispatchEvent(new Event('dsm-identity-ready')); } catch (e) { logger.warn('[EventBridge] dsm-identity-ready dispatch failed:', e); }
        emit(topic, bytes);
        return;
      }

      if (topic === 'dsm-app-pause') {
        try { window.dispatchEvent(new CustomEvent('dsm-app-pause')); } catch (e) { logger.warn('[EventBridge] dsm-app-pause dispatch failed:', e); }
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
          const detail = {
            type: parts[0] || 'UNKNOWN_ERROR',
            message: parts[1] || 'Environment configuration error',
            help: parts[2] || undefined,
          };
          document.dispatchEvent(new CustomEvent('dsm-env-config-error', { detail }));
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

      if (topic === 'bluetooth-permissions') {
        // Payload: [0x01] = granted, [0x00] = denied
        try {
          const granted = bytes.length > 0 && bytes[0] === 0x01;
          window.dispatchEvent(new CustomEvent('bluetooth-permissions', { detail: { granted } }));
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
        try { window.dispatchEvent(new CustomEvent('dsm-wallet-refresh', { detail: { source: 'native' } })); } catch {}
        emit(topic, bytes);
        return;
      }

      // Inbox sync result pushed from Rust inbox_poller (Invariant #7 compliant).
      // Payload is StorageSyncResponse protobuf bytes.
      if (topic === 'inbox.updated') {
        try {
          const resp = pb.StorageSyncResponse.fromBinary(bytes);
          const unreadCount = Math.max((resp.pulled ?? 0) - (resp.processed ?? 0), 0);
          bridgeEvents.emit('inbox.updated', {
            unreadCount,
            newItems: resp.processed,
            source: 'rust_poller',
          });
          // Also trigger wallet refresh if items were processed.
          if (resp.processed > 0) {
            bridgeEvents.emit('wallet.refresh', { source: 'inbox.sync' });
          }
        } catch {
          // Fallback: emit with zero counts if decode fails.
          bridgeEvents.emit('inbox.updated', {
            unreadCount: 0,
            newItems: 0,
            source: 'rust_poller',
          });
        }
        emit(topic, bytes);
        return;
      }

      // Pairing completion relay from native.
      // Payload is expected to be counterparty device_id bytes (32 bytes).
      if (topic === 'dsm-contact-ble-updated') {
        try {
          const deviceIdB32 = bytes.length === 32 ? encodeBase32Crockford(bytes) : undefined;
          bridgeEvents.emit('contact.bleUpdated', {
            bleAddress: undefined,
            deviceId: deviceIdB32,
          });
        } catch {
          try {
            bridgeEvents.emit('contact.bleUpdated', {
              bleAddress: undefined,
            });
          } catch {}
        }
        emit(topic, bytes);
        return;
      }

      // Special-case: bilateral.event TRANSFER_COMPLETE -> refresh wallet state
      if (topic === 'bilateral.event') {
        try {
          const note = pb.BilateralEventNotification.fromBinary(bytes);

          const status = String(note?.status ?? '');
          const needsReconcile =
            status === 'needs_online_reconcile' ||
            status === 'needsOnlineReconcile';

          if (needsReconcile) {
            try {
              bridgeEvents.emit('wallet.refresh', { source: 'bilateral.reconcile_status' });
            } catch {}
          }

          // Always fan out a typed DOM event so UI can react even if it doesn't subscribe via EventBridge.
          try {
            window.dispatchEvent(
              new CustomEvent('dsm-bilateral-notification', {
                detail: { notification: note, bytes },
              })
            );
          } catch {}
          
          // Also emit to bridgeEvents for testing
          try {
            bridgeEvents.emit('bilateral.event', bytes);
          } catch {}
          
          // Accept explicit type or status string (robustness against enum drift)
          const isComplete = 
            note?.eventType === pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE ||
            note?.status === 'completed';

          if (isComplete) {
            try { logger.debug('[BilateralTransfer] TRANSFER_COMPLETE - refreshing wallet state'); } catch {}
            try { bridgeEvents.emit('wallet.refresh', { source: 'bilateral.transfer_complete' }); } catch {}
            // Direct signal so listeners can bypass the wallet.refresh throttle chain.
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
            } else if (evCase === 'advertisingStarted') {
              try { bridgeEvents.emit('ble.advertisingStarted', undefined as any); } catch {}
            } else if (evCase === 'advertisingStopped') {
              try { bridgeEvents.emit('ble.advertisingStopped', undefined as any); } catch {}
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

          // Check for bilateral response (type 8 = BilateralPrepareResponse)
          // Throttled: emit wallet.refresh only every Nth BLE envelope to avoid
          // flooding the bridge with balance+history queries (~50/sec without this).
          const uTx: any = (p?.case === 'universalTx' ? p.value : p?.universalTx);
          const bpResp: any = (p?.case === 'bilateralPrepareResponse' ? p.value : p?.bilateralPrepareResponse);
          if (uTx?.type === 8 || bpResp) {
            bleWalletRefreshCounter = (bleWalletRefreshCounter + 1) | 0;
            if ((bleWalletRefreshCounter % BLE_WALLET_REFRESH_EVERY) === 1) {
              bridgeEvents.emit('wallet.refresh', { source: 'bilateral.transfer_complete' });
            }
          }
          
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
