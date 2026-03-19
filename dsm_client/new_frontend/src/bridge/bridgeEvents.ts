/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/bridge/bridgeEvents.ts
// SPDX-License-Identifier: Apache-2.0

import type { NativeSessionSnapshot } from '../runtime/nativeSessionTypes';

export type BridgeEventMap = {
  'session.state': NativeSessionSnapshot;
  'identity.ready': void;
  'wallet.refresh': { source: string; [k: string]: any };
  'wallet.bilateralCommitted': { commitmentHash?: Uint8Array; counterpartyDeviceId?: Uint8Array; accepted?: boolean; committed?: boolean; rejected?: boolean };
  'wallet.historyUpdated': void;
  'wallet.balancesUpdated': void;
  'wallet.sendCommitted': { success?: boolean; tokenId?: string; newBalance?: bigint | string | number; transactionHash?: Uint8Array; toDeviceId?: Uint8Array; amount?: bigint | string | number };
  'dsm.deterministicSafety': { classification: string; message?: string };
  'contact.added': { contact?: unknown };
  'contact.bleMapped': { address: string; deviceId?: string; genesisHash?: string };
  'contact.bleUpdated': { bleAddress?: string; alias?: string; deviceId?: string; genesisHash?: string };
  'contact.reconcileNeeded': { deviceId?: string; message?: string };
  'bilateral.event': Uint8Array;
  'bilateral.transferComplete': void;
  'env.config.error': { message: string };
  'bridge.error': { code?: number; message: string; debugB32: string };
  'port.tx': void;
  'port.rx': void;
  'ui.tick': void;
  'inbox.open': { open: boolean };
  'inbox.updated': { unreadCount: number; newItems?: number; source: string };
  'visibility.change': { state: DocumentVisibilityState };
  'ble.permission.error': { message: string };
  'ble.permission.recovery.needed': void;
  'ble.features.disabled': void;
  'ble.deviceFound': { address: string; name: string; rssi: number };
  'ble.scanStarted': void;
  'ble.scanStopped': void;
  'ble.deviceConnected': { address: string };
  'ble.deviceDisconnected': { address: string };
  'ble.connectionFailed': { reason: string };
  'ble.advertisingStarted': void;
  'ble.advertisingStopped': void;
  'ble.pairingStatus': { deviceId: string; status: string; message: string; bleAddress?: string };
  'deposit.completed': { depositId: string; amount: string };
  'wallet.exitCompleted': { source: string };
  // NFC ring backup domain
  'nfc.backupWritten': void;
  'nfc.writeStarted': void;
};

type Handler<T> = (payload: T) => void;

type EventKey = keyof BridgeEventMap;

class BridgeEventBus {
  private listeners = new Map<EventKey, Set<Handler<any>>>();

  on<K extends EventKey>(event: K, handler: Handler<BridgeEventMap[K]>): () => void {
    const set = this.listeners.get(event) ?? new Set();
    set.add(handler as Handler<any>);
    this.listeners.set(event, set);
    return () => this.off(event, handler);
  }

  off<K extends EventKey>(event: K, handler: Handler<BridgeEventMap[K]>): void {
    const set = this.listeners.get(event);
    if (!set) return;
    set.delete(handler as Handler<any>);
  }

  emit<K extends EventKey>(event: K, payload: BridgeEventMap[K]): void {
    const set = this.listeners.get(event);
    if (!set || set.size === 0) return;
    for (const handler of Array.from(set)) {
      try { (handler as Handler<BridgeEventMap[K]>)(payload); } catch {}
    }
  }
}

export const bridgeEvents = new BridgeEventBus();
