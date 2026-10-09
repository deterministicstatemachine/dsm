/* eslint-disable @typescript-eslint/no-explicit-any */
// path: dsm_client/frontend/src/dsm/events.ts
// SPDX-License-Identifier: Apache-2.0
// Shared event definitions to avoid circular dependencies between index.ts and EventBridge.ts

// Emitted once the accept of an offline transfer has been sent. The transfer
// is not committed by then: the peer's confirm arrives later as a BLE event.
export interface BilateralAcceptedEventDetail {
  // Bytes-only: protocol boundary must not depend on hex/json.
  // If UI needs display, compute Base32 at render-time.
  commitmentHash: Uint8Array;
  counterpartyDeviceId: Uint8Array;
}

/**
 * Canonical wallet refresh event: `wallet.refresh` on the bus.
 *
 * Determinism rule: there is exactly ONE pathway to trigger a UI refresh.
 * All wallet mutation boundaries emit ONLY this (coalesced) event.
 */
export type WalletRefreshDetail = {
  /** Where the mutation originated (e.g. 'wallet.send', 'storage.sync', 'bilateral.commit'). */
  source: string;
  /** Optional identifiers for debugging/targeted refresh. */
  transactionHash?: Uint8Array;
  commitmentHash?: Uint8Array;
  counterpartyDeviceId?: Uint8Array;
  /** Optional carry-through payload for sync stats, etc. */
  [k: string]: any;
};

import { bridgeEvents } from '../bridge/bridgeEvents';

export function emitWalletRefresh(detail: WalletRefreshDetail): void {
  bridgeEvents.emit('wallet.refresh', detail);
}

export function emitBilateralAccepted(detail: BilateralAcceptedEventDetail): void {
  bridgeEvents.emit('wallet.bilateralAccepted', detail);
}
