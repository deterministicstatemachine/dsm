/* eslint-disable @typescript-eslint/no-explicit-any */
// path: dsm_client/new_frontend/src/dsm/events.ts
// SPDX-License-Identifier: Apache-2.0
// Shared event definitions to avoid circular dependencies between index.ts and EventBridge.ts

// Standard event payload for UI updates: emitted when a bilateral transfer has been committed
export interface BilateralCommittedEventDetail {
  // Bytes-only: protocol boundary must not depend on hex/json.
  // If UI needs display, compute Base32 at render-time.
  commitmentHash?: Uint8Array;
  counterpartyDeviceId?: Uint8Array;
  accepted?: boolean;
  committed?: boolean;
  rejected?: boolean;
}

/**
 * Canonical wallet refresh event.
 *
 * Determinism rule: there should be exactly ONE pathway to trigger a UI refresh.
 * All wallet mutation boundaries must emit ONLY this (coalesced) event.
 */
export const DSM_WALLET_REFRESH_EVENT = 'dsm-wallet-refresh' as const;

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

export function emitBilateralCommitted(detail?: BilateralCommittedEventDetail): void {
  bridgeEvents.emit('wallet.bilateralCommitted', detail ?? {});
}
