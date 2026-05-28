// SPDX-License-Identifier: MIT OR Apache-2.0

// ============================================================================
// DSM APP INTEGRATION BOUNDARY — Public API Surface
// ============================================================================
//
// This barrel file is the public API for frontend consumers of the DSM stack.
// Import from 'dsm/' to access the exported domain modules below.
//
// MODULE MAP (kept in sync with the `export * from './<name>'` lines below):
//   types         — TypeScript types for State, Token, Policy, etc.
//   crypto        — Client-side crypto utilities (hashing, encoding)
//   resolution    — Name/address resolution
//   identity      — Device identity, genesis, pairing
//   contacts      — Contact management (device IDs, metadata)
//   wallet        — Balance queries, transaction history
//   policies      — Token policy management (CPTA)
//   dlv           — Deterministic Limbo Vaults (sovereign finance primitives)
//   storage       — Storage node communication
//   transactions  — Bilateral/unilateral transfer logic
//   diagnostics   — telemetry, debug
//   nfc           — NFC ring backup (write/read recovery capsules)
//
// BRIDGE HELPER RE-EXPORTS (not part of the curated `dsmClient` namespace):
//   eventBridgeOn / eventBridgeEmit  — pub/sub on the native bridge
//   getBridgeInstance                — bridge handle accessor
//
// CURATED FLAT NAMESPACE EXPORT (`dsmClient`):
//   `dsmClient` exposes a curated, object-style API combining the modules
//   that need name-collision-free access: identity, contacts, wallet,
//   policies, dlv, storage, transactions, diagnostics, resolution, nfc.
//   It intentionally OMITS `crypto` and `types` (too generic to flatten
//   safely) and the bridge-helper re-exports above (imported by name).
//
// All exports ultimately call through WebViewBridge.ts (protobuf-only).
// See docs/INTEGRATION_GUIDE.md for the full developer onboarding guide.
// ============================================================================

// Export core types
export * from './types';

// Export crypto utilities
export * from './crypto';

// Export resolution logic
export * from './resolution';

// Export domain-specific logic
export * from './identity';
export * from './contacts';
export * from './wallet';
export * from './policies';
export * from './dlv';
export * from './storage';
export * from './transactions';
export * from './diagnostics';
export * from './nfc';

// Re-export bridge helpers used by external consumers.
import { 
  on as eventBridgeOn, 
  emit as eventBridgeEmit 
} from './EventBridge';
import { 
  getBridgeInstance 
} from '../bridge/BridgeRegistry';

export { eventBridgeOn, eventBridgeEmit, getBridgeInstance };

import * as Identity from './identity';
import * as Contacts from './contacts';
import * as Wallet from './wallet';
import * as Policies from './policies';
import * as Dlv from './dlv';
import * as Storage from './storage';
import * as Transactions from './transactions';
import * as Diagnostics from './diagnostics';
import * as Nfc from './nfc';
import * as Resolution from './resolution';

// Flat namespace export for consumers that prefer object-style access.
export const dsmClient = {
  ...Identity,
  ...Contacts,
  ...Wallet,
  ...Policies,
  ...Dlv,
  ...Storage,
  ...Transactions,
  ...Diagnostics,
  ...Resolution,
  ...Nfc,
};
