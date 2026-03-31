// Lightweight shared types for DSM UI flows and events
import * as pb from '../proto/dsm_app_pb';

export type DsmRawEvent = {
  type?: string;
  payload?: unknown;
  [k: string]: unknown;
};

export type ContactAddProgress = {
  kind: "contact:add:progress";
  step:
    | "qr:parsed"
    | "qr:validated"
    | "bridge:request_sent"
    | "storage:verifying"
    | "storage:verified_quorum"
    | "done";
  info?: Record<string, unknown>;
};

export type ContactAddSuccess = {
  kind: "contact:add:success";
  deviceId?: string; // base32 (Crockford)
  verifyingNodes?: string[];
  genesisHashBase32?: string;
};

export type ContactAddFailure = {
  kind: "contact:add:failure";
  error: string;
  info?: Record<string, unknown>;
};

export type ContactAddEvent = ContactAddProgress | ContactAddSuccess | ContactAddFailure;

export type DsmEventListener = (e: ContactAddEvent | DsmRawEvent) => void;

// Minimal structural type for the Android/iOS WebView bridge (or web stub)
export type DsmBridgeLike = object;

// Access the bridge defensively (SSR-safe) to avoid ReferenceErrors in non-DOM contexts
import { getBridgeInstance } from '../bridge/BridgeRegistry';
export const getDsmBridge = (): DsmBridgeLike | undefined => {
  try {
    return getBridgeInstance() as DsmBridgeLike | undefined;
  } catch {
    return undefined;
  }
};
// path: dsm_client/frontend/src/lib/types.ts
// SPDX-License-Identifier: Apache-2.0

// Strict discriminated result types for DSM API (protobuf-only boundary)
export type Ok<T>  = { success: true; data: T };
export type Err    = { success: false; error: { code: number; message: string; isRecoverable: boolean } };
export type Result<T> = Ok<T> | Err;

/**
 * Backend-verified ChainTip (pb-aligned).
 * Canonical fields only; any time-like info is audit-only and optional.
 */
export interface ChainTipDTO {
  tipHash: Uint8Array;            // Hash32 (32 bytes)
  stateNumber?: bigint;           // u64 - may not be available initially
  deviceId?: Uint8Array;          // 32 bytes - may not be available initially
  counterpartyId?: Uint8Array;    // 32 bytes - may not be available initially
  bilateralChainId?: string;      // string id (proto) - may not be available initially
  anchored?: boolean;             // storage-node confirmation - defaults to false
  anchorReceiptId?: string;       // optional external anchor ref
  lastAnchorAttempt?: bigint;     // u64 audit-only counter/index (NOT wall-clock)
  failedAnchorAttempts?: number;  // u32 - defaults to 0
  auditTickMs?: bigint;           // OPTIONAL, UI-only; never hashed
}

/**
 * Bilateral relationship view (pb-aligned).
 * No hex/base64 at the boundary; binary everywhere.
 */
export interface BilateralRelationshipDTO {
  deviceId: Uint8Array;             // 32 bytes device id
  publicKey: Uint8Array;          // raw PQ key bytes
  alias: string;            // user label
  genesisHash?: Uint8Array;       // 32 bytes genesis hash (if known)
  lastSeenTick?: bigint;          // canonical progress indicator (no clocks)
  chainTip?: ChainTipDTO;         // current bilateral tip
  bleAddress?: string;           // BLE MAC address for offline bilateral transfers
  genesisVerifiedOnline?: boolean; // genesis hash verified via storage node
  addedCounter?: bigint;           // commit height when contact was added
}

export interface BilateralRelationshipsListDTO {
  relationships: BilateralRelationshipDTO[];
  totalCount?: number;
}

/**
 * Token balance in base units (no FP).
 */
export interface BalanceDTO {
  tokenId: string;                // canonical token id (proto string)
  baseUnits: bigint;              // u128 as bigint (amount)
  decimals: number;               // display hint (e.g., ERA=8)
  symbol?: string;                // optional UI hint
}

/**
 * Deterministic transaction shape (pb-aligned).
 * No time fields in canon; optional audit tick is UI-only.
 */
export interface TransactionDTO {
  hash: Uint8Array;               // 32 bytes
  amount: bigint;                 // s128/u128 normalized to bigint
  from: Uint8Array;               // 32 bytes device id
  to: Uint8Array;                 // 32 bytes device id
  tokenId: string;                // token id
  fee?: bigint;                   // optional fee in base units
  logicalIndex?: bigint;          // device-local deterministic counter
  type: 'transfer' | 'mint' | 'burn';
  auditTickMs?: bigint;           // OPTIONAL UI-only
}

export interface TransactionHistoryDTO {
  transactions: TransactionDTO[];
  totalCount?: number;
  hasMore?: boolean;
}

/**
 * Platform status (transport/UI only).
 */
export interface BluetoothStatusDTO {
  enabled: boolean;
  scanning: boolean;
  advertising: boolean;
  available: boolean;
}

/**
 * Genesis/identity summary (pb-aligned).
 * Avoid clocks; include optional UI audit tick separately.
 */
export interface GenesisDTO {
  genesis_hash: Uint8Array;       // 32 bytes
  identity_created: boolean;
  chainIndex?: bigint;            // optional deterministic index
  auditTickMs?: bigint;           // OPTIONAL UI-only
}

// Testnet faucet for token distribution.

/**
 * Unilateral inbox check (UI helper).
 */
export interface B0xCheckDTO {
  pending_transactions: TransactionDTO[];
  inbox_available: boolean;
}

export interface NetworkStatusDTO {
  connected: boolean;
  latency?: number;               // UI-only hint
}

/** UI-level transaction shape used by sendOnlineTransfer/offlineSend. */
export type GenericTransaction = {
  tokenId: string;
  to: string; // Base32 Crockford device id
  amount: string | number | bigint;
  memo?: string;
  bleAddress?: string;
};

/** UI-level response shape returned by sendOnlineTransfer/offlineSend. */
export type GenericTxResponse = {
  accepted: boolean;
  result?: string;
  txHash?: string;
  newBalance?: bigint;
  failureReason?: pb.BilateralFailureReason;
};

/**
 * Storage Node Status View
 */
export interface StorageStatus {
  nodeId: string;
  isReachable: boolean;
  latencyMs: number;
  lastSyncTick?: bigint; // logical tick
  storageUsedBytes: number;
  quotaBytes: number;
  isPaid: boolean;
  subscriptions: Array<{
    topic: string;
    expiresAtTick: bigint;
  }>;
  // Proto StorageStatusResponse fields (used by StorageScreen overview)
  totalNodes?: number;
  connectedNodes?: number;
  dataSize?: string;
  backupStatus?: string;
}

/**
 * Deterministic Limbo Vault (DLV) index entry
 */
export interface DlvIndexEntry {
  vaultId: string;
  createdAtTick: bigint;
  status: 'locked' | 'unlocked' | 'expired' | 'LOCKED' | 'UNLOCKABLE' | 'LIVE' | 'SPENT' | 'EXPIRED';
  balance: BalanceDTO;
  conditions: Array<{
    type: string;
    description: string;
    isMet: boolean;
  }>;
  cptaAnchorHex: string;
  expectedReplication: number;
  localLabel: string;
  kind: string;
}

/**
 * Wallet History Item
 */
export interface WalletHistoryItem {
  id: string;
  type: 'send' | 'receive' | 'mint' | 'burn';
  amount: BalanceDTO;
  counterparty: string;
  status: 'pending' | 'completed' | 'failed';
  date: Date;
  txHash: string;
}

/**
 * Wallet Inbox Item (Pending Actions)
 */
export interface WalletInboxItem {
  id: string;
  type: 'ble_request' | 'payment_request' | 'contact_request';
  from: string;
  summary: string;
  receivedAt: Date;
  expiresAt?: Date;
  actions: Array<{
    label: string;
    actionId: string;
    isPrimary: boolean;
  }>;
}

// -- Missing Types from Refactor --

/**
 * Identity information
 */
export interface IdentityInfo {
  deviceId: string; // Base32
  deviceEntropy: string; // Hex or B32
  isRegistered: boolean;
  genesisHash: string; // Base32
  networkId: string;
}

/**
 * Contacts List (Wrapper)
 */
export interface ContactsList {
  contacts: BilateralRelationshipDTO[];
  total: number;
}

/**
 * Add Contact Arguments
 */
export interface AddContactArgs {
  alias: string;
  deviceId: Uint8Array | string;
  genesisHash: Uint8Array | string;
  signingPublicKey: Uint8Array | string;
}

/**
 * Add Contact Result
 */
export interface AddContactResult {
  accepted: boolean;
  contactId?: string; // Base32 DeviceID
  error?: string;
}

/**
 * Token Balance View (UI Friendly)
 */
export interface TokenBalanceView {
  tokenId: string; // string id
  ticker: string;
  balance: string; // formatted decimal string
  baseUnits: bigint;
  decimals: number;
  symbol: string;
  tokenName?: string;
}

/**
 * Wallet history response DTO.
 * Transactions are mapped from proto TransactionInfo → DomainTransaction
 * at the envelope boundary (wallet.ts). No raw proto types leak past that point.
 */
export interface WalletHistory {
  transactions: import('../domain/types').DomainTransaction[];
}
