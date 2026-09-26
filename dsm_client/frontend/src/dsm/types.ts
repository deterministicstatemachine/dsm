// SPDX-License-Identifier: MIT OR Apache-2.0

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
  chainTip?: ChainTipDTO;         // current bilateral tip
  bleAddress?: string;           // BLE MAC address for offline bilateral transfers
  genesisVerifiedOnline?: boolean; // genesis hash verified via storage node
  sendStatus?: pb.RelationshipSendStatus;
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
  type: 'transfer' | 'mint' | 'burn';
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
  /** Base32 Crockford device id, or the raw 32 bytes. Both paths are
   *  implemented in offlineSend/sendOnlineTransfer; the type said string only. */
  to: Uint8Array | string;
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
 * What a member of the pinned storage set answered when the SDK asked for its
 * latest ByteCommit. An observation, never a verdict: a member that did not
 * answer has not failed, and a ByteCommit is as the member stated it.
 */
export type StorageMemberAnswer =
  | {
      kind: 'latest';
      cycle: bigint;
      bytesUsed: bigint;
      rootB32: string;
      parentB32: string;
      /** d_t, computed by Core from the commit's fields. */
      digestB32: string;
    }
  | { kind: 'noCycle' }
  | { kind: 'unanswered'; why: string };

/** One member of the pinned storage set, as `storage.status` reports it. */
export interface StorageMember {
  /** The member id exactly as the set commits it. */
  memberId: string;
  registerIncarnationB32: string;
  /** Transport only; resolved outside committed state. */
  endpoint: string;
  answer: StorageMemberAnswer;
  /** The member id the answering node echoed, when it echoed one. */
  answeredAs?: string;
}

/** `storage.status`: the storage set this device's traffic uses. */
export interface StorageStatus {
  networkId: string;
  storageSetIdB32: string;
  /** In the set's member order. */
  members: StorageMember[];
  /** `storage.sync` runs that ran to their end on this device. */
  completedSyncs: bigint;
  /** The size of this device's database file. */
  databaseBytes: bigint;
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
 * The device's identity as its transport headers carry it.
 */
export interface IdentityInfo {
  deviceId: string; // Base32
  genesisHash: string; // Base32
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
  /** Display form of `baseUnits`, rendered by Rust. Never computed here. */
  displayAmount?: string;
  /** The token's canonical id. `tokenId` on the wire is the TICKER, which is not an identity. */
  canonicalTokenId?: string;
  /** CPTA policy anchor, Base32 Crockford, rendered by Rust. Carried, never derived. */
  policyAnchorB32?: string;
  /** Short head of the anchor, for visual comparison before adopting. */
  anchorFingerprint?: string;
  /** The token policy's icon field, carried from Rust; the wallet draws the token's coin from it. */
  iconUrl?: string;
}

/**
 * Wallet history response DTO.
 * Transactions are mapped from proto TransactionInfo → DomainTransaction
 * at the envelope boundary (wallet.ts). No raw proto types leak past that point.
 */
export interface WalletHistory {
  transactions: import('../domain/types').DomainTransaction[];
}
