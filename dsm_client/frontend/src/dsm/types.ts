// SPDX-License-Identifier: MIT OR Apache-2.0

// Lightweight shared types for DSM UI flows and events
import * as pb from '../proto/dsm_app_pb';
import type { ContactPairing } from '../domain/types';

/**
 * A contact as `contacts.list` states it (pb-aligned, binary). Rust writes the
 * device id, genesis, signing key and alias on every contact.
 */
export interface BilateralRelationshipDTO {
  deviceId: Uint8Array;             // 32 bytes
  publicKey: Uint8Array;            // SPHINCS+ signing key, 64 bytes
  alias: string;
  genesisHash: Uint8Array;          // 32 bytes
  /** The relationship's tip, once it has one. */
  chainTip?: Uint8Array;            // 32 bytes
  bleAddress?: string;              // BLE MAC address for offline bilateral transfers
  pairing: ContactPairing;          // where BLE pairing stands, as Rust's pairing loop has it
  genesisVerifiedOnline: boolean;   // genesis hash verified via storage node
  sendStatus?: pb.RelationshipSendStatus;
}

/** UI-level transaction shape used by offlineSend. */
export type GenericTransaction = {
  tokenId: string;
  /** Base32 Crockford device id, or the raw 32 bytes. Both paths are
   *  implemented in offlineSend; the type said string only. */
  to: Uint8Array | string;
  amount: string | number | bigint;
  memo?: string;
};

/** UI-level response shape returned by offlineSend. */
export type GenericTxResponse = {
  accepted: boolean;
  /**
   * The screen stopped waiting while the step is still open: it completes when
   * the devices meet again, and until its confirm its proposer may cancel it.
   * Not a failure.
   */
  open?: boolean;
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
  /** Empty: Rust names the contact by its device. */
  alias: string;
  deviceId: Uint8Array;
  genesisHash: Uint8Array;
  signingPublicKey: Uint8Array;
}

/**
 * The card a contact code carries, as Rust read it (`contacts.readContactCode`).
 * Rust refuses a code that is not whole or names another network than this
 * device's.
 */
export interface ContactCard {
  deviceId: Uint8Array;
  genesisHash: Uint8Array;
  signingPublicKey: Uint8Array;
  network: string;
  /** The alias the card's owner suggests, when it names one. */
  preferredAlias?: string;
}

/**
 * One item `inbox.pull` found queued for this device, as Rust described it.
 * Rust writes the id and the preview on every item; `isStaleRoute` marks an
 * item found at the address derived from the contact's previous tip.
 */
export interface InboxItemView {
  id: string;
  preview: string;
  senderId?: string;
  isStaleRoute: boolean;
}

/**
 * Add Contact Result
 */
export type AddContactResult =
  /** The contact Rust added: its device (Base32) and the alias Rust stored. */
  | { accepted: true; contactId: string; alias: string }
  /** Rust's refusal, as Rust worded it. */
  | { accepted: false; error: string };

/**
 * One row of `balance.list`, as Rust reported it. Rust enriches every row at
 * its encoding boundary, so a row without its token, symbol, name or display
 * amount is refused, never filled in.
 */
export interface TokenBalanceView {
  /** The ticker the balance is projected under. Not an identity: see `canonicalTokenId`. */
  tokenId: string;
  symbol: string;
  tokenName: string;
  /** The available balance in base units. */
  baseUnits: bigint;
  decimals: number;
  /** Display form of `baseUnits`, rendered by Rust. Never computed here. */
  displayAmount: string;
  /** The token's canonical id, when Rust names one (registered tokens). */
  canonicalTokenId?: string;
  /** CPTA policy anchor, Base32 Crockford, rendered by Rust. Carried, never derived. */
  policyAnchorB32?: string;
  /** Short head of the anchor, for visual comparison before adopting. */
  anchorFingerprint?: string;
  /** The token policy's icon field, carried from Rust; the wallet draws the token's coin from it. */
  iconUrl?: string;
  /**
   * Whether Rust reports the token as one the protocol defines (ERA, dBTC).
   * Never decided here: a ticker is text, and a created token may read "ERA".
   */
  protocolDefined: boolean;
  /** The whole supply that will ever exist, rendered by Rust; absent when Rust holds none. */
  genesisSupplyDisplay?: string;
  /** What the committed policy permits, as Rust read it; absent when Rust holds no policy for the token. */
  permissions?: TokenPolicyPermissionsView;
}

/** The permission flags of a committed token policy, as Rust read them. */
export interface TokenPolicyPermissionsView {
  burnEnabled: boolean;
  transferable: boolean;
}

/**
 * Wallet history response DTO.
 * Transactions are mapped from proto TransactionInfo → DomainTransaction
 * at the envelope boundary (wallet.ts). No raw proto types leak past that point.
 */
export interface WalletHistory {
  transactions: import('../domain/types').DomainTransaction[];
}
