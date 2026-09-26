/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/domain/types.ts
// SPDX-License-Identifier: Apache-2.0

export type DomainIdentity = {
  genesisHash: string;
  deviceId: string;
};

export type DomainRelationshipSendCheckState = 'checking' | 'ready' | 'blocked';

export type DomainRelationshipSendBlockReason =
  | 'pending_catchup'
  | 'state_divergence'
  | 'internal_error';

export type DomainRelationshipSendStatus = {
  sendReady: boolean;
  sendCheckState?: DomainRelationshipSendCheckState;
  sendBlockReason?: DomainRelationshipSendBlockReason;
  sendBlockMessage?: string;
};

/** Where BLE pairing with a contact stands, as Rust's pairing loop has it. */
export type ContactPairing = 'paired' | 'idle' | 'searching' | 'connected' | 'retrying';

export type DomainContact = {
  alias: string;
  deviceId: string;
  genesisHash: string;
  chainTip?: string;
  bleAddress?: string;
  pairing: ContactPairing;
  genesisVerifiedOnline: boolean;
  signingPublicKey: string;  // base32 Crockford encoded
  sendReady?: boolean;
  sendCheckState?: DomainRelationshipSendCheckState;
  sendBlockReason?: DomainRelationshipSendBlockReason;
  sendBlockMessage?: string;
};

/** The history types Rust writes (`TransactionInfo.tx_type`). */
export type DomainTxType = 'faucet' | 'bilateral_offline' | 'online' | 'dbtc_mint' | 'dbtc_burn';

/**
 * One wallet history row, exactly as `wallet.history` reports it. Every
 * field is Rust's; nothing here is inferred, defaulted or re-derived.
 */
export type DomainTransaction = {
  txId: string;
  /** Base32 Crockford. */
  txHash: string;
  txType: DomainTxType;
  /** A transfer's transport; a dBTC deposit or withdrawal has none. */
  type?: 'online' | 'offline';
  /** Signed base units, as Rust signed it: negative is outgoing. */
  amount: bigint;
  /** Signed display form rendered by Rust. Never computed in this layer. */
  displayAmount: string;
  tokenId: string;
  /** The counterparty as Rust labels it (alias or device id). */
  recipient: string;
  /** Rust's word for the row's state. */
  status: string;
  /**
   * Base32 Crockford. Absent for a faucet row: its source is the ERA reserve,
   * not a device, and Rust names none.
   */
  fromDeviceId?: string;
  /** Base32 Crockford. */
  toDeviceId: string;
  memo?: string;
  stitchedReceipt?: Uint8Array;
  receiptVerified: boolean;
};
