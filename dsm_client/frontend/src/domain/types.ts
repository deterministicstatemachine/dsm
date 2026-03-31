/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/domain/types.ts
// SPDX-License-Identifier: Apache-2.0

export type DomainIdentity = {
  genesisHash: string;
  deviceId: string;
};

export type DomainBalance = {
  tokenId: string;
  tokenName: string;
  balance: bigint;
  decimals: number;
  symbol: string;
};

export type DomainContact = {
  alias: string;
  deviceId: string;
  genesisHash: string;
  chainTip?: string;
  chainTipSmtProof?: unknown;
  bleAddress?: string;
  status?: string;
  needsOnlineReconcile?: boolean;
  genesisVerifiedOnline?: boolean;
  verifyCounter?: number;
  addedCounter?: number;
  verifyingStorageNodes?: number;
  signingPublicKey?: string;  // base32 Crockford encoded
};

export type DomainTransaction = {
  txId: string;
  type: 'online' | 'offline';
  amount: bigint;
  recipient: string;
  createdAt?: number;
  memo?: string;
  status: 'pending' | 'confirmed' | 'failed';
  syncStatus?: 'synced' | 'syncing' | 'unsynced' | undefined;
  txType?: string;
  txHash?: string;
  fromDeviceId?: string;
  toDeviceId?: string;
  amountSigned?: bigint;
  stitchedReceipt?: Uint8Array;
  receiptVerified?: boolean;
  tokenId?: string;
};
