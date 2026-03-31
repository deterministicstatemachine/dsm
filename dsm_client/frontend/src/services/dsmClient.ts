/* eslint-disable @typescript-eslint/no-explicit-any */
/*
  DSM client wrapper for WebView bridge calls with identity gating.
  - Public methods ensure identity exists before performing contact- and wallet-dependent calls.
  - Bridge and schema failures are surfaced to callers instead of being converted to synthetic defaults.
*/
import { hasIdentity } from '../utils/identity';
import { getBridgeInstance } from '../bridge/BridgeRegistry';
import { mapBalanceList, mapContactList, mapIdentity } from '../domain/mappers';
import type { DomainBalance, DomainContact, DomainIdentity, DomainTransaction } from '../domain/types';
import { fromBase32Crockford } from '../dsm/decoding';
import * as dsm from '../dsm/index';
import { decodeBase32Crockford } from '../utils/textId';
import { TokenPolicyV3 } from '../proto/dsm_app_pb';
import { nativeSessionStore } from '../runtime/nativeSessionStore';

export type ContactsResponse = {
  contacts: DomainContact[];
};

function isBinaryBridgeReady(): boolean {
  const bridge = getBridgeInstance();
  if (!bridge || bridge.__binary !== true) {
    return false;
  }

  if (typeof bridge.isAvailable === 'function') {
    return bridge.isAvailable();
  }

  return typeof bridge.sendMessageBin === 'function' || typeof bridge.__callBin === 'function';
}

export class DsmClient {
  // Identity helpers
  async isReady(): Promise<boolean> {
    if (!isBinaryBridgeReady()) {
      return false;
    }

    const session = nativeSessionStore.getSnapshot();
    if (session.received) {
      return session.identity_status === 'ready';
    }
    return hasIdentity();
  }

  async getIdentity(): Promise<DomainIdentity | null> {
    if (!(await this.isReady())) {
      return null;
    }

    if (typeof dsm.getIdentity !== 'function') {
      throw new Error('getIdentity not available on this build');
    }
    const raw = await dsm.getIdentity();
    return mapIdentity(raw);
  }

  // Wallet history (for Transactions screen)
  // mapTransactions() is applied at the envelope boundary in wallet.ts —
  // no redundant re-mapping here.
  async getWalletHistory(): Promise<{ transactions: DomainTransaction[] }> {
    if (!(await this.isReady())) {
      throw new Error('Identity not initialized');
    }

    const fn: any = (dsm as any).getWalletHistory;
    if (typeof fn !== 'function') {
      throw new Error('getWalletHistory not available on this build');
    }
    const v = await fn();
    if (!v || !Array.isArray((v as any).transactions)) {
      throw new Error('Invalid wallet history response');
    }
    return { transactions: (v as any).transactions };
  }
  async getLogicalTick(): Promise<bigint> {
    if (!(await this.isReady())) throw new Error('Identity not initialized');

    return dsm.getLogicalTick();
  }

  // Contacts
  async getContacts(): Promise<ContactsResponse> {
    if (!(await this.isReady())) {
      throw new Error('Identity not initialized');
    }


    if (typeof dsm.getContacts !== 'function') {
      throw new Error('getContacts not available on this build');
    }
    const out = await dsm.getContacts();
    if (!out || !Array.isArray((out as any).contacts)) {
      throw new Error('Invalid contacts response');
    }
    const snapshot = typeof dsm.getBleIdentitySnapshot === 'function' ? dsm.getBleIdentitySnapshot() : undefined;
    return { contacts: mapContactList((out as any).contacts, snapshot) };
  }

  async addContact(input: { alias: string; genesisHash: string | Uint8Array; deviceId: string | Uint8Array; signingPublicKey: string | Uint8Array }): Promise<{ ok: boolean }>
  {
    if (!(await this.isReady())) {
      return { ok: false };
    }


    if (typeof dsm.addContact !== 'function') {
      throw new Error('Bridge not available');
    }
    const normalize32 = (value: string | Uint8Array, label: string): Uint8Array => {
      if (value instanceof Uint8Array) {
        if (value.length !== 32) throw new Error(`${label} must be 32 bytes`);
        return value;
      }
      const bytes = fromBase32Crockford(String(value));
      if (bytes.length !== 32) throw new Error(`${label} must be 32 bytes`);
      return bytes;
    };
    const normalize64 = (value: string | Uint8Array, label: string): Uint8Array => {
      if (value instanceof Uint8Array) {
        if (value.length !== 64) throw new Error(`${label} must be 64 bytes`);
        return value;
      }
      const bytes = fromBase32Crockford(String(value));
      if (bytes.length !== 64) throw new Error(`${label} must be 64 bytes`);
      return bytes;
    };

    const res = await dsm.addContact({
      alias: input.alias,
      deviceId: normalize32(input.deviceId, 'device_id'),
      genesisHash: normalize32(input.genesisHash, 'genesis_hash'),
      signingPublicKey: normalize64(input.signingPublicKey, 'signingPublicKey'),
    });
    return { ok: res.accepted !== false };
  }

  async handleContactQrV3(payload: string): Promise<{ ok: boolean }>
  {
    if (!(await this.isReady())) {
      throw new Error('Identity not initialized');
    }

    // Strict path: use dsm/fullFlow ContactQrV3 pipeline (binary only).
    const fullFlow = await import('../dsm/fullFlow');
    const _controller = fullFlow.startAddContactFlow({ qr: payload });
    // The flow reports completion details via events.
    return { ok: true };
  }

  async sendOnlineTransfer(params: {
    tokenId: string;
    to: string | Uint8Array;
    amount: number | bigint | string;
    memo?: string;
  }): Promise<{ success: boolean; message?: string; transactionHash?: string; newBalance?: bigint }> {
    if (!(await this.isReady())) {
      return { success: false, message: 'Identity not initialized' };
    }

    const res = await (dsm as any).sendOnlineTransfer(params);
    return {
      success: Boolean(res?.accepted),
      message: String(res?.result ?? ''),
      transactionHash: typeof res?.txHash === 'string' ? res.txHash : undefined,
      newBalance: res?.newBalance,
    };
  }

  async sendOnlineTransferSmart(
    recipientAlias: string,
    scaledAmountStr: string | number | bigint,
    memo?: string,
    tokenId?: string
  ): Promise<{ success: boolean; newBalance?: bigint; error?: { message?: string } }> {
    if (!(await this.isReady())) {
      return { success: false, error: { message: 'Identity not initialized' } };
    }

    // Delegate to dsm/transactions.ts:sendOnlineTransferSmart() which calls
    // the Rust wallet.sendSmart handler with proper deterministic nonce generation.

    const res = await dsm.sendOnlineTransferSmart(recipientAlias, scaledAmountStr, memo, tokenId);
    return {
      success: Boolean(res?.success),
      newBalance: res?.newBalance,
      error: res?.success ? undefined : { message: res?.message || 'Online transfer failed' },
    };
  }

  async offlineSend(params: {
    tokenId: string;
    to: Uint8Array;
    amount: number | bigint | string;
    memo?: string;
    // Optional hint for platform BLE routing; ignored by core implementation if unused.
    bleAddress?: string;
  }): Promise<{
    success: boolean;
    message?: string;
    transactionId?: string;
    failureReason?: import('../proto/dsm_app_pb').BilateralFailureReason;
  }> {
    if (!(await this.isReady())) {
      throw new Error('Identity not initialized');
    }
    // Use the universal dsm module for bilateral prepare

    const res = await (dsm as any).offlineSend(params);
    return {
      success: Boolean(res?.accepted),
      message: String(res?.result ?? ''),
      transactionId: undefined,
      failureReason: res?.failureReason,
    };
  }

  async getAllBalances(): Promise<DomainBalance[]> {
    if (!(await this.isReady())) {
      throw new Error('Identity not initialized');
    }

    const fn: any = (dsm as any).getAllBalances;
    if (typeof fn !== 'function') {
      throw new Error('getAllBalances not available on this build');
    }
    const res = await fn();
    if (!Array.isArray(res)) {
      throw new Error('Invalid balances response');
    }
    return mapBalanceList(res);
  }

  // Alias used by EnhancedWalletScreen
  async sendOfflineTransfer(params: {
    tokenId: string;
    to: string;
    amount: number | bigint | string;
    memo?: string;
    bleAddress?: string;
  }): Promise<{
    success: boolean;
    message?: string;
    transactionId?: string;
    failureReason?: import('../proto/dsm_app_pb').BilateralFailureReason;
  }> {
    // Convert Base32 Crockford device_id to Uint8Array (no hex)
    const toBytes = fromBase32Crockford(params.to);

    return this.offlineSend({
      tokenId: params.tokenId,
      to: toBytes,
      amount: params.amount,
      memo: params.memo,
      bleAddress: params.bleAddress,
    });
  }

  async acceptBilateralTransfer(params: { commitmentHash: Uint8Array; counterpartyDeviceId: Uint8Array }): Promise<{ success: boolean; message?: string }> {
    if (!(await this.isReady())) {
      return { success: false, message: 'Identity not initialized' };
    }

    return dsm.acceptOfflineTransfer(params);
  }

  async resolveBleAddressForContact(contact: DomainContact): Promise<string | undefined> {

    if (typeof dsm.resolveBleAddressForContact !== 'function') return undefined;
    return await dsm.resolveBleAddressForContact({
      bleAddress: contact.bleAddress,
      deviceId: contact.deviceId,
      genesisHash: contact.genesisHash,
    });
  }

  async commitBilateralTransfer(params: { commitmentHash: Uint8Array; counterpartyDeviceId: Uint8Array }): Promise<{ success: boolean; message?: string }> {
    if (!(await this.isReady())) {
      return { success: false, message: 'Identity not initialized' };
    }

    return dsm.commitOfflineTransfer(params);
  }

  async rejectBilateralTransfer(params: { commitmentHash: Uint8Array; counterpartyDeviceId: Uint8Array; reason?: string }): Promise<{ success: boolean; message?: string }> {
    if (!(await this.isReady())) {
      return { success: false, message: 'Identity not initialized' };
    }

    return dsm.rejectOfflineTransfer(params);
  }

  async claimFaucet(tokenId?: string): Promise<{ success: boolean; message?: string; tokensReceived?: number }> {
    if (!(await this.isReady())) {
      return { success: false, message: 'Identity not initialized' };
    }
    try {
      const fn = (dsm as any).claimFaucet;
      if (typeof fn !== 'function') {
        return { success: false, message: 'claimFaucet not available on this build' };
      }
      const res = await fn(tokenId || '');
      // Normalize possible shapes.
      if (res && typeof res === 'object') {
        if (typeof (res as any).success === 'boolean') return res;
        if (typeof (res as any).ok === 'boolean') return { success: Boolean((res as any).ok), message: (res as any).message };
      }
      return { success: true };
    } catch (e: any) {
      return { success: false, message: e?.message || 'claimFaucet failed' };
    }
  }

  async syncWithStorage(params: { pullInbox: boolean; pushPending: boolean; limit: number }): Promise<{ success: boolean; processed?: number; message?: string }> {
    if (!(await this.isReady())) {
      return { success: false, message: 'Identity not initialized' };
    }
    try {
      const fn = (dsm as any).syncWithStorage;
      if (typeof fn !== 'function') {
        return { success: false, message: 'syncWithStorage not available on this build' };
      }
      return await fn(params);
    } catch (e: any) {
      return { success: false, message: e?.message || 'syncWithStorage failed' };
    }
  }

  async getBluetoothStatus(): Promise<{ enabled?: boolean } | null> {
    const fn = (dsm as any).getBluetoothStatus;
    if (typeof fn !== 'function') {
      throw new Error('getBluetoothStatus not available on this build');
    }
    return await fn();
  }

  subscribeBleEvents?(callback: (detail: Record<string, unknown>) => void): (() => void) | undefined {
    if (typeof dsm.subscribeBleEvents !== 'function') return undefined;
    return dsm.subscribeBleEvents(callback as any);
  }

  async setPreference(key: string, value: string): Promise<void> {

    if (typeof dsm.setPreference !== 'function') {
      throw new Error('Bridge not available');
    }
    await dsm.setPreference(key, value);
  }

  async getPreference(key: string): Promise<string | null> {

    if (typeof dsm.getPreference !== 'function') {
      throw new Error('Bridge not available');
    }
    return await dsm.getPreference(key);
  }

  // Dev / Policy Tools
  async publishTokenPolicy(input: { policyBase32: string }): Promise<{ success: boolean; id?: string; error?: string }> {
    if (!(await this.isReady())) {
      return { success: false, error: 'Identity not initialized' };
    }
    const hasB32 = typeof input?.policyBase32 === 'string' && input.policyBase32.trim().length > 0;
    if (!hasB32) {
      return { success: false, error: 'policy bytes required (base32)' };
    }

    try {
      const bytes = decodeBase32Crockford(input.policyBase32.trim());
      if (!bytes || bytes.length === 0) {
        return { success: false, error: 'decoded policy bytes empty' };
      }

      // Validate that payload is a TokenPolicyV3 proto; re-encode to canonical bytes.
      const policy = TokenPolicyV3.fromBinary(bytes);
      const canonicalBytes = policy.toBinary();

      const out = await dsm.publishTokenPolicyBytes(canonicalBytes);
      return { success: true, id: out.anchorBase32 };
    } catch (e: any) {
      return { success: false, error: e?.message || 'Policy publish failed' };
    }
  }

  async importTokenPolicy(input: { anchorBase32: string }): Promise<{ success: boolean; error?: string }> {
    if (!(await this.isReady())) {
      return { success: false, error: 'Identity not initialized' };
    }
    const hasB32 = typeof input?.anchorBase32 === 'string' && input.anchorBase32.trim().length > 0;
    if (!hasB32) return { success: false, error: 'anchor id required' };
    

    try {
      const anchor = decodeBase32Crockford(input.anchorBase32.trim());
      if (anchor.length !== 32) return { success: false, error: 'Invalid anchor length' };
      
      // Just fetching it will cache it locally, making it available to usePolicies etc.
      await dsm.getTokenPolicyBytes(anchor);
      return { success: true };
    } catch (e: any) {
      return { success: false, error: e?.message || 'Policy import failed' };
    }
  }

  async createToken(params: {
    ticker: string;
    alias: string;
    decimals: number;
    maxSupply: string;
    kind?: 'FUNGIBLE' | 'NFT' | 'SBT';
    description?: string;
    iconUrl?: string;
    unlimitedSupply?: boolean;
    initialAlloc?: string;
    mintBurnEnabled?: boolean;
    mintBurnThreshold?: number;
    transferable?: boolean;
    allowlistKind?: 'NONE' | 'INLINE';
    allowlistData?: string;
  }): Promise<{ success: boolean; result?: { success: boolean; tokenId?: string; anchorBase32?: string; message?: string }; error?: string }> {
    if (!(await this.isReady())) return { success: false, error: 'Identity not initialized' };
    try {
  
      const res = await (dsm as any).createToken(params);
      if (res && typeof res === 'object' && 'success' in res) {
        return { success: Boolean((res as any).success), result: res };
      }
      return { success: Boolean(res), result: res };
    } catch (e: any) {
      return { success: false, error: e.message };
    }
  }

  async createCustomDlv(params: {
    lock: string;
    condition?: string;
  }): Promise<{ success: boolean; id?: string; error?: string }> {
    if (!(await this.isReady())) return { success: false, error: 'Identity not initialized' };
    try {
      return await dsm.createCustomDlv(params);
    } catch (e: any) {
      return { success: false, error: e?.message || 'createCustomDlv failed' };
    }
  }

  async listPolicies(): Promise<unknown> {

    if (typeof dsm.listPolicies !== 'function') {
      throw new Error('listPolicies not available on this build');
    }
    return await dsm.listPolicies();
  }
}

// Re-export the canonical dsmClient from '@/dsm/index' so tests that mock
// '../../dsm/index' can override methods via jest.fn(). The class DsmClient
// remains available for identity-gated, direct usage in other tests.
export { dsmClient } from '../dsm/index';
