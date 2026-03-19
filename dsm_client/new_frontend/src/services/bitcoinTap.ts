/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Bitcoin Tap Service Layer
 *
 * TypeScript service functions for the dBTC Bitcoin integration.
 * Each function wraps a binary protobuf call to the Rust app router
 * via the existing WebViewBridge.
 */

import { appRouterQueryBin, appRouterInvokeBin } from '../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';
import logger from '../utils/logger';

/** Log and throw a Bitcoin service error so it appears in DevTools console. */
function btcError(route: string, msg: string): never {
  const full = `${route} failed: ${msg}`;
  logger.error(`[BitcoinTap] ${full}`);
  throw new Error(full);
}

/** Safe decode: returns null for empty/insufficient bridge responses instead of throwing. */
function safeDecodeEnvelope(route: string, res: Uint8Array) {
  if (!res || res.length < 2) {
    logger.warn(`[BitcoinTap] ${route}: empty response (${res?.length ?? 0} bytes), skipping decode`);
    return null;
  }
  return decodeFramedEnvelopeV3(res);
}
import {
  AppStateRequest,
  ArgPack,
  Codec,
  BitcoinAddressRequest,
  BitcoinAddressResponse,
  BitcoinAddressSelectRequest,
  BitcoinAddressSelectResponse,
  BitcoinDepositListResponse,
  BitcoinDepositEntry,
  BitcoinClaimTxRequest,
  BitcoinClaimTxResponse,
  DepositRequest,
  DepositResponse,
  DepositRefundRequest,
  DepositStatusRequest,
  BalanceGetResponse,
  BitcoinWalletImportRequest,
  BitcoinWalletImportResponse,
  BitcoinWalletListRequest,
  BitcoinWalletListResponse,
  BitcoinWalletSelectRequest,
  BitcoinWalletSelectResponse,
  BitcoinBroadcastRequest,
  BitcoinBroadcastResponse,
  BitcoinAutoClaimRequest,
  BitcoinAutoClaimResponse,
  BitcoinTxStatusRequest,
  BitcoinTxStatusResponse,
  BitcoinVaultListResponse,
  BitcoinVaultSummary,
  BitcoinVaultGetRequest,
  BitcoinVaultGetResponse,
  BitcoinWalletHealthResponse,
  BitcoinFeeEstimateRequest,
  BitcoinFeeEstimateResponse,
  BitcoinRefundTxRequest,
  BitcoinRefundTxResponse,
  BitcoinWithdrawalPlanRequest,
  BitcoinWithdrawalPlanResponse,
  BitcoinWithdrawalExecuteRequest,
  BitcoinWithdrawalExecuteResponse,
  BitcoinWithdrawalPlanLeg as ProtoBitcoinWithdrawalPlanLeg,
  BitcoinWithdrawalBlockedVault as ProtoBitcoinWithdrawalBlockedVault,
  BitcoinWithdrawalExecutionLeg as ProtoBitcoinWithdrawalExecutionLeg,
  BitcoinWalletCreateRequest,
  BitcoinWalletCreateResponse,
} from '../proto/dsm_app_pb';

// ---- Address ----

export interface BitcoinAddress {
  address: string;
  index: number;
  pubkey: Uint8Array;
}

/**
 * Get the next unused Bitcoin receive address (BIP84 P2WPKH).
 * Each call increments the internal index counter.
 */
export async function getBitcoinAddress(): Promise<BitcoinAddress> {
  const res = await appRouterQueryBin('bitcoin.address');
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinAddressResponse') {
    const resp = payload.value as BitcoinAddressResponse;
    return {
      address: resp.address,
      index: resp.index,
      pubkey: resp.compressedPubkey,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.address', (payload.value as any).message);
  }
  btcError('bitcoin.address', 'unexpected response type');
}

/**
 * Peek at a Bitcoin address at a specific index without advancing the counter.
 */
export async function peekBitcoinAddress(index: number): Promise<BitcoinAddress> {
  const req = new BitcoinAddressRequest({ index });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterQueryBin('bitcoin.address.peek', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinAddressResponse') {
    const resp = payload.value as BitcoinAddressResponse;
    return {
      address: resp.address,
      index: resp.index,
      pubkey: resp.compressedPubkey,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.address.peek', (payload.value as any).message);
  }
  btcError('bitcoin.address.peek', 'unexpected response type');
}

/**
 * Persist the selected BIP84 address index as the active receive address.
 * This is a write operation — the Rust handler updates the DB and all
 * subsequent bitcoin.address calls will reflect the new index.
 * WIF-imported accounts (single key) do not support index selection.
 */
export async function selectBitcoinAddress(index: number): Promise<BitcoinAddress> {
  const req = new BitcoinAddressSelectRequest({ index });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.address.select', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinAddressSelectResponse') {
    const resp = payload.value as BitcoinAddressSelectResponse;
    return {
      address: resp.address,
      index: resp.index,
      pubkey: resp.compressedPubkey,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.address.select', (payload.value as any).message);
  }
  btcError('bitcoin.address.select', 'unexpected response type');
}

// ---- Balance ----

export interface DbtcBalance {
  available: bigint;
  locked: bigint;
  source?: 'CHAIN' | 'UNKNOWN';
}

export interface NativeBtcBalance {
  available: bigint;
  locked: bigint;
  source?: 'CHAIN' | 'UNKNOWN';
}

export interface BitcoinWalletHealth {
  network: string;
  reachable: boolean;
  source: 'CHAIN' | 'MEMPOOL' | 'UNKNOWN';
  reason?: string;
  rpcUrl?: string;
  trackedAddresses?: number;
}

/**
 * Get the dBTC balance for this wallet.
 */
export async function getDbtcBalance(): Promise<DbtcBalance> {
  const res = await appRouterQueryBin('bitcoin.balance');
  const env = safeDecodeEnvelope('bitcoin.balance', res);
  if (!env) return { available: BigInt(0), locked: BigInt(0), source: 'UNKNOWN' };
  const payload = env.payload;
  if (payload.case === 'balanceGetResponse') {
    const resp = payload.value as BalanceGetResponse;
    return {
      available: resp.available,
      locked: resp.locked,
      source: resp.tokenId === 'BTC_CHAIN' ? 'CHAIN' : 'UNKNOWN',
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.balance', (payload.value as any).message);
  }
  btcError('bitcoin.balance', 'unexpected response type');
}

/**
 * Get native BTC wallet balance from the on-chain wallet view.
 * `available` is confirmed BTC only; unconfirmed incoming is intentionally
 * excluded from the spendable number.
 */
export async function getNativeBtcBalance(): Promise<NativeBtcBalance> {
  const res = await appRouterQueryBin('bitcoin.wallet.balance');
  const env = safeDecodeEnvelope('bitcoin.wallet.balance', res);
  if (!env) return { available: BigInt(0), locked: BigInt(0), source: 'UNKNOWN' };
  const payload = env.payload;
  if (payload.case === 'balanceGetResponse') {
    const resp = payload.value as BalanceGetResponse;
    const tokenId = (resp.tokenId || '').toUpperCase();
    const source: NativeBtcBalance['source'] = tokenId.includes('CHAIN')
      ? 'CHAIN'
      : 'UNKNOWN';
    return {
      available: resp.available,
      locked: resp.locked,
      source,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.wallet.balance', (payload.value as any).message);
  }
  btcError('bitcoin.wallet.balance', 'unexpected response type');
}

export async function getBitcoinWalletHealth(): Promise<BitcoinWalletHealth> {
  const res = await appRouterQueryBin('bitcoin.wallet.health');
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinWalletHealthResponse') {
    const resp = payload.value as BitcoinWalletHealthResponse;
    const source: BitcoinWalletHealth['source'] = resp.source === 'CHAIN' ? 'CHAIN'
      : resp.source === 'MEMPOOL' ? 'MEMPOOL' : 'UNKNOWN';
    return {
      network: resp.network || 'unknown',
      reachable: resp.reachable,
      source,
      reason: resp.reason || undefined,
      rpcUrl: resp.rpcUrl || undefined,
      trackedAddresses: resp.trackedAddresses,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.wallet.health', (payload.value as any).message);
  }
  btcError('bitcoin.wallet.health', 'unexpected response type');
}

// ---- Deposits ----

export interface DepositEntry {
  vaultOpId: string;
  direction: string;
  status: string;
  btcAmountSats: bigint;
  htlcAddress: string;
  vaultId: string;
  isFractionalSuccessor: boolean;
  fundingTxid: string;
}

export interface BitcoinWalletAccountEntry {
  accountId: string;
  label: string;
  importKind: string;
  network: number;
  active: boolean;
  firstAddress: string;
  activeReceiveIndex: number;
}

export interface BitcoinWalletList {
  accounts: BitcoinWalletAccountEntry[];
  activeAccountId: string;
}

/**
 * List all active and completed deposits.
 */
export async function listDeposits(): Promise<DepositEntry[]> {
  const res = await appRouterQueryBin('bitcoin.deposit.list');
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinDepositListResponse') {
    const resp = payload.value as BitcoinDepositListResponse;
    return resp.deposits.map((s: BitcoinDepositEntry) => ({
      vaultOpId: s.vaultOpId,
      direction: s.direction,
      status: s.status,
      btcAmountSats: s.btcAmountSats,
      htlcAddress: s.htlcAddress,
      vaultId: s.vaultId,
      isFractionalSuccessor: s.isFractionalSuccessor,
      fundingTxid: s.fundingTxid || '',
    }));
  }
  if (payload.case === 'error') {
    btcError('bitcoin.deposit.list', (payload.value as any).message);
  }
  btcError('bitcoin.deposit.list', 'unexpected response type');
}

/**
 * Get the status of a specific deposit.
 */
export async function getDepositStatus(vaultOpId: string): Promise<DepositResponse> {
  const req = new DepositStatusRequest({ vaultOpId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterQueryBin('bitcoin.deposit.status', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'depositResponse') {
    return payload.value as DepositResponse;
  }
  if (payload.case === 'error') {
    btcError('bitcoin.deposit.status', (payload.value as any).message);
  }
  btcError('bitcoin.deposit.status', 'unexpected response type');
}

/**
 * Check current confirmation count for a deposit's funding tx.
 * Returns { confirmations, required, ready } — non-blocking, single HTTP check.
 */
export async function checkConfirmations(vaultOpId: string): Promise<{
  confirmations: number;
  required: number;
  ready: boolean;
  status: string;
  fundingTxid: string;
}> {
  const req = new DepositStatusRequest({ vaultOpId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterQueryBin('bitcoin.deposit.check_confirmations', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'depositResponse') {
    const resp = payload.value as DepositResponse;
    // message format: "X/Y" (confirmations/required)
    const parts = (resp.message || '0/0').split('/');
    const confirmations = parseInt(parts[0] || '0', 10);
    const required = parseInt(parts[1] || '0', 10);
    return {
      confirmations,
      required,
      ready: resp.status === 'confirmed',
      status: resp.status,
      // The resolved funding_txid — may appear after auto-retry claim
      // even if the initial listDeposits() had an empty value.
      fundingTxid: resp.fundingTxid || '',
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.deposit.check_confirmations', (payload.value as any).message);
  }
  btcError('bitcoin.deposit.check_confirmations', 'unexpected response type');
}

// ---- Deposit Operations ----

/**
 * Initiate a BTC -> dBTC deposit.
 */
export async function initiateDeposit(
  amountSats: bigint,
  refundIterations: bigint,
): Promise<DepositResponse> {
  const req = new DepositRequest({
    direction: 'btc_to_dbtc',
    btcAmountSats: amountSats,
    refundIterations,
  });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.deposit.initiate', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'depositResponse') {
    return payload.value as DepositResponse;
  }
  if (payload.case === 'error') {
    btcError('bitcoin.deposit.initiate', (payload.value as any).message);
  }
  btcError('bitcoin.deposit.initiate', 'unexpected response type');
}

/**
 * Request a refund for an expired deposit.
 */
export async function refundDeposit(vaultOpId: string): Promise<DepositResponse> {
  const req = new DepositRefundRequest({ vaultOpId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.deposit.refund', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'depositResponse') {
    return payload.value as DepositResponse;
  }
  if (payload.case === 'error') {
    btcError('bitcoin.deposit.refund', (payload.value as any).message);
  }
  btcError('bitcoin.deposit.refund', 'unexpected response type');
}

/**
 * Build a claim transaction for sweeping BTC from an HTLC.
 * Returns the raw signed transaction bytes and txid.
 */
export async function buildClaimTx(
  vaultOpId: string,
  destAddress: string,
  feeRate: bigint,
  outpointTxid: Uint8Array,
  outpointVout: number,
  preimage?: Uint8Array,
  signingIndex?: number,
): Promise<{ rawTx: Uint8Array; txid: string }> {
  const req = new BitcoinClaimTxRequest({
    vaultOpId,
    destinationAddress: destAddress,
    feeRateSatVb: feeRate,
    outpointTxid: outpointTxid as any,
    outpointVout,
    preimage: (preimage ?? new Uint8Array(0)) as any,
    signingIndex: signingIndex ?? 0,
  });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.claim.build', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinClaimTxResponse') {
    const resp = payload.value as BitcoinClaimTxResponse;
    return { rawTx: resp.rawTx, txid: resp.txid };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.claim.build', (payload.value as any).message);
  }
  btcError('bitcoin.claim.build', 'unexpected response type');
}

/** Generate a fresh BIP39 wallet on the given network. Returns the mnemonic — display it and ask the user to back it up. */
export async function createBitcoinWallet(
  network: number,
  label: string = '',
  wordCount: 12 | 24 = 24,
): Promise<BitcoinWalletCreateResponse> {
  const req = new BitcoinWalletCreateRequest({
    network,
    label,
    wordCount,
  });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.wallet.create', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinWalletCreateResponse') {
    return payload.value as BitcoinWalletCreateResponse;
  }
  if (payload.case === 'error') {
    btcError('bitcoin.wallet.create', (payload.value as any).message);
  }
  btcError('bitcoin.wallet.create', 'unexpected response type');
}

export async function importBitcoinWallet(
  importKind: 'wif' | 'xpriv' | 'mnemonic',
  secret: string,
  label: string,
  network: number,
  startIndex: number = 0,
): Promise<BitcoinWalletImportResponse> {
  const req = new BitcoinWalletImportRequest({
    importKind,
    secret,
    label,
    network,
    startIndex,
  });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.wallet.import', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinWalletImportResponse') {
    return payload.value as BitcoinWalletImportResponse;
  }
  if (payload.case === 'error') {
    btcError('bitcoin.wallet.import', (payload.value as any).message);
  }
  btcError('bitcoin.wallet.import', 'unexpected response type');
}

export async function listBitcoinWalletAccounts(): Promise<BitcoinWalletList> {
  const req = new BitcoinWalletListRequest({});
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterQueryBin('bitcoin.wallet.list', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinWalletListResponse') {
    const resp = payload.value as BitcoinWalletListResponse;
    return {
      accounts: resp.accounts.map((a) => ({
        accountId: a.accountId,
        label: a.label,
        importKind: a.importKind,
        network: a.network,
        active: a.active,
        firstAddress: a.firstAddress,
        activeReceiveIndex: a.activeReceiveIndex,
      })),
      activeAccountId: resp.activeAccountId,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.wallet.list', (payload.value as any).message);
  }
  btcError('bitcoin.wallet.list', 'unexpected response type');
}

export async function selectBitcoinWalletAccount(accountId: string): Promise<BitcoinWalletSelectResponse> {
  const req = new BitcoinWalletSelectRequest({ accountId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.wallet.select', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinWalletSelectResponse') {
    return payload.value as BitcoinWalletSelectResponse;
  }
  if (payload.case === 'error') {
    btcError('bitcoin.wallet.select', (payload.value as any).message);
  }
  btcError('bitcoin.wallet.select', 'unexpected response type');
}

// ---- Broadcast / Auto-Claim / Tx Status ----

/**
 * Broadcast a raw signed Bitcoin transaction.
 * Returns the 32-byte txid in internal byte order.
 */
export async function broadcastTx(rawTx: Uint8Array): Promise<Uint8Array> {
  const req = new BitcoinBroadcastRequest({ rawTx: rawTx as any });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.tx.broadcast', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinBroadcastResponse') {
    return (payload.value as BitcoinBroadcastResponse).txid;
  }
  if (payload.case === 'error') {
    btcError('bitcoin.tx.broadcast', (payload.value as any).message);
  }
  btcError('bitcoin.tx.broadcast', 'unexpected response type');
}

/**
 * Build + broadcast a claim transaction for an HTLC in one call.
 * Returns the claim txid (32 bytes, internal byte order) and raw tx bytes.
 */
export async function autoClaimHtlc(
  vaultOpId: string,
  destinationAddress: string,
  fundingTxid: Uint8Array,
  fundingVout: number,
  feeRateSatVb: bigint,
  signingIndex?: number,
): Promise<{ txid: Uint8Array; rawTx: Uint8Array }> {
  const req = new BitcoinAutoClaimRequest({
    vaultOpId,
    destinationAddress,
    fundingTxid: fundingTxid as any,
    fundingVout,
    feeRateSatVb,
    signingIndex: signingIndex ?? 0,
  });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.claim.auto', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinAutoClaimResponse') {
    const resp = payload.value as BitcoinAutoClaimResponse;
    return { txid: resp.txid, rawTx: resp.rawTx };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.claim.auto', (payload.value as any).message);
  }
  btcError('bitcoin.claim.auto', 'unexpected response type');
}

/**
 * Query the status of a Bitcoin transaction by txid.
 * Returns the number of confirmations and whether it's in the mempool.
 */
export async function getTxStatus(
  txid: Uint8Array,
): Promise<{ confirmations: number; inMempool: boolean }> {
  const req = new BitcoinTxStatusRequest({ txid: txid as any });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterQueryBin('bitcoin.tx.status', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinTxStatusResponse') {
    const resp = payload.value as BitcoinTxStatusResponse;
    return { confirmations: resp.confirmations, inMempool: resp.inMempool };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.tx.status', (payload.value as any).message);
  }
  btcError('bitcoin.tx.status', 'unexpected response type');
}

// ---- Vault Monitor ----

export interface VaultSummary {
  vaultId: string;
  state: string;
  amountSats: bigint;
  direction: string;
  htlcAddress: string;
  entryHeader: Uint8Array;
}

export interface VaultDetail extends VaultSummary {
  createdAtState: bigint;
  contentCommitment: Uint8Array;
  depositId: string;
}

/**
 * List all DLV vaults with summary info.
 */
export async function listVaults(): Promise<VaultSummary[]> {
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: new Uint8Array(0) as any, // BitcoinVaultListRequest has no fields
  });
  const res = await appRouterQueryBin('bitcoin.vault.list', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinVaultListResponse') {
    const resp = payload.value as BitcoinVaultListResponse;
    return resp.vaults.map((v: BitcoinVaultSummary) => ({
      vaultId: v.vaultId,
      state: v.state,
      amountSats: v.amountSats,
      direction: v.direction,
      htlcAddress: v.htlcAddress,
      entryHeader: v.entryHeader,
    }));
  }
  if (payload.case === 'error') {
    btcError('bitcoin.vault.list', (payload.value as any).message);
  }
  btcError('bitcoin.vault.list', 'unexpected response type');
}

/**
 * Get detailed info for a specific vault.
 */
export async function getVaultDetail(vaultId: string): Promise<VaultDetail> {
  const req = new BitcoinVaultGetRequest({ vaultId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterQueryBin('bitcoin.vault.get', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinVaultGetResponse') {
    const resp = payload.value as BitcoinVaultGetResponse;
    return {
      vaultId: resp.vaultId,
      state: resp.state,
      amountSats: resp.amountSats,
      direction: resp.direction,
      htlcAddress: resp.htlcAddress,
      entryHeader: resp.entryHeader,
      createdAtState: resp.createdAtState,
      contentCommitment: resp.contentCommitment,
      depositId: resp.vaultOpId,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.vault.get', (payload.value as any).message);
  }
  btcError('bitcoin.vault.get', 'unexpected response type');
}

// ---- Formatting Helpers ----

/**
 * Format satoshis as BTC string (8 decimal places).
 */
export function formatBtc(sats: bigint): string {
  const whole = sats / 100000000n;
  const frac = sats % 100000000n;
  const fracStr = frac.toString().padStart(8, '0');
  return `${whole}.${fracStr}`;
}

/**
 * Parse a BTC string to satoshis.
 */
export function parseBtcToSats(btcStr: string): bigint {
  const parts = btcStr.split('.');
  const whole = BigInt(parts[0] || '0');
  const fracStr = (parts[1] || '').padEnd(8, '0').slice(0, 8);
  return whole * 100000000n + BigInt(fracStr);
}

// ---- Fee Estimation ----

export interface FeeEstimate {
  estimatedFeeSats: bigint;
  estimatedVsize: bigint;
  outputAmountSats: bigint;
}

export async function estimateFee(
  vaultOpId: string,
  feeRateSatVb: bigint,
  isFractional: boolean,
): Promise<FeeEstimate> {
  const req = new BitcoinFeeEstimateRequest({
    vaultOpId,
    feeRateSatVb,
    isFractional,
  });
  const pack = new ArgPack({ codec: Codec.PROTO, body: req.toBinary() as any });
  const res = await appRouterQueryBin('bitcoin.fee.estimate', pack.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinFeeEstimateResponse') {
    const resp = payload.value as BitcoinFeeEstimateResponse;
    return {
      estimatedFeeSats: resp.estimatedFeeSats,
      estimatedVsize: resp.estimatedVsize,
      outputAmountSats: resp.outputAmountSats,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.fee.estimate', (payload.value as any).message);
  }
  btcError('bitcoin.fee.estimate', 'unexpected response type');
}

// ---- Refund TX Builder ----

export async function buildRefundTx(
  vaultOpId: string,
  refundAddress: string,
  outpointTxid: Uint8Array,
  outpointVout: number,
  feeRateSatVb: bigint,
  signingIndex: number = 0,
): Promise<{ rawTx: Uint8Array; txid: string }> {
  const req = new BitcoinRefundTxRequest({
    vaultOpId,
    refundAddress,
    outpointTxid: new Uint8Array(outpointTxid) as any,
    outpointVout,
    feeRateSatVb,
    signingIndex,
  });
  const pack = new ArgPack({ codec: Codec.PROTO, body: req.toBinary() as any });
  const res = await appRouterInvokeBin('bitcoin.refund.build', pack.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinRefundTxResponse') {
    const resp = payload.value as BitcoinRefundTxResponse;
    return { rawTx: resp.rawTx, txid: resp.txid };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.refund.build', (payload.value as any).message);
  }
  btcError('bitcoin.refund.build', 'unexpected response type');
}

export interface WithdrawalBlockedVault {
  vaultId: string;
  amountSats: bigint;
  reason: string;
}

export interface WithdrawalPlanLeg {
  vaultId: string;
  kind: 'full' | 'partial' | string;
  sourceAmountSats: bigint;
  grossExitSats: bigint;
  estimatedFeeSats: bigint;
  estimatedNetSats: bigint;
  remainderSats: bigint;
  successorDepthAfter: number;
}

export interface WithdrawalPlanResult {
  planId: string;
  planClass: string;
  requestedNetSats: bigint;
  plannedNetSats: bigint;
  totalGrossExitSats: bigint;
  totalFeeSats: bigint;
  shortfallSats: bigint;
  availableDbtcSats: bigint;
  legs: WithdrawalPlanLeg[];
  blockedVaults: WithdrawalBlockedVault[];
  policyCommit: Uint8Array;
}

export interface WithdrawalExecutionLeg {
  vaultId: string;
  kind: 'full' | 'partial' | string;
  status: string;
  grossExitSats: bigint;
  estimatedFeeSats: bigint;
  estimatedNetSats: bigint;
  actualRemainderSats: bigint;
  successorVaultId: string;
  successorVaultOpId: string;
  exitVaultOpId: string;
  sweepTxid: string;
}

export interface WithdrawalExecuteResult {
  planId: string;
  planClass: string;
  status: string;
  message: string;
  requestedNetSats: bigint;
  plannedNetSats: bigint;
  totalGrossExitSats: bigint;
  totalFeeSats: bigint;
  shortfallSats: bigint;
  executedLegs: WithdrawalExecutionLeg[];
  blockedVaults: WithdrawalBlockedVault[];
}

function mapWithdrawalPlanLeg(leg: ProtoBitcoinWithdrawalPlanLeg): WithdrawalPlanLeg {
  return {
    vaultId: leg.vaultId,
    kind: leg.kind,
    sourceAmountSats: leg.sourceAmountSats,
    grossExitSats: leg.grossExitSats,
    estimatedFeeSats: leg.estimatedFeeSats,
    estimatedNetSats: leg.estimatedNetSats,
    remainderSats: leg.remainderSats,
    successorDepthAfter: leg.successorDepthAfter,
  };
}

function mapBlockedVault(vault: ProtoBitcoinWithdrawalBlockedVault): WithdrawalBlockedVault {
  return {
    vaultId: vault.vaultId,
    amountSats: vault.amountSats,
    reason: vault.reason,
  };
}

function mapWithdrawalExecutionLeg(leg: ProtoBitcoinWithdrawalExecutionLeg): WithdrawalExecutionLeg {
  return {
    vaultId: leg.vaultId,
    kind: leg.kind,
    status: leg.status,
    grossExitSats: leg.grossExitSats,
    estimatedFeeSats: leg.estimatedFeeSats,
    estimatedNetSats: leg.estimatedNetSats,
    actualRemainderSats: leg.actualRemainderSats,
    successorVaultId: leg.successorVaultId,
    successorVaultOpId: leg.successorVaultOpId,
    exitVaultOpId: leg.exitVaultOpId,
    sweepTxid: leg.sweepTxid,
  };
}

export async function reviewWithdrawalPlan(
  requestedNetSats: bigint,
  destinationAddress: string,
): Promise<WithdrawalPlanResult> {
  const req = new BitcoinWithdrawalPlanRequest({
    requestedNetSats,
    destinationAddress,
  });
  const pack = new ArgPack({ codec: Codec.PROTO, body: req.toBinary() as any });
  const res = await appRouterQueryBin('bitcoin.withdraw.plan', pack.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinWithdrawalPlanResponse') {
    const resp = payload.value as BitcoinWithdrawalPlanResponse;
    logger.info(
      `[BitcoinTap] withdraw.plan: class=${resp.planClass} legs=${resp.legs.length} blocked=${resp.blockedVaults.length} planned=${resp.plannedNetSats} shortfall=${resp.shortfallSats}`,
    );
    for (const bv of resp.blockedVaults) {
      logger.warn(
        `[BitcoinTap] withdraw.plan blocked: vault=${bv.vaultId.slice(0, 12)} amount=${bv.amountSats} reason=${bv.reason}`,
      );
    }
    return {
      planId: resp.planId,
      planClass: resp.planClass,
      requestedNetSats: resp.requestedNetSats,
      plannedNetSats: resp.plannedNetSats,
      totalGrossExitSats: resp.totalGrossExitSats,
      totalFeeSats: resp.totalFeeSats,
      shortfallSats: resp.shortfallSats,
      availableDbtcSats: resp.availableDbtcSats,
      legs: resp.legs.map(mapWithdrawalPlanLeg),
      blockedVaults: resp.blockedVaults.map(mapBlockedVault),
      policyCommit: resp.policyCommit,
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.withdraw.plan', (payload.value as any).message);
  }
  btcError('bitcoin.withdraw.plan', 'unexpected response type');
}

export async function executeWithdrawalPlan(
  planId: string,
  destinationAddress: string,
): Promise<WithdrawalExecuteResult> {
  const req = new BitcoinWithdrawalExecuteRequest({
    planId,
    destinationAddress,
  });
  const pack = new ArgPack({ codec: Codec.PROTO, body: req.toBinary() as any });
  const res = await appRouterInvokeBin('bitcoin.withdraw.execute', pack.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'bitcoinWithdrawalExecuteResponse') {
    const resp = payload.value as BitcoinWithdrawalExecuteResponse;
    return {
      planId: resp.planId,
      planClass: resp.planClass,
      status: resp.status,
      message: resp.message,
      requestedNetSats: resp.requestedNetSats,
      plannedNetSats: resp.plannedNetSats,
      totalGrossExitSats: resp.totalGrossExitSats,
      totalFeeSats: resp.totalFeeSats,
      shortfallSats: resp.shortfallSats,
      executedLegs: resp.executedLegs.map(mapWithdrawalExecutionLeg),
      blockedVaults: resp.blockedVaults.map(mapBlockedVault),
    };
  }
  if (payload.case === 'error') {
    btcError('bitcoin.withdraw.execute', (payload.value as any).message);
  }
  btcError('bitcoin.withdraw.execute', 'unexpected response type');
}

// ---- Universal: 2-step deposit (broadcast then complete) ----

/**
 * Step 1: Build the funding tx from user wallet UTXOs and broadcast it.
 * Returns the funding txid hex string immediately after broadcast.
 * The deposit state moves to `awaiting_confirmation`.
 */
export async function fundAndBroadcast(vaultOpId: string): Promise<string> {
  const req = new DepositRefundRequest({ vaultOpId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.deposit.fund_and_broadcast', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'appStateResponse') {
    return (payload.value as any).value || '';
  }
  if (payload.case === 'error') {
    btcError('bitcoin.deposit.fund_and_broadcast', (payload.value as any).message);
  }
  btcError('bitcoin.deposit.fund_and_broadcast', 'unexpected response type');
}

/**
 * Step 2: Wait for confirmations on the previously-broadcast funding tx,
 * build the SPV proof, and complete the deposit (DLV unlock + token mint/burn).
 * Returns a completion message string.
 */
export async function awaitAndComplete(vaultOpId: string): Promise<string> {
  const req = new DepositRefundRequest({ vaultOpId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.deposit.await_and_complete', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'appStateResponse') {
    return (payload.value as any).value || 'Success';
  }
  if (payload.case === 'error') {
    btcError('bitcoin.deposit.await_and_complete', (payload.value as any).message);
  }
  btcError('bitcoin.deposit.await_and_complete', 'unexpected response type');
}

/**
 * Complete an exit deposit (dbtc_to_btc) after sufficient confirmations.
 * This is the exit-side counterpart of `awaitAndComplete` — it verifies
 * the sweep tx has enough burial depth, stores the exit anchor header,
 * and transitions the deposit to Completed. No DLV unlock or token mint is
 * needed since the dBTC burn already happened at exit initiation.
 *
 * dBTC §6.4.3 (Exit Anchor), §12.1.3 (Deep-Anchor Confirmation Depths)
 */
export async function completeExitDeposit(vaultOpId: string): Promise<string> {
  const req = new DepositRefundRequest({ vaultOpId });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  const res = await appRouterInvokeBin('bitcoin.exit.complete', arg.toBinary());
  const env = decodeFramedEnvelopeV3(res);
  const payload = env.payload;
  if (payload.case === 'appStateResponse') {
    return (payload.value as any).value || 'Exit completed';
  }
  if (payload.case === 'error') {
    btcError('bitcoin.exit.complete', (payload.value as any).message);
  }
  btcError('bitcoin.exit.complete', 'unexpected response type');
}

// ---- Withdrawal Settlement Polling (dBTC §13) ----

/**
 * Poll Bitcoin for confirmation depth on all committed in-flight withdrawals.
 * Settles (finalizes burn) when sweep txids reach d_min confirmations.
 * Refunds (restores balance) when a sweep tx drops out of mempool.
 *
 * Called automatically on every data refresh cycle (app foreground, pull-to-refresh).
 * Returns a human-readable summary: "Checked N withdrawal(s): X settled, Y refunded, Z pending"
 */
export async function settleWithdrawals(): Promise<string> {
  const req = new AppStateRequest({ key: 'settle' });
  const arg = new ArgPack({
    codec: Codec.PROTO,
    body: req.toBinary() as any,
  });
  try {
    const res = await appRouterInvokeBin('bitcoin.withdraw.settle', arg.toBinary());
    const env = decodeFramedEnvelopeV3(res);
    const payload = env.payload;
    if (payload.case === 'appStateResponse') {
      const msg = (payload.value as any).value || 'No committed withdrawals';
      logger.info(`[BitcoinTap] withdraw.settle: ${msg}`);
      return msg;
    }
    if (payload.case === 'error') {
      const errMsg = (payload.value as any).message || 'settle failed';
      logger.warn(`[BitcoinTap] withdraw.settle error: ${errMsg}`);
      return errMsg;
    }
  } catch (e) {
    // Settlement polling is best-effort; don't throw on failure
    const msg = e instanceof Error ? e.message : 'settle poll failed';
    console.warn(`[BitcoinTap] withdraw.settle exception: ${msg}`);
    return msg;
  }
  return 'No committed withdrawals';
}

// ---- Explorer URL ----

export type BitcoinUiNetwork = 0 | 1 | 2;

export function normalizeBitcoinUiNetwork(network: number): BitcoinUiNetwork {
  if (network === 0 || network === 1) return network;
  return 2;
}

export function bitcoinNetworkLabel(network: number): string {
  return ['mainnet', 'testnet', 'signet'][normalizeBitcoinUiNetwork(network)] ?? 'signet';
}

/**
 * Build a mempool.space explorer URL for a given txid + network.
 * @param txid  hex string of the transaction
 * @param network  0=mainnet, 1=testnet4, 2=signet
 */
export function mempoolExplorerUrl(txid: string, network: number): string {
  const normalizedNetwork = normalizeBitcoinUiNetwork(network);
  const prefix = normalizedNetwork === 0 ? ''
    : normalizedNetwork === 2 ? '/signet'
    : '/testnet4';
  return `https://mempool.space${prefix}/tx/${txid}`;
}
