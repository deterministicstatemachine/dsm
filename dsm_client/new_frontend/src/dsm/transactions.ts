/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import { decodeBase32Crockford, encodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';
import {
    appRouterQueryBin,
    appRouterInvokeBin,
    getDeviceIdBinBridgeAsync,
    getSigningPublicKeyBinBridgeAsync,
    acceptBilateralByCommitmentBridge,
    rejectBilateralByCommitmentBridge,
    getPendingBilateralListStrictBridge,
    setBleIdentityForAdvertising,
    startBleAdvertisingViaRouter,
    startBleScanViaRouter,
} from './WebViewBridge';
import { on as eventBridgeOn } from './EventBridge';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { getHeaders } from './identity';
import { getContacts } from './contacts';

import { normalizeBleAddress, resolveBleAddressForContact } from './resolution';
import logger from '../utils/logger';

import { GenericTransaction, GenericTxResponse } from './types';

function canonicalizeTransferTokenId(tokenId: string | undefined | null): string {
  const trimmed = String(tokenId || 'ERA').trim();
  if (!trimmed) return 'ERA';
  const upper = trimmed.toUpperCase();
  if (upper === 'ERA') return 'ERA';
  if (upper === 'DBTC') return 'dBTC';
  return trimmed;
}

/**
 * After the receiver sends Accept, the Confirm arrives within ~1-2 seconds.
 * Schedule staggered priority wallet refreshes using RAF batches to ensure
 * the UI picks up the balance change from SQLite regardless of whether the
 * TRANSFER_COMPLETE event chain delivers successfully.  Each refresh uses
 * the priority source so useWalletRefreshListener bypasses its cooldown.
 *
 * RAF spacing: ~30 frames ≈ 0.5s at 60fps, repeated 4 times ≈ 0/0.5/1.5/3s.
 */
function schedulePostAcceptRefreshes(): void {
  const INTERVALS = [1, 30, 60, 120]; // RAF frame counts
  let frame = 0;
  let idx = 0;
  const tick = () => {
    frame++;
    if (idx >= INTERVALS.length) return;
    if (frame >= INTERVALS[idx]) {
      idx++;
      try {
        bridgeEvents.emit('wallet.refresh', { source: 'bilateral.transfer_complete' });
      } catch {}
    }
    if (idx < INTERVALS.length) {
      requestAnimationFrame(tick);
    }
  };
  requestAnimationFrame(tick);
}

// Helpers

/** Diagnostics: get local device id via native bridge (may be empty until identity initialized). */
export function getLocalDeviceId(): Uint8Array {
  // Try cache first (works for binary bridge if getHeaders() was called previously)
  const g: any = globalThis as any;
  const cached = g.__dsmLastGoodHeaders?.deviceId;
  if (cached instanceof Uint8Array && cached.length === 32) {
    return cached;
  }

  // Not available in async bridge contract
  return new Uint8Array();
}

/** Get local signing public key (64 bytes for SPHINCS+ SPX256s) via native bridge (sync). */
export function getLocalSigningPublicKey(): Uint8Array {
  // Not available in async bridge contract
  return new Uint8Array();
}


/** Get local signing public key (64 bytes for SPHINCS+ SPX256s) via native bridge (async). */
export async function getLocalSigningPublicKeyAsync(): Promise<Uint8Array> {
  try {
    const key = await getSigningPublicKeyBinBridgeAsync();
    return key || new Uint8Array();
  } catch {
    return new Uint8Array();
  }
}

/** Get local device ID (32 bytes) via native bridge (async). */
export async function getLocalDeviceIdAsync(): Promise<Uint8Array> {
  try {
    const id = await getDeviceIdBinBridgeAsync();
    return id || new Uint8Array();
  } catch {
    return new Uint8Array();
  }
}

export async function sendOnlineTransfer(transfer: GenericTransaction): Promise<GenericTxResponse> {
  try {
    let toBytes: Uint8Array;
    if (typeof transfer.to === 'string') {
      toBytes = new Uint8Array(decodeBase32Crockford(transfer.to));
    } else if ((transfer.to as any) instanceof Uint8Array) {
      toBytes = new Uint8Array(transfer.to as any);
    } else {
      throw new Error(`Invalid toDeviceId: must be string or Uint8Array`);
    }

    if (toBytes.length !== 32) {
      throw new Error("to_device_id must be 32 bytes");
    }

    // Required signing context from transport headers (bytes-only bridge)
    const headers = await getHeaders();
    const fromDeviceId = headers.deviceId instanceof Uint8Array ? headers.deviceId : new Uint8Array();
    if (fromDeviceId.length !== 32) {
      throw new Error('from_device_id must be 32 bytes (bridge headers missing)');
    }
    const seq = typeof (headers as any).seq === 'bigint'
      ? (headers as any).seq
      : BigInt((headers as any).seq ?? 0);
    const safeSeq = seq > 0n ? seq : 1n;

    // chain_tip is protocol state owned by the SDK (per-relationship bilateral tip, §4).
    // The SDK derives it from SQLite; the frontend never supplies it.
    const req = new pb.OnlineTransferRequest({
      tokenId: canonicalizeTransferTokenId(transfer.tokenId),
      toDeviceId: toBytes as any,
      amount: BigInt(transfer.amount),
      memo: transfer.memo,
      nonce: new Uint8Array(0),
      signature: new Uint8Array(0),
      fromDeviceId: fromDeviceId as any,
      seq: safeSeq as any,
    } as any);

    // Route through AppRouter via appRouterInvokeBin('wallet.send').
    // The Rust handler at AppRouterImpl.handle_wallet_invoke decodes the ArgPack,
    // runs process_online_transfer_logic, and returns Envelope.onlineTransferResponse.
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });

    const resBytes = await appRouterInvokeBin('wallet.send', new Uint8Array(argPack.toBinary()));

    if (!resBytes || resBytes.length === 0) {
      throw new Error('Empty response from wallet.send');
    }

    // Canonical Envelope v3 decode — AppRouter returns Envelope.onlineTransferResponse
    const env = decodeFramedEnvelopeV3(resBytes);

    if (env.payload.case === 'error') {
      const errMsg = env.payload.value.message || `Error code ${env.payload.value.code}`;
      throw new Error(`DSM error: ${errMsg}`);
    }

    if (env.payload.case !== 'onlineTransferResponse') {
      throw new Error(`Expected onlineTransferResponse, got ${env.payload.case}`);
    }

    const inner = env.payload.value;

    return {
      accepted: inner.success,
      result: inner.message,
      txHash: inner.transactionHash ? encodeBase32Crockford(inner.transactionHash.v) : undefined,
      newBalance: inner.newBalance,
    };
  } catch (e: any) {
    return {
      accepted: false,
      result: e?.message || 'Failed',
    };
  }
}


export async function sendOnlineTransferSmart(
    alias: string,
    amount: string | number | bigint,
    memo?: string,
    tokenId?: string
): Promise<{ success: boolean; message?: string; newBalance?: bigint }> {
    try {
      const recipient = String(alias ?? '').trim();
      if (!recipient) {
        return { success: false, message: 'Recipient alias is required' };
      }

      const smartReq = new pb.OnlineTransferSmartRequest({
        recipient,
        amount: String(amount),
        tokenId: String(tokenId ?? '').trim(),
        memo: memo || '',
      });

      const argPack = new pb.ArgPack({
        codec: pb.Codec.PROTO as any,
        body: new Uint8Array(smartReq.toBinary()),
      });

      const resBytes = await appRouterInvokeBin('wallet.sendSmart', new Uint8Array(argPack.toBinary()));

      if (!resBytes || resBytes.length === 0) {
         throw new Error("Empty response from wallet.sendSmart");
      }

      // Canonical Envelope v3 decode
      const env = decodeFramedEnvelopeV3(resBytes);
      if (env.payload.case === 'error') {
        const errMsg = env.payload.value.message || `Error code ${env.payload.value.code}`;
        throw new Error(`DSM error: ${errMsg}`);
      }
      if (env.payload.case !== 'onlineTransferResponse') {
        throw new Error(`Expected onlineTransferResponse, got ${env.payload.case}`);
      }
      const inner = env.payload.value;
      return { success: inner.success, message: inner.message, newBalance: inner.newBalance };
    } catch (e: any) {
      return { success: false, message: e?.message || 'Online transfer failed' };
    }
}

export async function offlineSend(transfer: GenericTransaction): Promise<GenericTxResponse> {
  try {
    let toBytes: Uint8Array;
    if (typeof transfer.to === 'string') {
      toBytes = new Uint8Array(decodeBase32Crockford(transfer.to));
    } else if ((transfer.to as any) instanceof Uint8Array) {
      toBytes = new Uint8Array(transfer.to as any);
    } else {
      throw new Error('Invalid toDeviceId');
    }

    if (toBytes.length !== 32) {
      throw new Error('to_device_id must be 32 bytes');
    }

    const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
      if (a.length !== b.length) return false;
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
      return true;
    };

    const transferAmountDisplay = String(transfer.amount ?? '').trim();
    if (!transferAmountDisplay) {
      throw new Error('offlineSend: amount is required');
    }

    const prepReq = new pb.BilateralPrepareRequest({
      counterpartyDeviceId: toBytes as any,
      validityIterations: BigInt(100),
      bleAddress: normalizeBleAddress(String(transfer.bleAddress || '')) || '',
      transferAmountDisplay,
      tokenIdHint: canonicalizeTransferTokenId(transfer.tokenId),
      memoHint: transfer.memo || '',
    } as any);

    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(prepReq.toBinary()),
    });

    // --- Set up event listeners BEFORE sending BLE chunks to avoid race condition ---
    // The receiver may process the prepare and fire back a commit/event before
    // wallet.sendOffline returns. By registering listeners first and buffering
    // events until we know the commitmentHash, we never miss fast responses.
    const BLE_COMPLETION_TIMEOUT_MS = 60_000;
    const FAILURE_GRACE_MS = 3000;

    let commitmentHash: Uint8Array | null = null;
    let settled = false;
    let settledResult: GenericTxResponse | null = null;
    let pendingFailure: GenericTxResponse | null = null;
    let pendingFailureTimer: ReturnType<typeof setTimeout> | null = null;
    const earlyEventBuffer: pb.BilateralEventNotification[] = [];
    let resolvePromise: ((res: GenericTxResponse) => void) | null = null;

    const timer = setTimeout(() => {
      finish({ accepted: false, result: 'offlineSend: bilateral transfer timed out (60s)' });
    }, BLE_COMPLETION_TIMEOUT_MS);

    const finish = (res: GenericTxResponse) => {
      if (settled) return;
      settled = true;
      settledResult = res;
      clearTimeout(timer);
      if (pendingFailureTimer) {
        clearTimeout(pendingFailureTimer);
        pendingFailureTimer = null;
      }
      offEvent();
      offBle();
      // Re-start advertising so device stays discoverable for next transfer
      void startBleAdvertisingViaRouter().catch(() => {});
      if (resolvePromise) resolvePromise(res);
    };

    const processEvent = (note: pb.BilateralEventNotification) => {
      if (settled) return;
      const h = note.commitmentHash instanceof Uint8Array ? note.commitmentHash : undefined;
      if (!h || h.length !== 32) return;
      if (!commitmentHash || !bytesEqual(h, commitmentHash)) return;
      if (note.eventType === pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE) {
        if (pendingFailureTimer) { clearTimeout(pendingFailureTimer); pendingFailureTimer = null; }
        pendingFailure = null;
        finish({ accepted: true, result: note.message || 'Bilateral transfer complete' });
      } else if (note.eventType === pb.BilateralEventType.BILATERAL_EVENT_REJECTED) {
        if (pendingFailureTimer) { clearTimeout(pendingFailureTimer); pendingFailureTimer = null; }
        pendingFailure = null;
        finish({ accepted: false, result: note.message || 'Bilateral transfer rejected', failureReason: note.failureReason });
      } else if (note.eventType === pb.BilateralEventType.BILATERAL_EVENT_FAILED) {
        pendingFailure = { accepted: false, result: note.message || 'Bilateral transfer failed', failureReason: note.failureReason };
        if (pendingFailureTimer) clearTimeout(pendingFailureTimer);
        pendingFailureTimer = setTimeout(() => {
          const res = pendingFailure; pendingFailure = null; pendingFailureTimer = null;
          if (res) finish(res);
        }, FAILURE_GRACE_MS);
      }
    };

    // Register listeners BEFORE BLE chunks are sent
    const offEvent = eventBridgeOn('bilateral.event', (payload) => {
      try {
        const note = pb.BilateralEventNotification.fromBinary(payload);
        if (!commitmentHash) {
          // commitmentHash not yet known — buffer event for later drain
          earlyEventBuffer.push(note);
          return;
        }
        processEvent(note);
      } catch { /* ignore */ }
    });

    const offBle = eventBridgeOn('ble.envelope.bin', (payload) => {
      try {
        const bleEnv = decodeFramedEnvelopeV3(payload as Uint8Array);
        const p2: any = bleEnv?.payload ?? bleEnv;
        const btMsg = (p2?.case === 'dsmBtMessage' ? p2.value : p2?.dsmBtMessage) as pb.DsmBtMessage | undefined;
        if (!btMsg || btMsg.messageType !== pb.BtMessageType.BTMSG_TYPE_ERROR) return;
        const err = pb.BleTransactionError.fromBinary(btMsg.payload);
        const msg = err?.message || 'BLE transaction error';
        finish({ accepted: false, result: msg });
      } catch { /* ignore */ }
    });

    // --- Ensure BLE advertising + scanning so the receiver can connect back ---
    try {
      const devId = await getDeviceIdBinBridgeAsync();
      if (devId && devId.length === 32) {
        await setBleIdentityForAdvertising(new Uint8Array(32), devId);
        await startBleAdvertisingViaRouter();
      }
      await startBleScanViaRouter();
      // Brief pause for BLE stack to settle and peer to discover us
      await new Promise(r => setTimeout(r, 1500));
    } catch {
      // Best-effort — proceed with send even if BLE priming fails
    }

    // --- Delegate native authoring + BLE dispatch to wallet.sendOffline ---
    const respBytes = await appRouterInvokeBin('wallet.sendOffline', new Uint8Array(argPack.toBinary()));
    if (!respBytes || respBytes.length === 0) {
      finish({ accepted: false, result: 'offlineSend: empty response from bridge' });
      return { accepted: false, result: 'offlineSend: empty response from bridge' };
    }
    // Canonical Envelope v3 decode
    const env1 = decodeFramedEnvelopeV3(respBytes);
    if (env1.payload.case === 'error') {
      const errMsg = env1.payload.value.message || `Error code ${env1.payload.value.code}`;
      finish({ accepted: false, result: `offlineSend: ${errMsg}` });
      return { accepted: false, result: `offlineSend: ${errMsg}` };
    }

    try {
      const p = env1.payload;
      if (p.case === 'bilateralPrepareResponse') {
        const resp = p.value as pb.BilateralPrepareResponse;
        const h = resp.commitmentHash?.v;
        if (h instanceof Uint8Array && h.length === 32) commitmentHash = h;
      } else if (p.case === 'bilateralPrepareReject') {
        const rej = p.value as pb.BilateralPrepareReject;
        finish({ accepted: false, result: rej?.reason || 'offlineSend: rejected' });
        return { accepted: false, result: rej?.reason || 'offlineSend: rejected' };
      } else {
        finish({ accepted: false, result: `offlineSend: unexpected payload case ${p.case}` });
        return { accepted: false, result: `offlineSend: unexpected payload case ${p.case}` };
      }
    } catch (e) {
      logger.error('[offlineSend] Failed to extract commitment hash:', e);
    }

    if (!commitmentHash || commitmentHash.length !== 32) {
      finish({ accepted: false, result: 'offlineSend: missing commitment hash' });
      return { accepted: false, result: 'offlineSend: missing commitment hash' };
    }

    // --- Drain any events that arrived while we were awaiting the prepare response ---
    for (const buffered of earlyEventBuffer) {
      processEvent(buffered);
    }
    earlyEventBuffer.length = 0;

    // If an early event already resolved the transfer, return immediately
    if (settled && settledResult) {
      return settledResult;
    }

    // --- Await remaining completion events ---
    return await new Promise<GenericTxResponse>((resolve) => {
      resolvePromise = resolve;
      // If finish was called during buffer drain (race), resolve immediately
      if (settled && settledResult) {
        resolve(settledResult);
      }
    });
  } catch (e: any) {
    return {
      accepted: false,
      result: e?.message || 'Failed',
    };
  }
}

// Compatibility wrapper used by UI/service layers that call dsmClient.sendOfflineTransfer(...)
export async function sendOfflineTransfer(params: {
  tokenId: string;
  to: string | Uint8Array;
  amount: string | number | bigint;
  memo?: string;
  bleAddress?: string;
}): Promise<GenericTxResponse> {
  return offlineSend({
    tokenId: canonicalizeTransferTokenId(params.tokenId),
    to: params.to as any,
    amount: params.amount as any,
    memo: params.memo,
    bleAddress: params.bleAddress,
  } as any);
}

export async function acceptOfflineTransfer(args: { commitmentHash: Uint8Array, counterpartyDeviceId: Uint8Array }): Promise<{ success: boolean }> {
  try {
    const response = await acceptBilateralByCommitmentBridge(new Uint8Array(args.commitmentHash));
    // Canonical Envelope v3 decode
    const env2 = decodeFramedEnvelopeV3(response);
    if (env2.payload.case === 'error') {
      const errMsg = env2.payload.value.message || `Error code ${env2.payload.value.code}`;
      logger.error('[DSM] acceptOfflineTransfer failed:', errMsg);
      return { success: false };
    }
    // Emit through the real DOM/native adapter path so all app listeners see
    // the same bilateral acceptance signal as production.
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('dsm-bilateral-committed', {
        detail: {
          commitmentHash: new Uint8Array(args.commitmentHash),
          counterpartyDeviceId: new Uint8Array(args.counterpartyDeviceId),
          accepted: true,
          committed: true,
        },
      }));
    }
    // Also emit the bridge event for consistency with the event system
    try {
      bridgeEvents.emit('wallet.bilateralCommitted', {
        commitmentHash: new Uint8Array(args.commitmentHash),
        counterpartyDeviceId: new Uint8Array(args.counterpartyDeviceId),
        accepted: true,
        committed: true,
      });
    } catch (e) {
      logger.warn('[DSM] Failed to emit bilateral committed event:', e);
    }
    // Don't fire wallet.refresh here — the balance hasn't changed yet (Accept
    // was sent, but Confirm hasn't arrived).  Firing now queries balance=0 and
    // starts the 120-frame cooldown in useWalletRefreshListener, which can
    // throttle the REAL refresh when TRANSFER_COMPLETE arrives milliseconds
    // later.  Instead, schedule staggered priority refreshes that will catch
    // the Confirm's SQLite write once it lands (typically <2s after Accept).
    schedulePostAcceptRefreshes();
    return { success: true };
  } catch (error) {
    logger.error('[DSM] acceptOfflineTransfer error:', error);
    return { success: false };
  }
}

export async function commitOfflineTransfer(_args: { commitmentHash: Uint8Array, counterpartyDeviceId: Uint8Array }): Promise<{ success: boolean }> {
  // Commit is handled by the sender's BLE state machine after accept.
  // JS should not attempt to fabricate signatures.
  logger.warn('[DSM] commitOfflineTransfer is handled natively; JS commit is disabled');
  return { success: false };
}

export async function rejectOfflineTransfer(args: { commitmentHash: Uint8Array, counterpartyDeviceId: Uint8Array, reason?: string }): Promise<{ success: boolean }> {
   try {
     const response = await rejectBilateralByCommitmentBridge(new Uint8Array(args.commitmentHash), String(args.reason || ''));
     // Canonical Envelope v3 decode
     const env3 = decodeFramedEnvelopeV3(response);
     if (env3.payload.case === 'error') {
       const errMsg = env3.payload.value.message || `Error code ${env3.payload.value.code}`;
       logger.error('[DSM] rejectOfflineTransfer failed:', errMsg);
       return { success: false };
     }
   } catch (e) {
     logger.warn('[DSM] rejectOfflineTransfer native reject failed:', e);
     return { success: false };
   }

   return { success: true };
}

export async function getLogicalTick(): Promise<bigint> {
  const resBytes = await appRouterQueryBin('sys.tick');
  const pack = pb.ArgPack.fromBinary(resBytes);
  const tickBytes = pack.body;
  if (tickBytes.length !== 8) {
    throw new Error(`getLogicalTick: expected 8-byte LE u64, got ${tickBytes.length} bytes`);
  }
  const view = new DataView(tickBytes.buffer, tickBytes.byteOffset, tickBytes.byteLength);
  return view.getBigUint64(0, true);
}

export async function sendOnlineMessage(recipientId: string, payload: any): Promise<boolean> {
  try {
    let toBytes: Uint8Array;
    if (typeof recipientId === 'string') {
      toBytes = new Uint8Array(decodeBase32Crockford(recipientId));
    } else if ((recipientId as any) instanceof Uint8Array) {
      toBytes = new Uint8Array(recipientId as any);
    } else {
      throw new Error('Invalid recipientId: must be base32 string or Uint8Array');
    }

    if (toBytes.length !== 32) {
      throw new Error('to_device_id must be 32 bytes');
    }

    const headers = await getHeaders();
    const fromDeviceId = headers.deviceId instanceof Uint8Array ? headers.deviceId : new Uint8Array();
    if (fromDeviceId.length !== 32) {
      throw new Error('from_device_id must be 32 bytes (bridge headers missing)');
    }
    const seq = typeof (headers as any).seq === 'bigint'
      ? (headers as any).seq
      : BigInt((headers as any).seq ?? 0);
    const safeSeq = seq > 0n ? seq : 1n;

    const memo = typeof payload?.memo === 'string' ? payload.memo : '';
    const rawPayload = payload?.data ?? payload;
    let payloadBytes: Uint8Array;
    if (rawPayload instanceof Uint8Array) {
      payloadBytes = rawPayload;
    } else if (rawPayload instanceof ArrayBuffer) {
      payloadBytes = new Uint8Array(rawPayload);
    } else if (typeof rawPayload === 'string') {
      payloadBytes = new TextEncoder().encode(rawPayload);
    } else {
      throw new Error('payload must be Uint8Array, ArrayBuffer, or string');
    }

    const req = new pb.OnlineMessageRequest({
      toDeviceId: toBytes as any,
      payload: payloadBytes as any,
      memo,
      signature: new Uint8Array(0),
      nonce: new Uint8Array(0),
      fromDeviceId: fromDeviceId as any,
      // chain_tip is RESERVED/IGNORED: SDK derives bilateral tip from SQLite
      seq: safeSeq as any,
    } as any);

    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO as any,
      body: new Uint8Array(req.toBinary()),
    });

    const resBytes = await appRouterInvokeBin('message.send', new Uint8Array(argPack.toBinary()));

    // Canonical Envelope v3 decode
    let resp: pb.OnlineMessageResponse | null = null;
    try {
      const env4 = decodeFramedEnvelopeV3(resBytes);
      if (env4.payload.case === 'error') {
        logger.warn('sendOnlineMessage native error:', env4.payload.value.message);
        return false;
      }
      if (env4.payload.case !== 'onlineMessageResponse') {
        logger.warn(`Expected onlineMessageResponse, got ${env4.payload.case}`);
        return false;
      }
      resp = env4.payload.value;
    } catch {
      // ignore
    }
    if (!resp) {
      return false;
    }
    return Boolean(resp.success);
  } catch (e) {
    logger.warn('sendOnlineMessage failed:', e);
    return false;
  }
}

export async function initiateBilateral(payload: any): Promise<boolean> {
  try {
    if (!payload) throw new Error('initiateBilateral: payload required');

    const toRaw = payload.to ?? payload.recipient ?? payload.deviceId;
    if (!toRaw) throw new Error('initiateBilateral: recipient device id required');

    const tokenId = String(payload.tokenId ?? 'ERA');
    const amount = payload.amount ?? payload.value;
    if (amount === undefined || amount === null) {
      throw new Error('initiateBilateral: amount required');
    }

    const memo = typeof payload.memo === 'string' ? payload.memo : '';
    const bleAddress = payload.bleAddress;

    const res = await offlineSend({
      tokenId: canonicalizeTransferTokenId(tokenId),
      to: toRaw as any,
      amount,
      memo,
      bleAddress: typeof bleAddress === 'string' ? bleAddress : undefined,
    });

    return Boolean(res.accepted);
  } catch (e) {
    logger.warn('initiateBilateral failed:', e);
    return false;
  }
}

export async function acceptBilateral(payload: any): Promise<boolean> {
  try {
    if (!payload) throw new Error('acceptBilateral: payload required');

    const commitmentRaw = payload.commitmentHash ?? payload.commitment_hash;
    if (!commitmentRaw) throw new Error('acceptBilateral: commitmentHash required');

    const counterpartyRaw = payload.counterpartyDeviceId;
    if (!counterpartyRaw) throw new Error('acceptBilateral: counterpartyDeviceId required');

    const commitmentHash =
      commitmentRaw instanceof Uint8Array
        ? commitmentRaw
        : new Uint8Array(decodeBase32Crockford(String(commitmentRaw)));
    if (commitmentHash.length !== 32) {
      throw new Error('acceptBilateral: commitmentHash must be 32 bytes');
    }

    const counterpartyDeviceId =
      counterpartyRaw instanceof Uint8Array
        ? counterpartyRaw
        : new Uint8Array(decodeBase32Crockford(String(counterpartyRaw)));
    if (counterpartyDeviceId.length !== 32) {
      throw new Error('acceptBilateral: counterpartyDeviceId must be 32 bytes');
    }

    const result = await acceptOfflineTransfer({
      commitmentHash,
      counterpartyDeviceId,
    });
    return Boolean(result.success);
  } catch (e) {
    logger.warn('acceptBilateral failed:', e);
    return false;
  }
}

export async function transferToken(tokenId: string, recipient: string, amount: number): Promise<boolean> {
  try {
    const token = canonicalizeTransferTokenId(tokenId);
    const amt = amount;
    if (amt === undefined || amt === null || Number.isNaN(Number(amt))) {
      throw new Error('transferToken: amount required');
    }
    const to = String(recipient || '').trim();
    if (!to) throw new Error('transferToken: recipient required');

    const online = await sendOnlineTransfer({ tokenId: token, to, amount: amt, memo: '' });
    if (online.accepted) return true;

    let bleAddress: string | undefined;
    try {
      const contacts = await getContacts();
      const recipientBytes = new Uint8Array(decodeBase32Crockford(to));
      const match = contacts.contacts.find(
        (c) => c.deviceId instanceof Uint8Array && c.deviceId.length === 32 && c.deviceId.every((b, i) => b === recipientBytes[i])
      );
      if (match) {
        bleAddress = await resolveBleAddressForContact(match);
      }
    } catch {
      bleAddress = undefined;
    }

    if (!bleAddress) {
      logger.warn('[transferToken] online failed; no BLE address available for offline send');
      return false;
    }

    const offline = await offlineSend({ tokenId: token, to, amount: amt, memo: '', bleAddress });
    return Boolean(offline.accepted);
  } catch (e) {
    logger.warn('transferToken failed:', e);
    return false;
  }
}

export async function claimFaucet(policyId: string): Promise<{ success: boolean; message: string; tokensReceived: number; nextAvailable?: number; humanScaled?: boolean; _debug?: any }> {
  void policyId;
  try {
    const deviceId = await getDeviceIdBinBridgeAsync();
    if (!deviceId || deviceId.length !== 32) {
      return { success: false, message: 'Faucet claim failed: device_id unavailable', tokensReceived: 0 };
    }
    const deviceIdU8 = new Uint8Array(deviceId);
    const body = new Uint8Array(new pb.FaucetClaimRequest({ deviceId: deviceIdU8 }).toBinary());
    const argPack = new pb.ArgPack({
      schemaHash: undefined,
      codec: pb.Codec.PROTO,
      body,
    });

    const bytes: Uint8Array = await appRouterInvokeBin('faucet.claim', argPack.toBinary());
    const _debug: any = {
      resultBytesLen: bytes?.length ?? 0,
    };

    // CANONICAL PATH: All bridge responses are FramedEnvelopeV3
    let env: pb.Envelope;
    try {
      env = decodeFramedEnvelopeV3(bytes);
      _debug.envelopeVersion = env.version;
      _debug.payloadCase = env.payload.case;
    } catch (e) {
      logger.error('[claimFaucet] Failed to decode FramedEnvelopeV3:', e);
      _debug.decodeException = String(e);
      return { success: false, message: `Faucet claim decode failed: ${e instanceof Error ? e.message : String(e)}`, tokensReceived: 0, _debug };
    }

    // Check for error envelope
    if (env.payload.case === 'error') {
      const err = env.payload.value;
      _debug.errorNote = `envelope error: ${err.message || 'unknown'} (code ${err.code || 0})`;
      return { success: false, message: `Faucet claim failed: ${err.message || 'Unknown error'}`, tokensReceived: 0, _debug };
    }

    // Extract faucet response from envelope
    if (env.payload.case !== 'faucetClaimResponse') {
      logger.error('[claimFaucet] Unexpected payload.case:', env.payload.case);
      _debug.unexpectedCase = env.payload.case;
      return { success: false, message: `Unexpected response type: ${env.payload.case}`, tokensReceived: 0, _debug };
    }

    const resp = env.payload.value;
    if (!resp) {
      _debug.nullResponse = true;
      return { success: false, message: 'Faucet claim response is null', tokensReceived: 0, _debug };
    }

    return {
      success: Boolean(resp.success),
      message: resp.success ? 'Faucet claim ok' : 'Faucet claim failed',
      tokensReceived: Number(resp.tokensReceived ?? 0),
      nextAvailable: Number(resp.nextAvailableIndex ?? 0),
      humanScaled: true,
      _debug,
    };
  } catch (e) {
    return { success: false, message: e instanceof Error ? e.message : String(e), tokensReceived: 0, _debug: { resultBytesLen: 0, decodeNote: 'outer exception' } };
  }
}

export async function getPendingBilateralListStrict(): Promise<{ transactions: pb.OfflineBilateralTransaction[] }> {
  const responseBytes = await getPendingBilateralListStrictBridge();

  // CANONICAL PATH: All bridge responses are FramedEnvelopeV3
  let env: pb.Envelope;
  try {
    env = decodeFramedEnvelopeV3(responseBytes);
  } catch (e) {
    logger.error('[getPendingBilateralListStrict] Failed to decode FramedEnvelopeV3:', e);
    throw new Error(`Failed to decode FramedEnvelopeV3: ${e instanceof Error ? e.message : String(e)}`);
  }

  if (env.payload.case === 'error') {
    const err = env.payload.value;
    throw new Error(`DSM native error (pending-list): code=${err.code} msg=${err.message}`);
  }

  if (env.payload.case !== 'offlineBilateralPendingListResponse') {
    logger.warn('[getPendingBilateralListStrict] Unexpected payload.case:', env.payload.case);
    throw new Error(`Unexpected payload case for pending list: ${env.payload.case}`);
  }

  const resp = env.payload.value;
  if (!resp) {
    throw new Error('offlineBilateralPendingListResponse payload is null');
  }

  return { transactions: resp.transactions ?? [] };
}

/**
 * Claim tokens from the testnet faucet.
 * Wraps FaucetClaimRequest via appRouterInvokeBin('faucet.claim', ...).
 *
 * Note: The native backend handles the actual logic in `transition.rs` and `client_db.rs`,
 * including CPTA verification and balance updates. The frontend just invokes the operation.
 */
export async function claimTestnetFaucet(): Promise<pb.FaucetClaimResponse> {
  logger.info('[transactions.claimTestnetFaucet] INVOKED');
  const deviceId = await getLocalDeviceIdAsync();
  logger.info('[transactions.claimTestnetFaucet] deviceId obtained, length=', deviceId?.length);
  if (!deviceId || deviceId.length !== 32) {
    throw new Error('claimTestnetFaucet: Device ID not available (wallet not initialized?)');
  }

  const req = new pb.FaucetClaimRequest({
    deviceId: deviceId as any,
  });
  logger.debug('[transactions.claimTestnetFaucet] FaucetClaimRequest created');

  const argPack = new pb.ArgPack({
    schemaHash: undefined,
    codec: pb.Codec.PROTO,
    body: new Uint8Array(req.toBinary()),
  });
  logger.debug('[transactions.claimTestnetFaucet] ArgPack created, calling appRouterInvokeBin(faucet.claim, ...)');

  // 'faucet.claim' maps to the FaucetClaimRequest handler in the native AppRouter
  const resBytes = await appRouterInvokeBin('faucet.claim', argPack.toBinary());
  logger.debug('[transactions.claimTestnetFaucet] appRouterInvokeBin returned, resBytes.length=', resBytes.length);

  // Canonical Envelope v3 decode
  const env5 = decodeFramedEnvelopeV3(resBytes);
  if (env5.payload.case === 'error') {
    const errMsg = env5.payload.value.message || `Error code ${env5.payload.value.code}`;
    throw new Error(`claimTestnetFaucet failed: ${errMsg}`);
  }
  if (env5.payload.case !== 'faucetClaimResponse') {
    throw new Error(`Expected faucetClaimResponse, got ${env5.payload.case}`);
  }
  return env5.payload.value;
}
