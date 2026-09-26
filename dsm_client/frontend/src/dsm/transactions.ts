// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as pb from '../proto/dsm_app_pb';
import { decodeBase32Crockford } from '../utils/textId';
import { decodeFramedEnvelopeV3 } from './decoding';
import {
    routerInvokeBin,
    getDeviceIdBinBridgeAsync,
    acceptBilateralByCommitmentBridge,
    cancelBilateralByCommitmentBridge,
    rejectBilateralByCommitmentBridge,
    getPendingBilateralListStrictBridge,
    setBleIdentityForAdvertising,
    startBleAdvertisingViaRouter,
    startBleScanViaRouter,
    readPeerRelationshipStatusBridge,
} from './WebViewBridge';
import { on as eventBridgeOn } from './EventBridge';
import { emitBilateralCommitted } from './events';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { getHeaders } from './identity';

import { normalizeBleAddress } from './resolution';
import logger from '../utils/logger';

import { GenericTransaction, GenericTxResponse } from './types';


/**
 * After the receiver sends Accept, the Confirm arrives within ~1-2 seconds
 * and Rust announces the completed transfer (`bilateral.event`), which the
 * event bridge turns into `wallet.refresh`. These staggered re-reads exist
 * beside that announcement, not instead of it: whether the announcement alone
 * suffices on a device is undecided (CONFORMANCE_GAPS §6.29, Open), so the
 * cadence stays until a device run says. Each re-read names itself.
 *
 * RAF spacing: ~30 frames ≈ 0.5s at 60fps, repeated 4 times ≈ 0/0.5/1/2s.
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
        bridgeEvents.emit('wallet.refresh', { source: 'bilateral.accept_followup' });
      } catch {}
    }
    if (idx < INTERVALS.length) {
      requestAnimationFrame(tick);
    }
  };
  requestAnimationFrame(tick);
}

export async function readPeerRelationshipStatus(
  bleAddress: string,
): Promise<pb.BleRelationshipStatusCharValue | null> {
  const normalized = normalizeBleAddress(bleAddress);
  if (!normalized) return null;
  const bytes = await readPeerRelationshipStatusBridge(normalized);
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    return null;
  }
  return pb.BleRelationshipStatusCharValue.fromBinary(bytes);
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

      const resBytes = await routerInvokeBin('wallet.sendSmart', new Uint8Array(argPack.toBinary()));

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
      bleAddress: normalizeBleAddress(String(transfer.bleAddress || '')) || '',
      transferAmountDisplay,
      // Named exactly as the user chose it; Rust canonicalizes it and refuses
      // a request that names none.
      tokenIdHint: transfer.tokenId,
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
    // Status polling interval: instead of a hard timeout that declares failure,
    // poll the backend session status and only resolve when the backend confirms
    // the session is terminal (committed, failed, or rejected).
    const STATUS_POLL_INTERVAL_MS = 3_000;
    const STATUS_POLL_MAX_ATTEMPTS = 40; // ~2 minutes max

    let commitmentHash: Uint8Array | null = null;
    let settled = false;
    let settledResult: GenericTxResponse | null = null;
    let statusPollTimer: ReturnType<typeof setTimeout> | null = null;
    const earlyEventBuffer: pb.BilateralEventNotification[] = [];
    let resolvePromise: ((res: GenericTxResponse) => void) | null = null;

    const finish = (res: GenericTxResponse) => {
      if (settled) return;
      settled = true;
      settledResult = res;
      if (statusPollTimer) {
        clearTimeout(statusPollTimer);
        statusPollTimer = null;
      }
      offEvent();
      offBle();
      // Re-start advertising so device stays discoverable for next transfer
      void startBleAdvertisingViaRouter().catch(() => {});
      if (resolvePromise) resolvePromise(res);
    };

    // Poll backend for authoritative session status. The backend tracks the
    // real phase (Preparing → Accepted → ConfirmPending → Committed/Failed).
    // Only the backend knows whether the transfer actually succeeded or failed.
    let pollAttempts = 0;
    const pollSessionStatus = async () => {
      if (settled || !commitmentHash) return;
      pollAttempts++;
      try {
        const { decodeOfflinePendingList } = await import('../domain/bilateral');
        const listBytes = await getPendingBilateralListStrictBridge();
        const pending = await decodeOfflinePendingList(listBytes);
        const hashB32 = (await import('../utils/textId')).encodeBase32Crockford(commitmentHash);
        const session = pending.find(p => p.commitmentHash === hashB32);

        // A step the list does not hold has not completed: only its committed
        // phase says that. Keep polling.
        if (session?.phase === 'committed') {
          finish({ accepted: true, result: 'Bilateral transfer complete' });
        } else if (session?.phase === 'failed') {
          finish({ accepted: false, result: 'Bilateral transfer failed' });
        } else if (session?.phase === 'rejected') {
          finish({ accepted: false, result: 'Bilateral transfer rejected' });
        }
      } catch {
        // Query failed — keep polling, don't declare failure
      }
      if (pollAttempts >= STATUS_POLL_MAX_ATTEMPTS && !settled) {
        // The screen stops waiting; the step does not end. A lost link fails
        // no step: it stays open on both devices and completes when they meet
        // again, and until its confirm its proposer may cancel it.
        finish({
          accepted: false,
          open: true,
          result: 'The transfer is still open. It completes when the two phones are together again; Pending transfers shows it.',
        });
        return;
      }
      // Self-schedule the next poll only after this one completes to prevent
      // overlapping concurrent invocations when bridge calls take longer than the interval.
      if (!settled) {
        statusPollTimer = setTimeout(() => { void pollSessionStatus(); }, STATUS_POLL_INTERVAL_MS);
      }
    };

    const processEvent = (note: pb.BilateralEventNotification) => {
      if (settled) return;
      const h = note.commitmentHash instanceof Uint8Array ? note.commitmentHash : undefined;
      if (!h || h.length !== 32) return;
      if (!commitmentHash || !bytesEqual(h, commitmentHash)) return;
      if (note.eventType === pb.BilateralEventType.BILATERAL_EVENT_TRANSFER_COMPLETE) {
        finish({ accepted: true, result: note.message || 'Bilateral transfer complete' });
      } else if (note.eventType === pb.BilateralEventType.BILATERAL_EVENT_REJECTED) {
        finish({ accepted: false, result: note.message || 'Bilateral transfer rejected', failureReason: note.failureReason });
      } else if (note.eventType === pb.BilateralEventType.BILATERAL_EVENT_FAILED) {
        // Don't immediately fail — poll backend to confirm the failure is real.
        // The backend may still be processing (e.g., settlement in progress).
        void pollSessionStatus();
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
    // §2.3-2.4: advertise real genesis hash, not zeros.
    try {
      const headers = await getHeaders();
      const devId = headers.deviceId;
      const genesisHash = headers.genesisHash;
      if (devId && devId.length === 32 && genesisHash && genesisHash.length === 32) {
        await setBleIdentityForAdvertising(new Uint8Array(genesisHash), new Uint8Array(devId));
        await startBleAdvertisingViaRouter();
      }
      await startBleScanViaRouter();
      // Brief pause for BLE stack to settle and peer to discover us
      await new Promise(r => setTimeout(r, 1500));
    } catch {
      // Best-effort — proceed with send even if BLE priming fails
    }

    // --- Delegate native authoring + BLE dispatch to wallet.sendOffline ---
    const respBytes = await routerInvokeBin('wallet.sendOffline', new Uint8Array(argPack.toBinary()));
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

    // Start polling backend for session status. Events are the fast path
    // (instant notification), but polling is the reliable fallback that
    // catches cases where the event was missed or delayed.
    // Use self-scheduling setTimeout (not setInterval) so a slow bridge call
    // never causes concurrent overlapping polls.
    statusPollTimer = setTimeout(() => { void pollSessionStatus(); }, STATUS_POLL_INTERVAL_MS);

    // --- Await remaining completion events or status poll resolution ---
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

// The send screen's entry: dsmClient.sendOfflineTransfer(...)
export async function sendOfflineTransfer(params: {
  tokenId: string;
  to: string | Uint8Array;
  amount: string | number | bigint;
  memo?: string;
  bleAddress?: string;
}): Promise<GenericTxResponse> {
  return offlineSend({
    tokenId: params.tokenId,
    to: params.to,
    amount: params.amount,
    memo: params.memo,
    bleAddress: params.bleAddress,
  });
}

/** What the SDK answered a bilateral accept, reject or cancel: done, or its reason why not. */
export type BilateralActionResult = { success: true } | { success: false; error: string };

/**
 * The SDK's answer to a bilateral action: the envelope `expected` names, or an
 * error carrying the SDK's reason. Anything else is not the action's answer.
 */
function bilateralActionAnswer(
  action: string,
  response: Uint8Array,
  expected: 'bilateralPrepareResponse' | 'bilateralPrepareReject',
): BilateralActionResult {
  const env = decodeFramedEnvelopeV3(response);
  if (env.payload.case === 'error') {
    const error = env.payload.value.message || `error code ${env.payload.value.code}`;
    logger.error(`[DSM] ${action} failed:`, error);
    return { success: false, error };
  }
  if (env.payload.case !== expected) {
    return { success: false, error: `${action}: the SDK answered ${String(env.payload.case)}, not ${expected}` };
  }
  return { success: true };
}

function bilateralActionFailure(action: string, e: unknown): BilateralActionResult {
  logger.error(`[DSM] ${action} error:`, e);
  return { success: false, error: e instanceof Error ? e.message : String(e) };
}

export async function acceptOfflineTransfer(args: { commitmentHash: Uint8Array, counterpartyDeviceId: Uint8Array }): Promise<BilateralActionResult> {
  try {
    const response = await acceptBilateralByCommitmentBridge(new Uint8Array(args.commitmentHash));
    const answer = bilateralActionAnswer('acceptOfflineTransfer', response, 'bilateralPrepareResponse');
    if (!answer.success) {
      return answer;
    }
    // The committed signal, once, on the event bus. It used to be dispatched
    // twice: as a window event the adapter re-emitted here, and here again.
    try {
      emitBilateralCommitted({
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
    return bilateralActionFailure('acceptOfflineTransfer', error);
  }
}

export async function rejectOfflineTransfer(args: { commitmentHash: Uint8Array, counterpartyDeviceId: Uint8Array, reason?: string }): Promise<BilateralActionResult> {
  try {
    const response = await rejectBilateralByCommitmentBridge(new Uint8Array(args.commitmentHash), String(args.reason || ''));
    return bilateralActionAnswer('rejectOfflineTransfer', response, 'bilateralPrepareReject');
  } catch (e) {
    return bilateralActionFailure('rejectOfflineTransfer', e);
  }
}

/**
 * The proposer cancels a proposal it has not confirmed. The SDK decides
 * whether the step may still be cancelled; its refusal comes back as the error.
 */
export async function cancelOfflineTransfer(args: { commitmentHash: Uint8Array, reason?: string }): Promise<BilateralActionResult> {
  try {
    const response = await cancelBilateralByCommitmentBridge(new Uint8Array(args.commitmentHash), String(args.reason || ''));
    return bilateralActionAnswer('cancelOfflineTransfer', response, 'bilateralPrepareReject');
  } catch (e) {
    return bilateralActionFailure('cancelOfflineTransfer', e);
  }
}

/** What `faucet.claim` answered: what Rust released, in its words, or why not. */
export type FaucetClaimResult =
  | { success: true; tokensReceived: bigint; message: string }
  | { success: false; message: string };

/**
 * faucet.claim: this device claims ERA from the faucet for itself (Rust
 * refuses a request naming another device) and reports Rust's answer.
 */
export async function claimFaucet(): Promise<FaucetClaimResult> {
  try {
    const deviceId = await getDeviceIdBinBridgeAsync();
    if (!deviceId || deviceId.length !== 32) {
      return { success: false, message: 'Faucet claim failed: the device id is unavailable' };
    }
    const argPack = new pb.ArgPack({
      codec: pb.Codec.PROTO,
      body: new Uint8Array(new pb.FaucetClaimRequest({ deviceId: new Uint8Array(deviceId) }).toBinary()),
    });
    const env = decodeFramedEnvelopeV3(await routerInvokeBin('faucet.claim', argPack.toBinary()));
    if (env.payload.case === 'error') {
      return { success: false, message: env.payload.value.message };
    }
    if (env.payload.case !== 'faucetClaimResponse') {
      return { success: false, message: `faucet.claim answered ${String(env.payload.case)}, not a claim` };
    }
    const resp = env.payload.value;
    return resp.success
      ? { success: true, tokensReceived: resp.tokensReceived, message: resp.message }
      : { success: false, message: resp.message };
  } catch (e) {
    return { success: false, message: e instanceof Error ? e.message : String(e) };
  }
}

