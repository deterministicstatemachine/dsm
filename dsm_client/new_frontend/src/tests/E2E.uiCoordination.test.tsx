/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * E2E UI Coordination Tests — REAL EVERYTHING, __callBin-only mock
 *
 * WHAT THIS PROVES:
 * The ENTIRE TypeScript stack works end-to-end — from React components down to
 * the JNI bridge boundary. The ONLY mock is window.DsmBridge.__callBin, which
 * is the actual Android/Kotlin JNI entry point.
 *
 * WHAT'S REAL (NOT MOCKED):
 * - BilateralTransferDialog (REAL React component)
 * - WalletProvider / useWallet (REAL React context with real refreshAll)
 * - UXProvider (REAL)
 * - dsmClient.getAllBalances() → dsm/wallet.ts::getAllBalances() → WebViewBridge::getAllBalancesStrictBridge() → callBin() → __callBin (mock)
 * - dsmClient.getWalletHistory() → dsm/wallet.ts::getWalletHistory() → WebViewBridge::getWalletHistoryStrictBridge() → appRouterQueryBin() → __callBin (mock)
 * - dsmClient.getIdentity() → dsm/identity.ts::getIdentity() → getHeaders() → getTransportHeadersV3Bin() → __callBin (mock)
 * - dsmClient.isReady() → hasIdentity() → checkIdentityState() → __callBin (mock)
 * - acceptIncomingTransfer() → acceptOfflineTransfer() → acceptBilateralByCommitmentBridge() → callBin() → __callBin (mock)
 * - rejectIncomingTransfer() → rejectOfflineTransfer() → rejectBilateralByCommitmentBridge() → sendBridgeRequestBytes() → __callBin (mock)
 * - EventBridge (REAL — initializeEventBridge)
 * - nativeBridgeAdapter (REAL — initializeNativeBridgeAdapter)
 * - bridgeEvents (REAL pub/sub)
 * - useEventSignal (REAL useSyncExternalStore)
 * - useWalletSync (REAL event→dispatch routing)
 * - BridgeGate (REAL — auto-opens for __callBin paths)
 * - decodeFramedEnvelopeV3, decodeBalancesListResponseStrict (REAL decoders)
 *
 * COVERAGE:
 * 1. BridgeEventBus — typed delivery, multi-subscriber, error isolation
 * 2. useEventSignal — useSyncExternalStore, no tearing
 * 3. Bilateral event encode/decode roundtrip (protobuf)
 * 4. DOM event → nativeBridgeAdapter → bridgeEvents (REAL adapter)
 * 5. DOM event → EventBridge → bilateral.event (REAL EventBridge)
 * 6. INTEGRATED: Dialog + WalletContext — PREPARE → Accept → COMPLETE → refreshAll → REAL getAllBalances → __callBin → proto decode → balance in DOM
 * 7. INTEGRATED: wallet.sendCommitted → WalletContext refresh trigger only
 * 8. INTEGRATED: Full bilateral sequence through REAL components — EXACT device sequence
 */

import React from 'react';
import { render, act, waitFor, screen, fireEvent } from '@testing-library/react';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { useEventSignal } from '../bridge/useEventSignal';
import * as pb from '../proto/dsm_app_pb';
import { emit as eventBridgeEmit, on as eventBridgeOn, initializeEventBridge } from '../dsm/EventBridge';
import { initializeNativeBridgeAdapter } from '../bridge/nativeBridgeAdapter';
import {
  BilateralEventType,
  encodeBilateralEventNotification,
  decodeBilateralEvent,
} from '../services/bilateral/bilateralEventService';
import { setBridgeInstance } from '../bridge/BridgeRegistry';

// ─── Constants ───────────────────────────────────────────────────────────────

const DEVICE_ID = new Uint8Array(32).fill(0x11);
const GENESIS_HASH = new Uint8Array(32).fill(0x22);
const CHAIN_TIP = new Uint8Array(32).fill(0xCC);

// ─── Proto Helpers ───────────────────────────────────────────────────────────

function makeCommitmentHash(fill: number = 0xAA): Uint8Array {
  return new Uint8Array(32).fill(fill);
}
function makeDeviceId(fill: number = 0xBB): Uint8Array {
  return new Uint8Array(32).fill(fill);
}
function makeTxHash(fill: number = 0xCC): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

/** Build a BridgeRpcResponse with success data */
function wrapSuccess(data: Uint8Array): Uint8Array {
  return (global as any).createDsmBridgeSuccessResponse(data);
}

/** Build a BridgeRpcResponse with error */
function wrapError(msg: string): Uint8Array {
  return (global as any).createDsmBridgeErrorResponse(msg);
}

/** Decode a BridgeRpcRequest to extract method and router method name */
function decodeBridgeReq(reqBytes: Uint8Array): { method: string; payload: Uint8Array; routerMethod?: string } {
  const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
  let payload = new Uint8Array(0);
  let routerMethod: string | undefined;

  if (req.payload?.case === 'bytes') {
    payload = req.payload.value.data || new Uint8Array(0);
  } else if (req.payload?.case === 'appRouter') {
    routerMethod = (req.payload.value as any).methodName;
    payload = (req.payload.value as any).args || new Uint8Array(0);
  } else if (req.payload?.case === 'bilateral') {
    const bp = req.payload.value as any;
    payload = bp.commitment || new Uint8Array(0);
  }
  return { method: req.method, payload, routerMethod };
}

/** Wrap Envelope in 0x03 framing prefix (FramedEnvelopeV3 format) */
function frameEnvelope(env: pb.Envelope): Uint8Array {
  const bytes = env.toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  return framed;
}

/** Add 8-byte router request-id prefix */
function withRouterPrefix(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + data.length);
  out.set(data, 8);
  return out;
}

/** Build FramedEnvelopeV3 containing a BalancesListResponse */
function makeBalancesFramedEnvelope(balances: Array<{ tokenId: string; available: bigint }>): Uint8Array {
  const balList = balances.map(b => new pb.BalanceGetResponse({
    tokenId: b.tokenId,
    available: b.available as any,
    locked: 0n as any,
  } as any));
  const resp = new pb.BalancesListResponse({ balances: balList } as any);
  const env = new pb.Envelope({
    version: 3,
    payload: { case: 'balancesListResponse', value: resp },
  } as any);
  return frameEnvelope(env);
}

/** Build FramedEnvelopeV3 containing a WalletHistoryResponse */
function makeHistoryFramedEnvelope(transactions: Array<{ amount: bigint; amountSigned: bigint }>): Uint8Array {
  const txList = transactions.map(t => new pb.TransactionInfo({
    id: `tx-${Math.random().toString(36).slice(2, 8)}`,
    amount: t.amount as any,
    amountSigned: t.amountSigned as any,
  } as any));
  const resp = new pb.WalletHistoryResponse({ transactions: txList } as any);
  const env = new pb.Envelope({
    version: 3,
    payload: { case: 'walletHistoryResponse', value: resp },
  } as any);
  return frameEnvelope(env);
}

/** Build FramedEnvelopeV3 with a simple success (universalRx accepted) */
function makeSuccessFramedEnvelope(): Uint8Array {
  const rx = new pb.UniversalRx({
    results: [new pb.OpResult({ accepted: true } as any)],
  });
  const env = new pb.Envelope({
    version: 3,
    payload: { case: 'universalRx', value: rx },
  } as any);
  return frameEnvelope(env);
}

// ─── __callBin Mock State ────────────────────────────────────────────────────

/** Mutable state that tests can modify to change what __callBin returns */
let balancesState: Array<{ tokenId: string; available: bigint }> = [
  { tokenId: 'ERA', available: 10000n },
];
let historyState: Array<{ amount: bigint; amountSigned: bigint }> = [
  { amount: 100n, amountSigned: 100n },
];
let capturedMethods: string[] = [];

/** Install a __callBin mock that handles the full protocol */
function installCallBinMock() {
  const g = global as any;
  g.window = g.window || {};

  const bridge = {
    __binary: true,
    __callBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
      const { method, payload, routerMethod } = decodeBridgeReq(reqBytes);
      capturedMethods.push(method);

      // --- Direct bridge methods ---

      if (method === 'hasIdentityDirect') {
        return wrapSuccess(new Uint8Array([0x01])); // identity exists
      }

      if (method === 'getTransportHeadersV3Bin') {
        const headers = new pb.Headers({
          deviceId: DEVICE_ID as any,
          genesisHash: GENESIS_HASH as any,
          chainTip: CHAIN_TIP as any,
          seq: 1n as any,
        } as any);
        return wrapSuccess(headers.toBinary());
      }

      if (method === 'getAllBalancesStrict') {
        // Returns FramedEnvelopeV3 directly (no router prefix)
        return wrapSuccess(makeBalancesFramedEnvelope(balancesState));
      }

      if (method === 'acceptBilateralByCommitment') {
        // Returns FramedEnvelopeV3 with success
        return wrapSuccess(makeSuccessFramedEnvelope());
      }

      if (method === 'rejectBilateralByCommitment') {
        // Returns FramedEnvelopeV3 with success
        return wrapSuccess(makeSuccessFramedEnvelope());
      }

      if (method === 'getPreference' || method === 'setPreference') {
        return wrapSuccess(new Uint8Array(0));
      }

      // --- Router methods (responses include 8-byte request-id prefix) ---

      if (method === 'appRouterQuery') {
        if (routerMethod === 'wallet.history') {
          // Returns 8-byte prefix + FramedEnvelopeV3
          return wrapSuccess(withRouterPrefix(makeHistoryFramedEnvelope(historyState)));
        }
        if (routerMethod === 'bitcoin.balance') {
          // Return a valid BalanceGetResponse for dBTC (zero balance)
          const resp = new pb.BalanceGetResponse({
            tokenId: 'BTC_CHAIN',
            available: 0n as any,
            locked: 0n as any,
          } as any);
          const env = new pb.Envelope({
            version: 3,
            payload: { case: 'balanceGetResponse', value: resp },
          } as any);
          return wrapSuccess(withRouterPrefix(frameEnvelope(env)));
        }
        if (routerMethod === 'prefs.get' || routerMethod === 'prefs.set') {
          return wrapSuccess(withRouterPrefix(new Uint8Array(0)));
        }
        // Default router query: empty
        return wrapSuccess(withRouterPrefix(new Uint8Array(0)));
      }

      if (method === 'appRouterInvoke') {
        return wrapSuccess(withRouterPrefix(makeSuccessFramedEnvelope()));
      }

      // Default: error for unknown methods
      return wrapError(`Method '${method}' not handled in UI coordination test mock`);
    },
    sendMessageBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
      return bridge.__callBin(reqBytes);
    },
    getAppRouterStatus: () => 1,
    hasIdentityDirect: () => true,
  };

  g.window.DsmBridge = bridge;
  setBridgeInstance(bridge);
}

// ─── Initialization ──────────────────────────────────────────────────────────

// Initialize REAL adapters (same as production app bootstrap)
initializeNativeBridgeAdapter();
initializeEventBridge();

async function settleWalletInit(): Promise<void> {
  await act(async () => {
    jest.runOnlyPendingTimers();
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function settleWalletEffects(rounds: number = 2): Promise<void> {
  for (let i = 0; i < rounds; i += 1) {
    await act(async () => {
      jest.runOnlyPendingTimers();
      await Promise.resolve();
      await Promise.resolve();
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. BridgeEventBus — Core Event Delivery
// ═══════════════════════════════════════════════════════════════════════════════

describe('BridgeEventBus — core event delivery', () => {
  test('emit delivers payload to subscriber', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.refresh', spy);
    bridgeEvents.emit('wallet.refresh', { source: 'test' });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith({ source: 'test' });
    unsub();
  });

  test('unsubscribe prevents further delivery', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.refresh', spy);
    unsub();
    bridgeEvents.emit('wallet.refresh', { source: 'test' });
    expect(spy).not.toHaveBeenCalled();
  });

  test('multiple subscribers all receive events', () => {
    const spy1 = jest.fn();
    const spy2 = jest.fn();
    const spy3 = jest.fn();
    const u1 = bridgeEvents.on('wallet.refresh', spy1);
    const u2 = bridgeEvents.on('wallet.refresh', spy2);
    const u3 = bridgeEvents.on('wallet.refresh', spy3);
    bridgeEvents.emit('wallet.refresh', { source: 'multi' });
    expect(spy1).toHaveBeenCalledTimes(1);
    expect(spy2).toHaveBeenCalledTimes(1);
    expect(spy3).toHaveBeenCalledTimes(1);
    u1(); u2(); u3();
  });

  test('subscriber error does not break other subscribers', () => {
    const spy1 = jest.fn(() => { throw new Error('boom'); });
    const spy2 = jest.fn();
    const u1 = bridgeEvents.on('wallet.refresh', spy1 as any);
    const u2 = bridgeEvents.on('wallet.refresh', spy2);
    bridgeEvents.emit('wallet.refresh', { source: 'error-test' });
    expect(spy1).toHaveBeenCalled();
    expect(spy2).toHaveBeenCalled();
    u1(); u2();
  });

  test('bilateral.event delivers Uint8Array payload', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('bilateral.event', spy);
    const payload = new Uint8Array([1, 2, 3, 4]);
    bridgeEvents.emit('bilateral.event', payload);
    expect(spy).toHaveBeenCalledWith(payload);
    unsub();
  });

  test('wallet.bilateralCommitted carries typed payload', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.bilateralCommitted', spy);
    bridgeEvents.emit('wallet.bilateralCommitted', {
      commitmentHash: makeCommitmentHash(),
      counterpartyDeviceId: makeDeviceId(),
      accepted: true,
      committed: true,
    });
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      accepted: true,
      committed: true,
    }));
    unsub();
  });

  test('wallet.sendCommitted carries balance and tx info', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.sendCommitted', spy);
    bridgeEvents.emit('wallet.sendCommitted', {
      success: true,
      tokenId: 'ERA',
      newBalance: 9500n,
      transactionHash: makeTxHash(),
      toDeviceId: makeDeviceId(),
      amount: 500n,
    });
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      success: true,
      tokenId: 'ERA',
      newBalance: 9500n,
      amount: 500n,
    }));
    unsub();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. useEventSignal — React External Store Integration
// ═══════════════════════════════════════════════════════════════════════════════

describe('useEventSignal — React external store integration', () => {
  test('initial value is 0', () => {
    const C: React.FC = () => {
      const s = useEventSignal('test.signal.init.unique');
      return <div data-testid="sig">{s}</div>;
    };
    render(<C />);
    expect(screen.getByTestId('sig').textContent).toBe('0');
  });

  test('increments on bridge event emission', async () => {
    const C: React.FC = () => {
      const s = useEventSignal('wallet.bilateralCommitted');
      return <div data-testid="sig2">{s}</div>;
    };
    const { unmount } = render(<C />);
    act(() => { bridgeEvents.emit('wallet.bilateralCommitted', {} as any); });
    await waitFor(() => {
      expect(parseInt(screen.getByTestId('sig2').textContent || '0')).toBeGreaterThan(0);
    });
    unmount();
  });

  test('multiple emissions increment monotonically', async () => {
    const C: React.FC = () => {
      const s = useEventSignal('wallet.refresh');
      return <div data-testid="sig3">{s}</div>;
    };
    const { unmount } = render(<C />);
    act(() => { bridgeEvents.emit('wallet.refresh', { source: '1' }); });
    act(() => { bridgeEvents.emit('wallet.refresh', { source: '2' }); });
    act(() => { bridgeEvents.emit('wallet.refresh', { source: '3' }); });
    await waitFor(() => {
      expect(parseInt(screen.getByTestId('sig3').textContent || '0')).toBeGreaterThanOrEqual(3);
    });
    unmount();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Bilateral Event Service — Encode/Decode Roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

describe('Bilateral event service — encode/decode roundtrip', () => {
  test('PREPARE_RECEIVED roundtrips correctly', () => {
    const payload = encodeBilateralEventNotification({
      eventType: BilateralEventType.PREPARE_RECEIVED,
      status: 'pending',
      message: 'incoming transfer',
      amount: 250n,
      tokenId: 'ERA',
      counterpartyDeviceId: makeDeviceId(0x11),
      commitmentHash: makeCommitmentHash(0x22),
      senderBleAddress: 'AA:BB:CC:DD:EE:FF',
    });
    expect(payload).toBeInstanceOf(Uint8Array);
    const decoded = decodeBilateralEvent(payload);
    expect(decoded).not.toBeNull();
    expect(decoded!.eventType).toBe(BilateralEventType.PREPARE_RECEIVED);
    expect(decoded!.amount).toBe(250n);
    expect(decoded!.tokenId).toBe('ERA');
    expect(decoded!.senderBleAddress).toBe('AA:BB:CC:DD:EE:FF');
    expect(decoded!.counterpartyDeviceId.length).toBeGreaterThan(0);
    expect(decoded!.commitmentHash.length).toBeGreaterThan(0);
  });

  test('TRANSFER_COMPLETE roundtrips correctly', () => {
    const payload = encodeBilateralEventNotification({
      eventType: BilateralEventType.TRANSFER_COMPLETE,
      status: 'completed',
      message: 'done',
      transactionHash: makeTxHash(0x55),
    });
    const decoded = decodeBilateralEvent(payload);
    expect(decoded).not.toBeNull();
    expect(decoded!.eventType).toBe(BilateralEventType.TRANSFER_COMPLETE);
    expect(decoded!.transactionHash!.length).toBeGreaterThan(0);
  });

  test('REJECTED roundtrips', () => {
    const decoded = decodeBilateralEvent(encodeBilateralEventNotification({
      eventType: BilateralEventType.REJECTED,
      status: 'rejected',
      message: 'user declined',
    }));
    expect(decoded!.eventType).toBe(BilateralEventType.REJECTED);
    expect(decoded!.message).toBe('user declined');
  });

  test('all 6 event types encode and decode', () => {
    const types = [
      BilateralEventType.PREPARE_RECEIVED,
      BilateralEventType.ACCEPT_SENT,
      BilateralEventType.COMMIT_RECEIVED,
      BilateralEventType.TRANSFER_COMPLETE,
      BilateralEventType.REJECTED,
      BilateralEventType.FAILED,
    ];
    for (const t of types) {
      const decoded = decodeBilateralEvent(encodeBilateralEventNotification({
        eventType: t, status: `s${t}`, message: `m${t}`,
      }));
      expect(decoded).not.toBeNull();
      expect(decoded!.eventType).toBe(t);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. nativeBridgeAdapter — REAL DOM → bridgeEvents Translation
// ═══════════════════════════════════════════════════════════════════════════════

describe('nativeBridgeAdapter — REAL DOM → bridgeEvents translation', () => {
  test('REAL: dsm-bilateral-committed DOM event → wallet.bilateralCommitted', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.bilateralCommitted', spy);
    window.dispatchEvent(new CustomEvent('dsm-bilateral-committed', {
      detail: { commitmentHash: makeCommitmentHash(0x11), counterpartyDeviceId: makeDeviceId(0x22), accepted: true },
    }));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ accepted: true }));
    unsub();
  });

  test('REAL: dsm-wallet-refresh DOM event → wallet.refresh', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.refresh', spy);
    window.dispatchEvent(new CustomEvent('dsm-wallet-refresh', { detail: { source: 'dom-test' } }));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ source: 'dom-test' }));
    unsub();
  });

  test('REAL: dsm-wallet-send-committed DOM event → wallet.sendCommitted', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.sendCommitted', spy);
    window.dispatchEvent(new CustomEvent('dsm-wallet-send-committed', {
      detail: { success: true, tokenId: 'ERA', newBalance: 5000n, amount: 1000n },
    }));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ success: true, tokenId: 'ERA' }));
    unsub();
  });

  test('REAL: dsm-identity-ready DOM event → identity.ready', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('identity.ready', spy);
    document.dispatchEvent(new CustomEvent('dsm-identity-ready'));
    expect(spy).toHaveBeenCalledTimes(1);
    unsub();
  });

  test('REAL: dsm-history-updated DOM event → wallet.historyUpdated', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.historyUpdated', spy);
    window.dispatchEvent(new CustomEvent('dsm-history-updated'));
    expect(spy).toHaveBeenCalledTimes(1);
    unsub();
  });

  test('REAL: dsm-balances-updated DOM event → wallet.balancesUpdated', () => {
    const spy = jest.fn();
    const unsub = bridgeEvents.on('wallet.balancesUpdated', spy);
    window.dispatchEvent(new CustomEvent('dsm-balances-updated'));
    expect(spy).toHaveBeenCalledTimes(1);
    unsub();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. EventBridge — REAL DOM → EventBridge → subscribers
// ═══════════════════════════════════════════════════════════════════════════════

describe('EventBridge — REAL DOM event-bin propagation', () => {
  test('REAL: dsm-event-bin with topic=bilateral.event → EventBridge subscribers', () => {
    const spy = jest.fn();
    const unsub = eventBridgeOn('bilateral.event', spy);
    const payload = encodeBilateralEventNotification({
      eventType: BilateralEventType.PREPARE_RECEIVED,
      status: 'pending',
      message: 'DOM event test',
      amount: 42n,
      tokenId: 'ERA',
    });
    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'bilateral.event', payload },
    }));
    expect(spy).toHaveBeenCalledTimes(1);
    const received = spy.mock.calls[0][0];
    expect(received).toBeInstanceOf(Uint8Array);
    const decoded = decodeBilateralEvent(received);
    expect(decoded).not.toBeNull();
    expect(decoded!.eventType).toBe(BilateralEventType.PREPARE_RECEIVED);
    expect(decoded!.amount).toBe(42n);
    unsub();
  });

  test('REAL: dsm-event-bin TRANSFER_COMPLETE also triggers wallet.refresh on bridgeEvents', () => {
    const refreshSpy = jest.fn();
    const unsub = bridgeEvents.on('wallet.refresh', refreshSpy);
    const payload = encodeBilateralEventNotification({
      eventType: BilateralEventType.TRANSFER_COMPLETE,
      status: 'completed',
      message: 'complete via DOM',
    });
    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'bilateral.event', payload },
    }));
    expect(refreshSpy).toHaveBeenCalledWith(
      expect.objectContaining({ source: 'bilateral.transfer_complete' })
    );
    unsub();
  });

  test('REAL: EventBridge.emit delivers to subscribers (internal pub/sub)', () => {
    const spy = jest.fn();
    const unsub = eventBridgeOn('bilateral.event', spy);
    const payload = encodeBilateralEventNotification({
      eventType: BilateralEventType.ACCEPT_SENT,
      status: 'accepted',
      message: 'internal emit test',
    });
    eventBridgeEmit('bilateral.event', payload);
    expect(spy).toHaveBeenCalledTimes(1);
    unsub();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. INTEGRATED: BilateralTransferDialog + WalletProvider — __callBin-only Mock
//    The ENTIRE TypeScript chain is REAL. Only __callBin is mocked.
// ═══════════════════════════════════════════════════════════════════════════════

describe('INTEGRATED: Full chain with __callBin-only mock', () => {
  // NO jest.mock() for bilateralEventService — it's REAL!
  // acceptIncomingTransfer → acceptOfflineTransfer → acceptBilateralByCommitmentBridge → callBin → __callBin (mocked)
  // rejectIncomingTransfer → rejectOfflineTransfer → rejectBilateralByCommitmentBridge → sendBridgeRequestBytes → __callBin (mocked)

  // Dynamic imports to avoid module initialization order issues
  let BilateralTransferDialog: any;
  let WalletProvider: any;
  let useWallet: any;
  let UXProvider: any;

  beforeAll(() => {
    // Install bridge first so module initialization finds it
    installCallBinMock();

    // Import REAL modules (no mocks)
    const dialogMod = require('../components/BilateralTransferDialog');
    BilateralTransferDialog = dialogMod.BilateralTransferDialog;
    const walletMod = require('../contexts/WalletContext');
    WalletProvider = walletMod.WalletProvider;
    useWallet = walletMod.useWallet;
    UXProvider = require('../contexts/UXContext').UXProvider;
  });

  // Helper: reads wallet state and renders it for assertions
  const WalletStateReader: React.FC = () => {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    const wallet = useWallet();
    return (
      <div>
        <span data-testid="i-bal-count">{wallet.balances?.length ?? 0}</span>
        <span data-testid="i-tx-count">{wallet.transactions?.length ?? 0}</span>
        <span data-testid="i-initialized">{String(wallet.isInitialized)}</span>
        <span data-testid="i-balance-era">
          {wallet.balances?.find((b: any) => b.tokenId === 'ERA')?.balance?.toString() ?? 'none'}
        </span>
      </div>
    );
  };

  // The production layout: WalletProvider wraps Dialog + wallet state UI
  const ProductionLayout: React.FC = () => (
    <UXProvider>
      <WalletProvider>
        <BilateralTransferDialog />
        <WalletStateReader />
      </WalletProvider>
    </UXProvider>
  );

  beforeEach(() => {
    jest.useFakeTimers();
    capturedMethods = [];

    // Reset balance and history state
    balancesState = [{ tokenId: 'ERA', available: 10000n }];
    historyState = [{ amount: 100n, amountSigned: 100n }];

    // Clear identity cache
    (global as any).__dsmLastGoodHeaders = { deviceId: undefined, genesisHash: undefined, chainTip: undefined };

    // Re-install bridge mock (in case previous test modified it)
    installCallBinMock();
  });

  afterEach(async () => {
    await settleWalletEffects();
    jest.useRealTimers();
  });

  test('WalletProvider initializes by calling REAL getAllBalances → __callBin', async () => {
    render(<ProductionLayout />);
    await settleWalletInit();

    // Wait for the REAL init chain: isReady → getIdentity → getAllBalances → getWalletHistory
    await waitFor(() => {
      expect(screen.getByTestId('i-balance-era').textContent).not.toBe('none');
    });

    // The balance came from __callBin via: dsmClient.getAllBalances() → dsm.getAllBalances()
    // → getAllBalancesStrictBridge() → callBin('getAllBalancesStrict') → __callBin → FramedEnvelopeV3
    // → decodeBalancesListResponseStrict() → TokenBalanceView[]
    // PROVES the entire decode chain works.
    const balText = screen.getByTestId('i-balance-era').textContent;
    expect(balText).toBe('10000');

    // Verify __callBin was actually called with the expected methods
    expect(capturedMethods).toContain('getAllBalancesStrict');
    expect(capturedMethods).toContain('getTransportHeadersV3Bin');
  });

  test('PREPARE_RECEIVED → Dialog shows → Accept → REAL acceptIncomingTransfer → __callBin', async () => {
    const { container } = render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).not.toBe('none'));

    // Initially no dialog
    expect(container.querySelector('.bilateral-transfer-dialog')).toBeNull();

    // Emit PREPARE_RECEIVED via EventBridge (same path as on device)
    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'incoming transfer',
        amount: 500n,
        tokenId: 'ERA',
        counterpartyDeviceId: makeDeviceId(0x11),
        commitmentHash: makeCommitmentHash(0x22),
        senderBleAddress: 'AA:BB:CC:DD:EE:FF',
      }));
    });

    // Dialog should appear
    await waitFor(() => {
      expect(container.querySelector('.bilateral-transfer-dialog')).not.toBeNull();
    });
    expect(container.textContent).toContain('500');
    expect(container.textContent).toContain('ERA');
    expect(screen.getByText('Accept')).toBeInTheDocument();
    expect(screen.getByText('Reject')).toBeInTheDocument();

    // Clear captured methods to track what Accept triggers
    capturedMethods = [];

    // Click Accept — calls REAL handleAccept → REAL acceptIncomingTransfer
    // → REAL acceptOfflineTransfer → REAL acceptBilateralByCommitmentBridge → callBin → __callBin
    await act(async () => {
      fireEvent.click(screen.getByText('Accept'));
    });

    // Verify __callBin received acceptBilateralByCommitment
    expect(capturedMethods).toContain('acceptBilateralByCommitment');

    // Dialog clears after successful accept
    await waitFor(() => {
      expect(container.querySelector('.bilateral-transfer-dialog')).toBeNull();
    });
  });

  test('PREPARE → Reject → REAL rejectIncomingTransfer → __callBin', async () => {
    const { container } = render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).not.toBe('none'));

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'reject test',
        amount: 200n,
        counterpartyDeviceId: makeDeviceId(0x55),
        commitmentHash: makeCommitmentHash(0x66),
      }));
    });

    await waitFor(() => expect(screen.getByText('Reject')).toBeInTheDocument());

    capturedMethods = [];

    await act(async () => {
      fireEvent.click(screen.getByText('Reject'));
    });

    // Verify __callBin received rejectBilateralByCommitment
    expect(capturedMethods).toContain('rejectBilateralByCommitment');

    await waitFor(() => {
      expect(container.querySelector('.bilateral-transfer-dialog')).toBeNull();
    });
  });

  test('TRANSFER_COMPLETE → Dialog clears + REAL refreshAll → __callBin returns new balance → DOM updates', async () => {
    const { container } = render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).toBe('10000'));

    // Show dialog first
    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'will complete',
        amount: 300n,
        counterpartyDeviceId: makeDeviceId(0x77),
        commitmentHash: makeCommitmentHash(0x88),
      }));
    });
    await waitFor(() => expect(container.querySelector('.bilateral-transfer-dialog')).not.toBeNull());

    // CHANGE what __callBin returns for the NEXT getAllBalancesStrict call
    // This simulates the balance updating in the native layer after transfer
    balancesState = [{ tokenId: 'ERA', available: 10300n }];
    historyState = [
      { amount: 300n, amountSigned: 300n },
      { amount: 100n, amountSigned: 100n },
    ];

    capturedMethods = [];

    // Emit TRANSFER_COMPLETE — this is the critical moment:
    // BilateralTransferDialog.handleComplete → refreshAll() → WalletProvider's REAL refreshAll()
    // → dsmClient.getAllBalances() → dsm.getAllBalances() → getAllBalancesStrictBridge()
    // → callBin('getAllBalancesStrict') → __callBin → FramedEnvelopeV3(10300)
    // → decodeBalancesListResponseStrict() → mapBalanceList() → dispatch SET_BALANCES → DOM updates
    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.TRANSFER_COMPLETE,
        status: 'completed',
        message: 'transfer done',
        commitmentHash: makeCommitmentHash(0x88),
      }));
    });

    // Dialog should be cleared
    await waitFor(() => expect(container.querySelector('.bilateral-transfer-dialog')).toBeNull());

    // KEY ASSERTION: __callBin was called for the refresh
    await waitFor(() => {
      expect(capturedMethods).toContain('getAllBalancesStrict');
    });

    // KEY ASSERTION: The new balance (10300) from __callBin should appear in the DOM
    // This proves the ENTIRE chain works:
    // TRANSFER_COMPLETE event → Dialog.handleComplete → refreshAll() → dsmClient.getAllBalances()
    // → dsm/wallet.ts::getAllBalances() → getAllBalancesStrictBridge() → callBin('getAllBalancesStrict')
    // → __callBin → BridgeRpcResponse → unwrapProtobufResponse → FramedEnvelopeV3
    // → decodeBalancesListResponseStrict → TokenBalanceView[] → mapBalanceList → dispatch SET_BALANCES → DOM
    await waitFor(() => {
      expect(screen.getByTestId('i-balance-era').textContent).toBe('10300');
    });

    // Transaction count should reflect updated history
    await waitFor(() => {
      expect(parseInt(screen.getByTestId('i-tx-count').textContent || '0')).toBe(2);
    });
  });

  test('REJECTED clears dialog WITHOUT triggering balance refresh', async () => {
    const { container } = render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).toBe('10000'));

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'will reject',
        amount: 150n,
        counterpartyDeviceId: makeDeviceId(0x99),
        commitmentHash: makeCommitmentHash(0xAA),
      }));
    });
    await waitFor(() => expect(container.querySelector('.bilateral-transfer-dialog')).not.toBeNull());

    capturedMethods = [];

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.REJECTED,
        status: 'rejected',
        message: 'counterparty rejected',
      }));
    });

    await waitFor(() => expect(container.querySelector('.bilateral-transfer-dialog')).toBeNull());

    // getAllBalancesStrict should NOT have been called for a rejection
    expect(capturedMethods.filter(m => m === 'getAllBalancesStrict')).toHaveLength(0);
  });

  test('FAILED clears dialog WITHOUT triggering balance refresh', async () => {
    const { container } = render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).not.toBe('none'));

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'will fail',
        amount: 75n,
        counterpartyDeviceId: makeDeviceId(0xBB),
        commitmentHash: makeCommitmentHash(0xCC),
      }));
    });
    await waitFor(() => expect(container.querySelector('.bilateral-transfer-dialog')).not.toBeNull());

    capturedMethods = [];

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.FAILED,
        status: 'failed',
        message: 'BLE disconnected',
      }));
    });

    await waitFor(() => expect(container.querySelector('.bilateral-transfer-dialog')).toBeNull());
    expect(capturedMethods.filter(m => m === 'getAllBalancesStrict')).toHaveLength(0);
  });

  test('incoming transfer dialog exposes current Accept/Reject actions', async () => {
    const { container } = render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).not.toBe('none'));

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'dismiss test',
        amount: 50n,
        counterpartyDeviceId: makeDeviceId(0xDD),
        commitmentHash: makeCommitmentHash(0xEE),
      }));
    });
    await waitFor(() => expect(screen.getByText('Accept')).toBeInTheDocument());
    expect(screen.getByText('Reject')).toBeInTheDocument();
    expect(container.querySelector('.bilateral-transfer-dialog')).not.toBeNull();
  });

  test('inbox.open hides overlay, close restores it', async () => {
    const { container } = render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).not.toBe('none'));

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'inbox test',
        amount: 25n,
        counterpartyDeviceId: makeDeviceId(0xFF),
        commitmentHash: makeCommitmentHash(0x01),
      }));
    });
    await waitFor(() => expect(container.querySelector('.bilateral-transfer-overlay')).not.toBeNull());

    act(() => { bridgeEvents.emit('inbox.open', { open: true }); });
    await waitFor(() => expect(container.querySelector('.bilateral-transfer-overlay')).toBeNull());

    act(() => { bridgeEvents.emit('inbox.open', { open: false }); });
    await waitFor(() => expect(container.querySelector('.bilateral-transfer-overlay')).not.toBeNull());
  });

  test('wallet.bilateralCommitted → WalletProvider refreshes (REAL __callBin round trip)', async () => {
    render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).toBe('10000'));

    // Change what __callBin will return on next balance fetch
    balancesState = [{ tokenId: 'ERA', available: 10500n }];
    capturedMethods = [];

    // Emit wallet.bilateralCommitted — useEventSignal triggers refreshAll
    act(() => {
      bridgeEvents.emit('wallet.bilateralCommitted', { accepted: true, committed: true } as any);
    });

    // Wait for REAL getAllBalances → __callBin round trip
    await waitFor(() => {
      expect(capturedMethods).toContain('getAllBalancesStrict');
    });

    // Balance should update in UI from __callBin's response
    await waitFor(() => {
      expect(screen.getByTestId('i-balance-era').textContent).toBe('10500');
    });

    await settleWalletEffects();
  });

  test('wallet.sendCommitted triggers refresh without frontend-owned balance mutation', async () => {
    render(<ProductionLayout />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('i-balance-era').textContent).toBe('10000'));

    const initialTxCount = parseInt(screen.getByTestId('i-tx-count').textContent || '0');
    capturedMethods = [];

    // Emit sendCommitted — simulates what happens after online send completes
    act(() => {
      bridgeEvents.emit('wallet.sendCommitted', {
        success: true,
        tokenId: 'ERA',
        newBalance: 9500n,
        transactionHash: makeTxHash(0x01),
        toDeviceId: makeDeviceId(0x02),
        amount: 500n,
      });
    });

    await waitFor(() => {
      expect(capturedMethods).toContain('getAllBalancesStrict');
      expect(capturedMethods).toContain('appRouterQuery');
    });

    expect(screen.getByTestId('i-balance-era').textContent).toBe('10000');
    expect(parseInt(screen.getByTestId('i-tx-count').textContent || '0')).toBe(initialTxCount);

    await settleWalletEffects();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 7. INTEGRATED: Full Bilateral Sequence — EXACT Device Event Flow
// ═══════════════════════════════════════════════════════════════════════════════

describe('INTEGRATED: Full bilateral transfer back-and-forth', () => {
  let BilateralTransferDialog: any;
  let WalletProvider: any;
  let useWallet: any;
  let UXProvider: any;

  beforeAll(() => {
    installCallBinMock();
    BilateralTransferDialog = require('../components/BilateralTransferDialog').BilateralTransferDialog;
    const wMod = require('../contexts/WalletContext');
    WalletProvider = wMod.WalletProvider;
    useWallet = wMod.useWallet;
    UXProvider = require('../contexts/UXContext').UXProvider;
  });

  const WalletState: React.FC = () => {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    const w = useWallet();
    return (
      <div>
        <span data-testid="seq-bal">{w.balances?.find((b: any) => b.tokenId === 'ERA')?.balance?.toString() ?? 'none'}</span>
        <span data-testid="seq-txs">{w.transactions?.length ?? 0}</span>
      </div>
    );
  };

  const FullApp: React.FC = () => (
    <UXProvider>
      <WalletProvider>
        <BilateralTransferDialog />
        <WalletState />
      </WalletProvider>
    </UXProvider>
  );

  beforeEach(() => {
    jest.useFakeTimers();
    capturedMethods = [];
    balancesState = [{ tokenId: 'ERA', available: 5000n }];
    historyState = [];
    (global as any).__dsmLastGoodHeaders = { deviceId: undefined, genesisHash: undefined, chainTip: undefined };
    installCallBinMock();
  });

  afterEach(async () => {
    await settleWalletEffects();
    jest.useRealTimers();
  });

  test('EXACT device sequence: PREPARE → show → Accept → __callBin(acceptBilateral) → ACCEPT_SENT → COMMIT → COMPLETE → __callBin(getAllBalancesStrict) → new balance in DOM', async () => {
    /**
     * This test reproduces the EXACT sequence of events from a real BLE transfer.
     * The ONLY mock is __callBin. Everything else — React components, event bridges,
     * proto encoding/decoding, identity resolution, BridgeGate, WebViewBridge,
     * bilateralEventService, transactions — is ALL REAL.
     */

    const { container } = render(<FullApp />);
    await settleWalletInit();
    await waitFor(() => expect(screen.getByTestId('seq-bal').textContent).toBe('5000'));

    // ──── Step 1: PREPARE_RECEIVED ────
    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.PREPARE_RECEIVED,
        status: 'pending',
        message: 'Incoming: 1000 ERA from Device-A',
        amount: 1000n,
        tokenId: 'ERA',
        counterpartyDeviceId: makeDeviceId(0x11),
        commitmentHash: makeCommitmentHash(0x22),
        senderBleAddress: 'AA:BB:CC:DD:EE:FF',
      }));
    });

    // ──── Step 2: Dialog appears ────
    await waitFor(() => {
      expect(container.querySelector('.bilateral-transfer-dialog')).not.toBeNull();
      expect(container.textContent).toContain('1000');
    });

    // ──── Step 3: User clicks Accept → REAL acceptIncomingTransfer chain → __callBin ────
    capturedMethods = [];
    await act(async () => {
      fireEvent.click(screen.getByText('Accept'));
    });
    // Proves the REAL chain: acceptIncomingTransfer → acceptOfflineTransfer → acceptBilateralByCommitmentBridge → __callBin
    expect(capturedMethods).toContain('acceptBilateralByCommitment');

    // ──── Step 4: ACCEPT_SENT ────
    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.ACCEPT_SENT,
        status: 'accepted',
        message: 'acceptance sent to Device-A',
        commitmentHash: makeCommitmentHash(0x22),
      }));
    });

    await waitFor(() => expect(container.querySelector('.bilateral-transfer-dialog')).toBeNull());

    // ──── Step 5: COMMIT_RECEIVED ────
    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.COMMIT_RECEIVED,
        status: 'committed',
        message: 'commit from Device-A',
        commitmentHash: makeCommitmentHash(0x22),
      }));
    });

    // ──── Step 6: TRANSFER_COMPLETE → refreshAll → __callBin(getAllBalancesStrict with new balance) → DOM ────
    balancesState = [{ tokenId: 'ERA', available: 6000n }];
    historyState = [{ amount: 1000n, amountSigned: 1000n }];
    capturedMethods = [];

    act(() => {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: BilateralEventType.TRANSFER_COMPLETE,
        status: 'completed',
        message: 'Transfer complete!',
        amount: 1000n,
        tokenId: 'ERA',
        commitmentHash: makeCommitmentHash(0x22),
        transactionHash: makeTxHash(0x33),
      }));
    });

    // Balance should reflect the 1000 ERA received (5000 → 6000) via __callBin
    await waitFor(() => {
      expect(screen.getByTestId('seq-bal').textContent).toBe('6000');
    });

    // Transaction history should show the transfer
    await waitFor(() => {
      expect(parseInt(screen.getByTestId('seq-txs').textContent || '0')).toBe(1);
    });

    // Verify __callBin was called for the balance refresh
    expect(capturedMethods).toContain('getAllBalancesStrict');

    // ──── Step 7: wallet.bilateralCommitted → refresh again via __callBin ────
    capturedMethods = [];
    act(() => {
      bridgeEvents.emit('wallet.bilateralCommitted', {
        commitmentHash: makeCommitmentHash(0x22),
        accepted: true,
        committed: true,
      } as any);
    });

    await waitFor(() => {
      expect(capturedMethods).toContain('getAllBalancesStrict');
    });

    await settleWalletEffects();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Event Ordering & Determinism
// ═══════════════════════════════════════════════════════════════════════════════

describe('Event ordering & determinism', () => {
  test('events are delivered in emission order (FIFO)', () => {
    const received: number[] = [];
    const unsub = bridgeEvents.on('wallet.refresh', (d) => {
      received.push(Number((d as any).seq));
    });
    for (let i = 1; i <= 10; i++) {
      bridgeEvents.emit('wallet.refresh', { source: 'order', seq: i } as any);
    }
    expect(received).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    unsub();
  });

  test('bilateral events maintain sequence through EventBridge pipeline', () => {
    const received: string[] = [];
    const unsub = eventBridgeOn('bilateral.event', (payload) => {
      const d = decodeBilateralEvent(payload);
      if (d) received.push(d.message);
    });
    const msgs = ['step-1', 'step-2', 'step-3', 'step-4'];
    const types = [
      BilateralEventType.PREPARE_RECEIVED,
      BilateralEventType.ACCEPT_SENT,
      BilateralEventType.COMMIT_RECEIVED,
      BilateralEventType.TRANSFER_COMPLETE,
    ];
    for (let i = 0; i < 4; i++) {
      eventBridgeEmit('bilateral.event', encodeBilateralEventNotification({
        eventType: types[i], status: 'test', message: msgs[i],
      }));
    }
    expect(received).toEqual(msgs);
    unsub();
  });

  test('unsubscribe during handler does not affect current delivery', () => {
    let unsub: (() => void) | null = null;
    const spy1 = jest.fn(() => { unsub?.(); });
    const spy2 = jest.fn();
    unsub = bridgeEvents.on('wallet.refresh', spy1);
    const unsub2 = bridgeEvents.on('wallet.refresh', spy2);
    bridgeEvents.emit('wallet.refresh', { source: 'x' });
    expect(spy1).toHaveBeenCalled();
    expect(spy2).toHaveBeenCalled();
    spy1.mockClear(); spy2.mockClear();
    bridgeEvents.emit('wallet.refresh', { source: 'y' });
    expect(spy1).not.toHaveBeenCalled();
    expect(spy2).toHaveBeenCalled();
    unsub2();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 9. Error Resilience
// ═══════════════════════════════════════════════════════════════════════════════

describe('Error resilience', () => {
  test('malformed bilateral event payload does not crash EventBridge', () => {
    const spy = jest.fn();
    const unsub = eventBridgeOn('bilateral.event', spy);
    expect(() => {
      eventBridgeEmit('bilateral.event', new Uint8Array([0xFF, 0xFE, 0x00, 0x01]));
    }).not.toThrow();
    expect(spy).toHaveBeenCalledTimes(1);
    unsub();
  });

  test('decodeBilateralEvent returns null for garbage', () => {
    expect(decodeBilateralEvent(new Uint8Array([0xFF, 0xFE]))).toBeNull();
  });

  test('handler error does not break other handlers', () => {
    const bad = jest.fn(() => { throw new Error('crash'); });
    const good = jest.fn();
    const u1 = bridgeEvents.on('wallet.bilateralCommitted', bad as any);
    const u2 = bridgeEvents.on('wallet.bilateralCommitted', good);
    bridgeEvents.emit('wallet.bilateralCommitted', { accepted: true } as any);
    expect(bad).toHaveBeenCalled();
    expect(good).toHaveBeenCalled();
    u1(); u2();
  });

  test('empty payload decoded gracefully (no crash)', () => {
    const result = decodeBilateralEvent(new Uint8Array(0));
    if (result === null) {
      expect(result).toBeNull();
    } else {
      expect(result.eventType).toBe(0);
      expect(result.commitmentHash).toBe('');
    }
  });
});
