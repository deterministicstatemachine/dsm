// SPDX-License-Identifier: Apache-2.0
//
// The guided tour's sandbox, at the bridge. While the tour's practice wallet
// stands in for the device's, every call the WebView makes to native code is
// read here before it leaves, whichever module made it and however it was
// imported, and only reads cross: each one named below. Everything else is
// answered "blocked in practice mode" in its channel's own wire shape and never
// reaches Rust or the host. The practice wallet's own answers
// (components/tour/practiceMode.ts) are made before any call is sent; this is
// what keeps the real wallet untouched while they are.

import {
  BridgeRpcRequest,
  BridgeRpcResponse,
  Error as ProtoError,
  ErrorResponse,
  IngressRequest,
  IngressResponse,
  NativeHostRequest,
  NativeHostRequestKind,
  NativeHostResponse,
  PreferencePayload,
} from '../proto/dsm_app_pb';
import type { AndroidBridgeV3 } from '../dsm/bridgeTypes';

export const PRACTICE_BLOCKED_MESSAGE =
  'Practice mode: this is switched off until the tour ends. Your real wallet is untouched.';

/** Bridge methods that only read. */
const READ_METHODS = new Set([
  'getAllBalancesStrict',
  'getTransportHeadersV3Bin',
  'getPreference',
  'getArchitectureInfo',
  'getDiagnosticsLog',
]);

/** The preferences the tour's shell lessons change: how the app looks and sounds. */
const DISPLAY_PREFERENCES = new Set(['ui_theme', 'sfx_enabled']);

/**
 * Router routes that only read, whether the router takes them as a query or an
 * invoke: the screens the tour visits read these. A route that writes anything,
 * a query path included (`tokens.addByAnchor`, `storage.sync`, `prefs.set`), is
 * not here.
 */
const READ_ROUTES = new Set([
  'balance.list',
  'wallet.history',
  'wallet.amount',
  'contacts.list',
  'contacts.readContactCode',
  'identity.contact_code',
  'inbox.pull',
  'storage.status',
  'tokens.getFeeSchedule',
  'token.adoptionQr',
  'bilateral.pending_list',
  'recovery.status',
  'recovery.capsulePreview',
  'recovery.phase',
  'recovery.syncStatus',
  'sofi.findRoute',
  'sofi.vaults',
  'bitcoin.balance',
  'bitcoin.vault.list',
]);

/** Host requests that change nothing: what the host can do, and the camera a contact code is scanned with. */
const HOST_READS = new Set<NativeHostRequestKind>([
  NativeHostRequestKind.HOST_CONTROL_CAPABILITIES_GET,
  NativeHostRequestKind.HOST_CONTROL_QR_START_SCAN,
  NativeHostRequestKind.HOST_CONTROL_QR_STOP_SCAN,
]);

let sandbox: 'real' | 'practice' = 'real';

/** The tour's practice wallet is standing in: only reads reach native code. */
export function enterPracticeSandbox(): void {
  sandbox = 'practice';
}

export function leavePracticeSandbox(): void {
  sandbox = 'real';
}

export function inPracticeSandbox(): boolean {
  return sandbox === 'practice';
}

/** What a request is, when it may not cross: undefined when it is a read. */
type Refusal = string | undefined;

function ingressRefusal(bytes: Uint8Array): Refusal {
  const operation = IngressRequest.fromBinary(bytes).operation;
  if (operation.case === 'routerQuery' || operation.case === 'routerInvoke') {
    return READ_ROUTES.has(operation.value.method) ? undefined : operation.value.method;
  }
  return `ingress ${String(operation.case)}`;
}

function hostRefusal(bytes: Uint8Array): Refusal {
  const kind = NativeHostRequest.fromBinary(bytes).kind;
  return HOST_READS.has(kind) ? undefined : `host request ${NativeHostRequestKind[kind]}`;
}

function rpcRefusal(bytes: Uint8Array): Refusal {
  const call = BridgeRpcRequest.fromBinary(bytes);
  const payload = call.payload.case === 'bytes' ? call.payload.value.data : new Uint8Array(0);
  if (call.method === 'nativeBoundaryIngress') return ingressRefusal(payload);
  if (call.method === 'nativeHostRequest') return hostRefusal(payload);
  if (call.method === 'setPreference') {
    const key = PreferencePayload.fromBinary(payload).key;
    return DISPLAY_PREFERENCES.has(key) ? undefined : `setPreference ${key}`;
  }
  return READ_METHODS.has(call.method) ? undefined : call.method;
}

/** A request that cannot be read is refused, never let through. */
function refusalOf(read: (bytes: Uint8Array) => Refusal, bytes: Uint8Array): Refusal {
  try {
    return read(bytes);
  } catch (e) {
    return `an unreadable request (${e instanceof Error ? e.message : String(e)})`;
  }
}

const blocked = (what: string): string => `${PRACTICE_BLOCKED_MESSAGE} (${what})`;

/**
 * The bridge as the WebView sees it while the tour runs: the same object, with
 * every request read first. Reads go to the real bridge; anything else is
 * answered here, refused, in the shape that channel answers a refusal in.
 */
export function practiceView(bridge: AndroidBridgeV3): AndroidBridgeV3 {
  return {
    __binary: bridge.__binary,
    isAvailable: () => bridge.isAvailable(),
    getBridgeStatus: () => bridge.getBridgeStatus(),
    sendMessageBin: async (bytes: Uint8Array) => {
      const what = refusalOf(rpcRefusal, bytes);
      if (what === undefined) return bridge.sendMessageBin(bytes);
      return new BridgeRpcResponse({
        result: { case: 'error', value: new ErrorResponse({ message: blocked(what) }) },
      }).toBinary();
    },
    ingress: async (bytes: Uint8Array) => {
      const what = refusalOf(ingressRefusal, bytes);
      if (what === undefined) return bridge.ingress(bytes);
      return new IngressResponse({
        result: { case: 'error', value: new ProtoError({ message: blocked(what) }) },
      }).toBinary();
    },
    hostRequest: async (bytes: Uint8Array) => {
      const what = refusalOf(hostRefusal, bytes);
      if (what === undefined) return bridge.hostRequest(bytes);
      return new NativeHostResponse({
        result: { case: 'error', value: new ProtoError({ message: blocked(what) }) },
      }).toBinary();
    },
  };
}
