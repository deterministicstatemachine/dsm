/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0

import { getBridgeInstance } from '../bridge/BridgeRegistry';
import { bridgeEvents } from '../bridge/bridgeEvents';
import type { AndroidBridgeV3 } from './bridgeTypes';
import { IngressRequest, IngressResponse, RouterInvokeOp, RouterQueryOp } from '../proto/dsm_app_pb';

function mustBridge(): AndroidBridgeV3 {
  const bridge = getBridgeInstance();
  if (!bridge) {
    throw new Error('DSM bridge not available');
  }
  return bridge;
}

function normalizeToBytes(data: unknown): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  throw new Error('expected Uint8Array response from native boundary');
}

async function callBoundaryMethod(method: 'nativeBoundaryIngress', payload: Uint8Array): Promise<Uint8Array> {
  // `ingress` is the bridge object's own wrapper over the MessagePort
  // (`index.html`); it answers the boundary's bytes or throws. The startup
  // boundary is Kotlin's to cross, at app start; the WebView never crossed it.
  const bridge = mustBridge();
  const call = bridge.ingress;
  if (typeof call !== 'function') {
    throw new Error(`DSM bridge does not expose ${method}`);
  }
  try {
    return normalizeToBytes(await call(payload));
  } catch (e) {
    // The wrapper reduces Kotlin's ErrorResponse to its message; that message
    // reaches the diagnostics bus as the RPC path's failures do.
    const message = e instanceof Error ? e.message : String(e);
    bridgeEvents.emit('bridge.error', { code: 0, message, debugB32: '' });
    throw e;
  }
}

function encodeIngressRequest(request: IngressRequest | Uint8Array): Uint8Array {
  return request instanceof Uint8Array ? new Uint8Array(request) : request.toBinary();
}

function unwrapIngressResponse(responseBytes: Uint8Array): Uint8Array {
  const response = IngressResponse.fromBinary(responseBytes);
  if (response.result.case === 'okBytes') {
    return response.result.value;
  }
  if (response.result.case === 'error') {
    throw new Error(response.result.value?.message || 'ingress boundary error');
  }
  throw new Error('ingress boundary returned no result');
}

export async function ingressBoundary(request: IngressRequest | Uint8Array): Promise<Uint8Array> {
  return callBoundaryMethod('nativeBoundaryIngress', encodeIngressRequest(request));
}

export async function ingressBoundaryOk(request: IngressRequest | Uint8Array): Promise<Uint8Array> {
  return unwrapIngressResponse(await ingressBoundary(request));
}

export function buildRouterQueryIngressRequest(path: string, params?: Uint8Array): IngressRequest {
  return new IngressRequest({
    operation: {
      case: 'routerQuery',
      value: new RouterQueryOp({
        method: path,
        args: params instanceof Uint8Array ? new Uint8Array(params) : new Uint8Array(0),
      }),
    },
  });
}

export function buildRouterInvokeIngressRequest(method: string, args?: Uint8Array): IngressRequest {
  return new IngressRequest({
    operation: {
      case: 'routerInvoke',
      value: new RouterInvokeOp({
        method,
        args: args instanceof Uint8Array ? new Uint8Array(args) : new Uint8Array(0),
      }),
    },
  });
}
