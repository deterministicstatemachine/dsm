/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0

import { getBridgeInstance } from '../bridge/BridgeRegistry';
import { bridgeEvents } from '../bridge/bridgeEvents';
import type { AndroidBridgeV3 } from './bridgeTypes';
import { encodeBase32Crockford } from '../utils/textId';
import {
  BridgeRpcRequest,
  BridgeRpcResponse,
  BytesPayload,
  EmptyPayload,
  EnvelopeOp,
  IngressRequest,
  IngressResponse,
  RouterInvokeOp,
  RouterQueryOp,
  StartupRequest,
  StartupResponse,
} from '../proto/dsm_app_pb';

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

function buildBridgeRequest(method: string, payload: Uint8Array): Uint8Array {
  const req = new BridgeRpcRequest({
    method,
    payload:
      payload.length > 0
        ? { case: 'bytes', value: new BytesPayload({ data: new Uint8Array(payload) }) }
        : { case: 'empty', value: new EmptyPayload({}) },
  });
  return req.toBinary();
}

function unwrapBridgeRpcResponse(method: string, responseBytes: Uint8Array): Uint8Array {
  let response: BridgeRpcResponse;
  try {
    response = BridgeRpcResponse.fromBinary(responseBytes);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Bridge error: failed to decode response for ${method}: ${msg}`);
  }
  if (response.result.case === 'success') {
    const data = response.result.value?.data;
    return data instanceof Uint8Array ? data : new Uint8Array(0);
  }
  if (response.result.case === 'error') {
    const errVal = response.result.value;
    const message = errVal?.message || `bridge error while calling ${method}`;
    const debugBytes = errVal ? errVal.toBinary() : new Uint8Array(0);
    bridgeEvents.emit('bridge.error', {
      code: errVal?.errorCode,
      message,
      debugB32: encodeBase32Crockford(debugBytes),
    });
    throw new Error(message);
  }
  throw new Error(`empty bridge response for ${method}`);
}

async function callBoundaryMethod(method: 'nativeBoundaryStartup' | 'nativeBoundaryIngress', payload: Uint8Array): Promise<Uint8Array> {
  const bridge = mustBridge();
  if (method === 'nativeBoundaryStartup' && typeof bridge.startup === 'function') {
    return normalizeToBytes(await bridge.startup(payload));
  }
  if (method === 'nativeBoundaryIngress' && typeof bridge.ingress === 'function') {
    return normalizeToBytes(await bridge.ingress(payload));
  }

  const requestBytes = buildBridgeRequest(method, payload);
  if (typeof bridge.__callBin === 'function') {
    const responseBytes = await bridge.__callBin(requestBytes);
    return unwrapBridgeRpcResponse(method, normalizeToBytes(responseBytes));
  }
  if (bridge.__binary === true && typeof bridge.sendMessageBin === 'function') {
    const responseBytes = await bridge.sendMessageBin(requestBytes);
    return unwrapBridgeRpcResponse(method, normalizeToBytes(responseBytes));
  }
  throw new Error('DSM bridge does not expose the native boundary transport');
}

function encodeStartupRequest(request: StartupRequest | Uint8Array): Uint8Array {
  return request instanceof Uint8Array ? new Uint8Array(request) : request.toBinary();
}

function encodeIngressRequest(request: IngressRequest | Uint8Array): Uint8Array {
  return request instanceof Uint8Array ? new Uint8Array(request) : request.toBinary();
}

function unwrapStartupResponse(responseBytes: Uint8Array): Uint8Array {
  const response = StartupResponse.fromBinary(responseBytes);
  if (response.result.case === 'okBytes') {
    return response.result.value;
  }
  if (response.result.case === 'error') {
    throw new Error(response.result.value?.message || 'startup boundary error');
  }
  throw new Error('startup boundary returned no result');
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

export async function startupBoundary(request: StartupRequest | Uint8Array): Promise<Uint8Array> {
  return callBoundaryMethod('nativeBoundaryStartup', encodeStartupRequest(request));
}

export async function ingressBoundary(request: IngressRequest | Uint8Array): Promise<Uint8Array> {
  return callBoundaryMethod('nativeBoundaryIngress', encodeIngressRequest(request));
}

export async function startupBoundaryOk(request: StartupRequest | Uint8Array): Promise<Uint8Array> {
  return unwrapStartupResponse(await startupBoundary(request));
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

export function buildEnvelopeIngressRequest(envelopeBytes: Uint8Array): IngressRequest {
  return new IngressRequest({
    operation: {
      case: 'envelope',
      value: new EnvelopeOp({ envelopeBytes: new Uint8Array(envelopeBytes) }),
    },
  });
}
