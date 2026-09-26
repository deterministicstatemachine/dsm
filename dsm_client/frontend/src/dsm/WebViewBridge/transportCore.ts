/* eslint-disable security/detect-object-injection */
// SPDX-License-Identifier: Apache-2.0
//
// Transport core: bridge gate, request framing, BridgeRpcResponse unwrapping,
// callBin / sendBridgeRequestBytes, router invoke/query, helpers shared across
// the modular WebViewBridge facade.

import { bridgeGate } from "../BridgeGate";
import {
  BridgeRpcRequest,
  BridgeRpcResponse,
  BytesPayload,
  EmptyPayload,
} from "../../proto/dsm_app_pb";
import { bridgeEvents } from "../../bridge/bridgeEvents";
import { getBridgeInstance } from "../../bridge/BridgeRegistry";
import type { AndroidBridgeV3 } from "../bridgeTypes";
import { emitDeterministicSafetyIfPresent } from "../../utils/deterministicSafety";
import {
  buildRouterInvokeIngressRequest,
  buildRouterQueryIngressRequest,
  ingressBoundaryOk,
} from "../NativeBoundaryBridge";

export function mustBridge(): AndroidBridgeV3 {
  const b = getBridgeInstance();
  if (!b) throw new Error("DSM bridge not available");
  return b;
}

export function normalizeToBytes(data: unknown): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return new Uint8Array(data);
  throw new Error("normalizeToBytes: expected Uint8Array or number[]");
}

export const toBytes = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => {
  const needsCopy = !(bytes.buffer instanceof ArrayBuffer);
  const buf =
    bytes.buffer instanceof ArrayBuffer
      ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
      : new ArrayBuffer(bytes.byteLength);
  const out = new Uint8Array(buf);
  if (needsCopy || bytes.byteOffset !== 0 || bytes.byteLength !== bytes.buffer.byteLength) {
    out.set(bytes);
  }
  return out;
};


export class BridgeError extends Error {
  errorCode?: number;
  details?: unknown;
  constructor(errorCode: number | undefined, message: string) {
    super(message);
    this.name = "BridgeError";
    this.errorCode = errorCode;
    Object.setPrototypeOf(this, BridgeError.prototype);
  }
}

const unwrapProtobufResponse = async (_method: string, buf: Uint8Array): Promise<Uint8Array> => {
  if (!buf || buf.length === 0) {
    throw new Error("Empty response from bridge");
  }

  try {
    const br = BridgeRpcResponse.fromBinary(buf);
    const result = br.result;
    if (result.case === "success") {
      const data = result.value?.data;
      return data instanceof Uint8Array ? data : new Uint8Array(0);
    }
    if (result.case === "error") {
      const err = result.value;
      const code = err.errorCode ?? 0;

      const hex = `0x${code.toString(16).toUpperCase()}`;
      let uiMessage = err.message ?? `Bridge error ${hex}`;

      if (code === 460) {
        uiMessage = `Transfer Rejected (Offline Mode) - Check peer connection [${hex}]`;
      } else if (code === 404) {
        uiMessage = `Item Not Found - State may be stale [${hex}]`;
      } else if (code === 408) {
        uiMessage = `Protocol Timeout - Peer did not respond [${hex}]`;
      } else if (!uiMessage.includes(hex)) {
        uiMessage += ` [${hex}]`;
      }

      emitDeterministicSafetyIfPresent(uiMessage);

      const be = new BridgeError(code, uiMessage);
      be.details = err;

      try {
        bridgeEvents.emit("bridge.error", {
          code: be.errorCode,
          message: be.message,
          debugB32: err.debugB32,
        });
      } catch (_e) {
        // ignore listener errors
      }
      throw be;
    }
    const errorMessage = new TextDecoder().decode(buf);
    emitDeterministicSafetyIfPresent(errorMessage);
    try {
      bridgeEvents.emit("bridge.error", { code: 0, message: errorMessage, debugB32: "" });
    } catch (_e) {
      // ignore
    }
    throw new BridgeError(0, `Bridge error: ${errorMessage}`);
  } catch (e) {
    if (e instanceof BridgeError) throw e;

    const errorMessage = new TextDecoder().decode(buf);
    emitDeterministicSafetyIfPresent(errorMessage);
    try {
      bridgeEvents.emit("bridge.error", { code: 0, message: errorMessage, debugB32: "" });
    } catch (_e) {
      // ignore
    }
    throw new BridgeError(0, `Bridge error: ${errorMessage}`);
  }
};

const buildBridgeRequest = (method: string, payload?: Uint8Array): Uint8Array => {
  const bytes = payload instanceof Uint8Array ? new Uint8Array(payload) : new Uint8Array(0);
  const req = new BridgeRpcRequest({
    method,
    payload:
      bytes.length > 0
        ? { case: "bytes", value: new BytesPayload({ data: bytes }) }
        : { case: "empty", value: new EmptyPayload({}) },
  });
  return req.toBinary();
};

/**
 * One request over the bytes-only MessagePort bridge `index.html` installs:
 * `sendMessageBin` waits for the port itself and answers the BridgeRpcResponse
 * Kotlin posted, which is unwrapped here. There is no other transport.
 */
export const sendBridgeRequestBytes = async (
  method: string,
  requestBytes: Uint8Array
): Promise<Uint8Array> => {
  const b = mustBridge();
  if (b.__binary !== true || typeof b.sendMessageBin !== "function") {
    throw new Error("DSM bridge not available (bytes-only MessagePort required)");
  }
  const respBytes = normalizeToBytes(await b.sendMessageBin(requestBytes));
  return await unwrapProtobufResponse(method, respBytes);
};

export async function callBin(method: string, payload?: Uint8Array): Promise<Uint8Array> {
  const reqBytes = buildBridgeRequest(method, payload);
  return sendBridgeRequestBytes(method, reqBytes);
}

export async function routerInvokeBin(method: string, args?: Uint8Array): Promise<Uint8Array> {
  if (typeof method !== "string" || method.length === 0) {
    throw new Error("routerInvokeBin: method required");
  }
  return bridgeGate.enqueue(() => ingressBoundaryOk(buildRouterInvokeIngressRequest(method, args)));
}

export async function routerQueryBin(path: string, params?: Uint8Array): Promise<Uint8Array> {
  if (typeof path !== "string" || path.length === 0) {
    throw new Error("routerQueryBin: path required");
  }
  return bridgeGate.enqueue(() => ingressBoundaryOk(buildRouterQueryIngressRequest(path, params)));
}

export async function queryTransportHeadersV3(): Promise<Uint8Array> {
  const responseBytes = await callBin("getTransportHeadersV3Bin", new Uint8Array(0));
  return responseBytes;
}
