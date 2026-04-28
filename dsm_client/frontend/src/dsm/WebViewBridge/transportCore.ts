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
import { decodeFramedEnvelopeV3 } from "../decoding";
import {
  buildEnvelopeIngressRequest,
  buildRouterInvokeIngressRequest,
  buildRouterQueryIngressRequest,
  ingressBoundaryOk,
} from "../NativeBoundaryBridge";

let bridgeEventCounter = 0;

function nextBridgeEventCounter(): number {
  bridgeEventCounter = (bridgeEventCounter + 1) >>> 0;
  return bridgeEventCounter;
}

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

function maybeUnframe(buf: Uint8Array): Uint8Array {
  if (buf.length < 4) return buf;
  const nBE = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
  if (4 + nBE === buf.length) return buf.slice(4, 4 + nBE);
  const nLE = (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)) >>> 0;
  if (4 + nLE === buf.length) return buf.slice(4, 4 + nLE);
  return buf;
}

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

      const win = window as Window & {
        __lastBridgeError?: { message: string; code: string; counter: number };
      };
      win.__lastBridgeError = { message: uiMessage, code: hex, counter: nextBridgeEventCounter() };

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

export const sendBridgeRequestBytes = async (
  method: string,
  requestBytes: Uint8Array
): Promise<Uint8Array> => {
  const b = mustBridge();

  const waitForBinaryBridgeReady = async (): Promise<void> => {
    const maybeBridge = b as unknown as { isAvailable?: () => boolean };
    if (typeof maybeBridge.isAvailable !== "function" || maybeBridge.isAvailable()) {
      return;
    }

    await new Promise<void>((resolve) => {
      let done = false;
      const finish = () => {
        if (!done) {
          done = true;
          resolve();
        }
      };
      const onReady = () => finish();
      if (typeof window !== "undefined") {
        window.addEventListener("dsm-bridge-ready", onReady, { once: true });
      }
      setTimeout(() => {
        if (typeof window !== "undefined") {
          window.removeEventListener("dsm-bridge-ready", onReady);
        }
        finish();
      }, 2500);
    });
  };

  if (typeof b.__callBin === "function") {
    const respBytes = await b.__callBin(requestBytes);
    return await unwrapProtobufResponse(method, normalizeToBytes(respBytes));
  }

  if (b.__binary === true && typeof b.sendMessageBin === "function") {
    await waitForBinaryBridgeReady();
    const respBytes = await b.sendMessageBin(requestBytes);
    const respFramed = normalizeToBytes(respBytes);
    return await unwrapProtobufResponse(method, maybeUnframe(respFramed));
  }

  throw new Error("DSM bridge not available (bytes-only MessagePort required)");
};

export async function callBin(method: string, payload?: Uint8Array): Promise<Uint8Array> {
  const reqBytes = buildBridgeRequest(method, payload);
  return sendBridgeRequestBytes(method, reqBytes);
}

export async function maybeThrowOnEmpty(result: Uint8Array): Promise<Uint8Array> {
  if (result.length > 0) return result;
  const b = mustBridge();
  try {
    if (typeof b.lastError === "function") {
      const msg = b.lastError();
      if (msg && typeof msg === "string" && msg.length > 0) {
        throw new Error(`DSM native error: ${msg}`);
      }
    }
  } catch (e) {
    if (e instanceof Error && /DSM native error/.test(e.message)) throw e;
  }
  return result;
}

export async function processEnvelopeV3Bin(envelopeBytes: Uint8Array): Promise<Uint8Array> {
  return bridgeGate.enqueue(() => ingressBoundaryOk(buildEnvelopeIngressRequest(envelopeBytes)));
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

export async function invokeRouterEnvelope(method: string, args?: Uint8Array) {
  const bytes = await routerInvokeBin(method, args);
  return { bytes, envelope: decodeFramedEnvelopeV3(bytes) };
}

export async function queryRouterEnvelope(path: string, params?: Uint8Array) {
  const bytes = await routerQueryBin(path, params);
  return { bytes, envelope: decodeFramedEnvelopeV3(bytes) };
}

export async function queryTransportHeadersV3(): Promise<Uint8Array> {
  const responseBytes = await callBin("getTransportHeadersV3Bin", new Uint8Array(0));
  return maybeThrowOnEmpty(responseBytes);
}
