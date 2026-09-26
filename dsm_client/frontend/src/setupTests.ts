// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
// Jest setup for React Testing Library and bridge shims
import '@testing-library/jest-dom';
import { setBridgeInstance } from './bridge/BridgeRegistry';
import * as pb from './proto/dsm_app_pb';

// Silence noisy console logs in test output. Warnings and errors remain visible.
const silenceLogs = process.env.JEST_SILENCE_LOGS !== '0';
if (silenceLogs) {
  // eslint-disable-next-line no-console
  console.log = () => {};
  // eslint-disable-next-line no-console
  console.info = () => {};
  // eslint-disable-next-line no-console
  console.debug = () => {};
}

// Avoid prototype patches that hide real issues. If BigInt needs serialization,
// use a local helper (safeJsonStringify) within application code instead.

// Polyfill btoa/atob for Node.js environment
if (typeof (global as any).btoa === 'undefined') {
  (global as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');
}
if (typeof (global as any).atob === 'undefined') {
  (global as any).atob = (b64: string) => Buffer.from(b64, 'base64').toString('binary');
}

// jsdom does not implement media playback APIs. Stub them globally so audio
// cues exercised in tests do not spam the console.
if (typeof window !== 'undefined' && typeof window.HTMLMediaElement !== 'undefined') {
  Object.defineProperty(window.HTMLMediaElement.prototype, 'load', {
    configurable: true,
    writable: true,
    value: jest.fn(),
  });
  Object.defineProperty(window.HTMLMediaElement.prototype, 'pause', {
    configurable: true,
    writable: true,
    value: jest.fn(),
  });
  Object.defineProperty(window.HTMLMediaElement.prototype, 'play', {
    configurable: true,
    writable: true,
    value: jest.fn().mockResolvedValue(undefined),
  });
}

// Provide a minimal WebView MCP bridge mock for tests
if (typeof (global as any).window !== 'undefined') {
  const g = (global as any);
  // The test bridge speaks the production interface: the object `index.html`
  // installs — `__binary`, `isAvailable`, `sendMessageBin`, and `startup` /
  // `ingress` / `hostRequest`, which are index.html's own wrappers over
  // `sendMessageBin`. A test supplies `sendMessageBin` (one BridgeRpcRequest in,
  // BridgeRpcResponse bytes out) and the setter completes the rest, so the
  // production transport runs unchanged; nothing in production branches on a
  // test-only method.
  const completeTestBridge = (bridge: any) => {
    if (typeof bridge.sendMessageBin !== 'function') return bridge;
    const callBridgeMethod = async (method: string, payload: Uint8Array): Promise<Uint8Array> => {
      const req = new pb.BridgeRpcRequest({
        method,
        payload: payload.length > 0
          ? { case: 'bytes', value: new pb.BytesPayload({ data: new Uint8Array(payload) as Uint8Array<ArrayBuffer> }) }
          : { case: 'empty', value: new pb.EmptyPayload({}) },
      });
      // Read at call time: a test may replace `sendMessageBin` on the same object.
      const raw = await bridge.sendMessageBin(req.toBinary());
      let response: pb.BridgeRpcResponse;
      try {
        response = pb.BridgeRpcResponse.fromBinary(raw);
      } catch {
        // As index.html's unwrapBridgeRpcSuccess answers bytes it cannot parse.
        throw new Error(`invalid bridge response for ${method}`);
      }
      if (response.result.case === 'success') return response.result.value.data;
      if (response.result.case === 'error') {
        throw new Error(response.result.value.message || `bridge error while calling ${method}`);
      }
      throw new Error(`invalid bridge response for ${method}`);
    };
    bridge.__binary = true;
    if (typeof bridge.isAvailable !== 'function') bridge.isAvailable = () => true;
    if (typeof bridge.getBridgeStatus !== 'function') bridge.getBridgeStatus = () => 3;
    if (typeof bridge.startup !== 'function') bridge.startup = (p: Uint8Array) => callBridgeMethod('nativeBoundaryStartup', p);
    if (typeof bridge.ingress !== 'function') bridge.ingress = (p: Uint8Array) => callBridgeMethod('nativeBoundaryIngress', p);
    if (typeof bridge.hostRequest !== 'function') bridge.hostRequest = (p: Uint8Array) => callBridgeMethod('nativeHostRequest', p);
    return bridge;
  };
  // A proxy setter: any reassignment of window.DsmBridge is completed and
  // registered with the DI registry, so a test that replaces the bridge object
  // still runs the production transport.
  let __bridge = completeTestBridge(g.window.DsmBridge || {});
  Object.defineProperty(g.window, 'DsmBridge', {
    configurable: true,
    enumerable: true,
    get() {
      return __bridge;
    },
    set(v: any) {
      __bridge = completeTestBridge(v || {});
      setBridgeInstance(__bridge);
    },
  });
  // Initialize registry with current bridge value.
  setBridgeInstance(g.window.DsmBridge);

  // The default transport answers the methods most tests need; a test that
  // needs another answer installs its own `sendMessageBin`.
  if (!g.window.DsmBridge.sendMessageBin) {
    g.window.DsmBridge.sendMessageBin = async (reqBytes: Uint8Array): Promise<Uint8Array> => {
      const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
      const method = req.method || '';
      // Default implementation returns mock responses for common methods
      if (method === 'getTransportHeadersV3Bin') {
        // Return mock headers for identity
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const headers = new (require('./proto/dsm_app_pb').Headers)({ 
          deviceId: new Uint8Array(32).fill(0x11), 
          chainTip: new Uint8Array(32).fill(0xff), 
          genesisHash: new Uint8Array(32).fill(0x11), 
          seq: 1n as any 
        } as any);
        return createDsmBridgeSuccessResponse(headers.toBinary());
      }
      
      if (method === 'getPreference') {
        // Return null for preferences by default
        return createDsmBridgeSuccessResponse(new Uint8Array(0));
      }

      if (method === 'setPreference') {
        // Return success for setting preferences
        return createDsmBridgeSuccessResponse(new Uint8Array(0));
      }

      if (method === 'nativeBoundaryStartup') {
        const response = new pb.StartupResponse({
          result: { case: 'okBytes', value: new Uint8Array(0) },
        });
        return createDsmBridgeSuccessResponse(response.toBinary());
      }

      if (method === 'nativeBoundaryIngress') {
        const response = new pb.IngressResponse({
          result: { case: 'okBytes', value: new Uint8Array(0) },
        });
        return createDsmBridgeSuccessResponse(response.toBinary());
      }

      if (method === 'nativeHostRequest') {
        const response = new pb.NativeHostResponse({
          result: { case: 'okBytes', value: new Uint8Array(0) },
        });
        return createDsmBridgeSuccessResponse(response.toBinary());
      }

      // Default: return an error for unmocked methods
      const errorMessage = `Method '${method}' not mocked in test environment`;
      return createDsmBridgeErrorResponse(errorMessage);
    };
    completeTestBridge(g.window.DsmBridge);
  }
}

import { encodeBase32Crockford } from './utils/textId';

// Helper function to create properly formatted BridgeRpcResponse error responses
function createDsmBridgeErrorResponse(errorMessage: string): Uint8Array {
  // Create an ErrorResponse first to compute canonical debug bytes
  const errProto = new pb.ErrorResponse({ errorCode: 1, message: errorMessage });
  const debug = encodeBase32Crockford(errProto.toBinary());
  const br = new pb.BridgeRpcResponse({ result: { case: 'error', value: { errorCode: 1, message: errorMessage, debugB32: debug } } });
  return br.toBinary();
}

// Helper function to create properly formatted BridgeRpcResponse success responses
function createDsmBridgeSuccessResponse(data: Uint8Array): Uint8Array {
  const br = new pb.BridgeRpcResponse({ result: { case: 'success', value: { data: data as Uint8Array<ArrayBuffer> } } });
  return br.toBinary();
}

// Attach to global for test harness
(global as any).createDsmBridgeErrorResponse = createDsmBridgeErrorResponse;
(global as any).createDsmBridgeSuccessResponse = createDsmBridgeSuccessResponse;

// Polyfill TextEncoder/TextDecoder for Node.js test environment
if (typeof (global as any).TextEncoder === 'undefined') {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { TextEncoder, TextDecoder } = require('util');
  (global as any).TextEncoder = TextEncoder;
  (global as any).TextDecoder = TextDecoder;
}

// Mock WebViewBridge functions that are imported during module initialization
// This prevents errors when StorageNodeService tries to load preferences
import * as WebViewBridge from './dsm/WebViewBridge';

// Use jest.spyOn so restoreMocks:true can restore originals between tests
jest.spyOn(WebViewBridge, 'getPreference').mockResolvedValue(null);
jest.spyOn(WebViewBridge, 'setPreference').mockResolvedValue(undefined);

