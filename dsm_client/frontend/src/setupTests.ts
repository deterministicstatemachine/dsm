/* eslint-disable @typescript-eslint/no-explicit-any */
// Jest setup for React Testing Library and bridge shims
import '@testing-library/jest-dom';
import { setBridgeInstance } from './bridge/BridgeRegistry';

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
  // Ensure DsmBridge exists for tests, but do NOT install shims here.
  // Tests should explicitly mock the exact methods they need, and production code
  // should rely on the single bytes-only bridge contract.
  // Install a proxy setter so any reassignment of window.DsmBridge also updates the DI registry.
  // This keeps tests deterministic even when they replace the bridge object.
  let __bridge = g.window.DsmBridge || {};
  Object.defineProperty(g.window, 'DsmBridge', {
    configurable: true,
    enumerable: true,
    get() {
      return __bridge;
    },
    set(v: any) {
      __bridge = v || {};
      setBridgeInstance(__bridge);
    },
  });
  // Initialize registry with current bridge value.
  setBridgeInstance(g.window.DsmBridge);

  // Provide a default __callBin implementation that returns BridgeRpcResponse bytes
  if (!g.window.DsmBridge.__callBin) {
    g.window.DsmBridge.__callBin = async (reqBytes: Uint8Array): Promise<Uint8Array> => {
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
      
      if (method === 'appRouterInvoke') {
        // Return empty success for router invoke calls
        return createDsmBridgeSuccessResponse(new Uint8Array(0));
      }

      if (method === 'appRouterQuery') {
        // Return empty success with 8-byte router request-ID prefix for router query calls
        const prefix = new Uint8Array(8);
        return createDsmBridgeSuccessResponse(prefix);
      }

      // Default: return an error for unmocked methods
      const errorMessage = `Method '${method}' not mocked in test environment`;
      return createDsmBridgeErrorResponse(errorMessage);
    };
  }
}

import * as pb from './proto/dsm_app_pb';
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

// Mock the specific functions that are used during initialization
const _originalGetPreference = WebViewBridge.getPreference;
const _originalSetPreference = WebViewBridge.setPreference;

(WebViewBridge as any).getPreference = jest.fn(async () => null);
(WebViewBridge as any).setPreference = jest.fn(async () => {});


