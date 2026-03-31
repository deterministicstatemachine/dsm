/* eslint-disable @typescript-eslint/no-explicit-any */
/* Jest tests for WebViewBridge event channel and error surfacing */
// Jest globals (describe, test, expect) are available without import in configured test environment.
import { addDsmEventListener, getTransportHeadersV3Bin } from '../WebViewBridge';
import type { DsmEvent } from '../WebViewBridge';

describe('WebViewBridge dsm-event listener', () => {
  test('receives binary payload bytes', (done: (err?: any) => void) => {
    const payload = new Uint8Array([0x00, 0xFF, 0x10, 0x41]);
    
  const unsub = addDsmEventListener((evt: DsmEvent) => {
      try {
        expect(evt.topic).toBe('test-topic');
        expect(evt.payload).toBeInstanceOf(Uint8Array);
        expect(evt.payload.length).toBe(payload.length);
        for (let i = 0; i < payload.length; i++) {
          expect(evt.payload[i]).toBe(payload[i]);
        }
        unsub();
        done();
      } catch (e) {
        done(e);
      }
    });
    // Dispatch synthetic event
    window.dispatchEvent(new CustomEvent('dsm-event-bin', { detail: { topic: 'test-topic', payload } }));
  });
});

describe('WebViewBridge error surfacing via lastError', () => {
  test('throws when native returns empty and lastError present', async () => {
    // Stub bridge
    (globalThis as any).window = (globalThis as any).window || {};
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async () => (global as any).createDsmBridgeSuccessResponse(new Uint8Array(0)),
      lastError: () => 'sdk_context_uninitialized'
    };
    await expect(getTransportHeadersV3Bin()).rejects.toThrow(/sdk_context_uninitialized/);
  });

  test('does not throw when empty and no lastError', async () => {
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async () => (global as any).createDsmBridgeSuccessResponse(new Uint8Array(0))
    };
    const res = await getTransportHeadersV3Bin();
    expect(res).toBeInstanceOf(Uint8Array);
    expect(res.length).toBe(0);
  });
});
