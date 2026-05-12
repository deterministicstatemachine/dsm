/* eslint-disable @typescript-eslint/no-explicit-any */
/* Jest tests for WebViewBridge event channel and error surfacing */
// Jest globals (describe, test, expect) are available without import in configured test environment.
import { setBridgeInstance } from "../../bridge/BridgeRegistry";
import { bridgeGate } from "../BridgeGate";
import {
  addDsmEventListener,
  getPreference,
  queryTransportHeadersV3,
  setPreference,
} from "../WebViewBridge";
import type { DsmEvent } from "../WebViewBridge";

afterEach(() => {
  // Reset bridge to empty object via the setupTests proxy so subsequent
  // assignments to window.DsmBridge keep going through setBridgeInstance.
  // Do NOT `delete window.DsmBridge` — that removes the Object.defineProperty
  // proxy installed in setupTests, after which assignments no longer update
  // the registry and mustBridge() throws "DSM bridge not available".
  (globalThis as any).window.DsmBridge = {};
  setBridgeInstance(undefined);
  jest.restoreAllMocks();
});

describe("WebViewBridge dsm-event listener", () => {
  test("receives binary payload bytes", (done: (err?: any) => void) => {
    const payload = new Uint8Array([0x00, 0xff, 0x10, 0x41]);

    const unsub = addDsmEventListener((evt: DsmEvent) => {
      try {
        expect(evt.topic).toBe("test-topic");
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
    window.dispatchEvent(
      new CustomEvent("dsm-event-bin", { detail: { topic: "test-topic", payload } })
    );
  });
});

describe("WebViewBridge error surfacing via lastError", () => {
  test("throws when native returns empty and lastError present", async () => {
    // Stub bridge
    (globalThis as any).window = (globalThis as any).window || {};
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async () => (global as any).createDsmBridgeSuccessResponse(new Uint8Array(0)),
      lastError: () => "sdk_context_uninitialized",
    };
    await expect(queryTransportHeadersV3()).rejects.toThrow(/sdk_context_uninitialized/);
  });

  test("does not throw when empty and no lastError", async () => {
    (globalThis as any).window.DsmBridge = {
      __binary: true,
      __callBin: async () => (global as any).createDsmBridgeSuccessResponse(new Uint8Array(0)),
    };
    const res = await queryTransportHeadersV3();
    expect(res).toBeInstanceOf(Uint8Array);
    expect(res.length).toBe(0);
  });
});

describe("WebViewBridge preference gating", () => {
  test("getPreference executes through bridgeGate", async () => {
    const enqueueSpy = jest.spyOn(bridgeGate, "enqueue");
    const bridge = {
      __binary: true,
      __callBin: async (reqBytes: Uint8Array) => {
        const pb = require("../../proto/dsm_app_pb");
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        expect(req.method).toBe("getPreference");
        const payload = req.payload?.case === "bytes" ? req.payload.value?.data : new Uint8Array(0);
        const pref = pb.PreferencePayload.fromBinary(payload);
        expect(pref.key).toBe("theme");
        return (global as any).createDsmBridgeSuccessResponse(new TextEncoder().encode("dark"));
      },
    };

    (globalThis as any).window.DsmBridge = bridge;
    setBridgeInstance(bridge as any);

    await expect(getPreference("theme")).resolves.toBe("dark");
    expect(enqueueSpy).toHaveBeenCalledTimes(1);
  });

  test("setPreference executes through bridgeGate", async () => {
    const enqueueSpy = jest.spyOn(bridgeGate, "enqueue");
    const bridge = {
      __binary: true,
      __callBin: async (reqBytes: Uint8Array) => {
        const pb = require("../../proto/dsm_app_pb");
        const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
        expect(req.method).toBe("setPreference");
        const payload = req.payload?.case === "bytes" ? req.payload.value?.data : new Uint8Array(0);
        const pref = pb.PreferencePayload.fromBinary(payload);
        expect(pref.key).toBe("theme");
        expect(pref.value).toBe("dark");
        return (global as any).createDsmBridgeSuccessResponse(new Uint8Array(0));
      },
    };

    (globalThis as any).window.DsmBridge = bridge;
    setBridgeInstance(bridge as any);

    await setPreference("theme", "dark");
    expect(enqueueSpy).toHaveBeenCalledTimes(1);
  });
});
