// Canonical bridge interface type, separated from WebViewBridge implementation
// to avoid circular imports when providing/injecting the bridge instance.
export interface AndroidBridgeV3 {
  // New bytes-only MessagePort bridge
  __binary?: boolean;
  sendMessageBin?: (payload: Uint8Array) => Promise<Uint8Array>;
  __callBin?: (payload: Uint8Array) => Promise<Uint8Array>;

  // Optional bridge error helper
  lastError?: () => string | null | undefined;
  // Router helpers
  getAppRouterStatus?: () => number;

  // Misc utilities
  computeB0xAddress?: (genesis: Uint8Array, deviceId: Uint8Array, tip: Uint8Array) => string;
  runNativeBridgeSelfTest?: () => unknown;

  // Optional introspection (Android bridge may expose these)
  getRouterStatus?: () => Promise<number> | number;
  ensureRouterInstalled?: () => Promise<boolean> | boolean;
}
