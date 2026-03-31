// Global type augmentations for the DSM WebView bridge.
// Jest types are provided by @types/jest (do not redeclare here).

declare interface Window {
  dsmBridge: {
    callNative(method: string, payload: Uint8Array): Promise<Uint8Array>;
  };
  DsmBridge?: {
    __binary?: boolean;
    __callBin?: (payload: Uint8Array) => Promise<Uint8Array>;
    sendMessageBin?: (payload: Uint8Array) => Promise<Uint8Array>;
  };
}
