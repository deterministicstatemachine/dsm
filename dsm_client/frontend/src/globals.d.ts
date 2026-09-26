// SPDX-License-Identifier: MIT OR Apache-2.0

// Global type augmentations for the DSM WebView bridge.
// Jest types are provided by @types/jest (do not redeclare here).

declare interface Window {
  DsmBridge?: {
    __binary?: boolean;
    sendMessageBin?: (payload: Uint8Array) => Promise<Uint8Array>;
  };
}
