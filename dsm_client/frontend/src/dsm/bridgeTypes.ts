// SPDX-License-Identifier: MIT OR Apache-2.0

// The bridge object `public/index.html` installs as `window.DsmBridge`: a
// bytes-only MessagePort bridge. Separated from WebViewBridge to avoid
// circular imports when providing/injecting the bridge instance.
export interface AndroidBridgeV3 {
  __binary?: boolean;
  sendMessageBin?: (payload: Uint8Array) => Promise<Uint8Array>;
  __callBin?: (payload: Uint8Array) => Promise<Uint8Array>;
  startup?: (payload: Uint8Array) => Promise<Uint8Array>;
  ingress?: (payload: Uint8Array) => Promise<Uint8Array>;
  hostRequest?: (payload: Uint8Array) => Promise<Uint8Array>;
  isAvailable?: () => boolean;
  getBridgeStatus?: () => number;
}
