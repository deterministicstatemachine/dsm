// SPDX-License-Identifier: MIT OR Apache-2.0

// The bridge object `public/index.html` installs as `window.DsmBridge`: a
// bytes-only MessagePort bridge. `ci/bridge_rpc_names.py` holds these members
// to exactly the keys index.html installs. Separated from WebViewBridge to
// avoid circular imports when providing/injecting the bridge instance.
export interface AndroidBridgeV3 {
  __binary: boolean;
  isAvailable: () => boolean;
  /** One BridgeRpcRequest over the port; answers the BridgeRpcResponse bytes Kotlin posted. */
  sendMessageBin: (payload: Uint8Array) => Promise<Uint8Array>;
  /** `nativeBoundaryStartup`, unwrapped to the boundary's bytes. */
  startup: (payload: Uint8Array) => Promise<Uint8Array>;
  /** `nativeBoundaryIngress`, unwrapped to the boundary's bytes. */
  ingress: (payload: Uint8Array) => Promise<Uint8Array>;
  /** `nativeHostRequest`, unwrapped to the host's bytes. */
  hostRequest: (payload: Uint8Array) => Promise<Uint8Array>;
  getBridgeStatus: () => number;
}
