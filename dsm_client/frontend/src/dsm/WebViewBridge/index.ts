// SPDX-License-Identifier: Apache-2.0
//
// Public facade for the WebView <-> DSM Rust core bridge.
//
// Wire rules: protobuf Uint8Array only (no JSON / hex / base64), no Date.now()
// in protocol logic, no signing in the UI layer. See docs/INTEGRATION_GUIDE.md
// for the full developer onboarding guide.
//
// Re-exports use `export const { ... } = mod` (not `export { ... } from`) so
// that `jest.spyOn(WebViewBridge, 'fn')` can rebind the property.

import * as ble from "./ble";
import * as bilateral from "./bilateral";
import * as diagnostics from "./diagnostics";
import * as events from "./events";
import * as genesis from "./genesis";
import * as preferences from "./preferences";
import * as qr from "./qr";
import * as sessionLock from "./sessionLock";
import * as strictQueries from "./strictQueries";
import * as tokenPolicy from "./tokenPolicy";
import * as transportCore from "./transportCore";

export type { DsmEvent } from "./events";

export const {
  callBin,
  mustBridge,
  normalizeToBytes,
  processEnvelopeV3Bin,
  queryTransportHeadersV3,
  routerInvokeBin,
  routerQueryBin,
  sendBridgeRequestBytes,
  toBytes,
} = transportCore;

export const {
  openBluetoothSettings,
  readPeerRelationshipStatusBridge,
  requestBlePermissions,
  resolveBleAddressForDeviceIdBridge,
  setBleIdentityForAdvertising,
  startBleAdvertisingViaRouter,
  startBleScanViaRouter,
  startPairingAll,
  stopBleAdvertisingViaRouter,
  stopBleScanViaRouter,
  stopPairingAll,
} = ble;

export const {
  acceptBilateralByCommitmentBridge,
  rejectBilateralByCommitmentBridge,
} = bilateral;

export const {
  captureCdbrwOrbitTimings,
  computeB0xAddressBridge,
  getArchitectureInfo,
  getDeviceIdBinBridgeAsync,
  getDiagnosticsLogStrict,
  getRouterStatusBridge,
  getSigningPublicKeyBinBridgeAsync,
  runNativeBridgeSelfTest,
} = diagnostics;

export const { addDsmEventListener } = events;
export const { addSecondaryDeviceBin, createGenesisViaRouter } = genesis;
export const { getPreference, setPreference } = preferences;
export const {
  configureLockViaRouter,
  lockSessionViaRouter,
  unlockSessionViaRouter,
} = sessionLock;

export const {
  getAllBalancesStrictBridge,
  getContactsStrictBridge,
  getInboxStrictBridge,
  getPendingBilateralListStrictBridge,
  getWalletHistoryStrictBridge,
  syncWithStorageStrictBridge,
} = strictQueries;

export const { startNativeQrScannerViaRouter } = qr;
export const {
  getTokenPolicyBytes,
  listCachedTokenPolicies,
  publishTokenPolicyBytes,
} = tokenPolicy;
