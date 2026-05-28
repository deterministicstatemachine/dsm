// SPDX-License-Identifier: MIT OR Apache-2.0

import type { AndroidBridgeV3 } from '../dsm/bridgeTypes';

let currentBridge: AndroidBridgeV3 | undefined;

export function setBridgeInstance(bridge: AndroidBridgeV3 | undefined) {
  currentBridge = bridge;
}

export function getBridgeInstance(): AndroidBridgeV3 | undefined {
  return currentBridge;
}
