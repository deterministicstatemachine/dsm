// SPDX-License-Identifier: MIT OR Apache-2.0

import type { AndroidBridgeV3 } from '../dsm/bridgeTypes';
import { inPracticeSandbox, practiceView } from './practiceGate';

let currentBridge: AndroidBridgeV3 | undefined;

export function setBridgeInstance(bridge: AndroidBridgeV3 | undefined) {
  currentBridge = bridge;
}

/**
 * The bridge every call to native code goes through. While the guided tour's
 * practice wallet stands in, it is the practice view, which lets only reads
 * cross (bridge/practiceGate.ts).
 */
export function getBridgeInstance(): AndroidBridgeV3 | undefined {
  if (currentBridge === undefined) return undefined;
  return inPracticeSandbox() ? practiceView(currentBridge) : currentBridge;
}
