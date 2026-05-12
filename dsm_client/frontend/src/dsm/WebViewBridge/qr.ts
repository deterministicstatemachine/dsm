// SPDX-License-Identifier: Apache-2.0
// Native QR scanner integration.

import { startNativeQrScan } from "../NativeHostBridge";
import { dispatchNativeQrScannerActive } from "../qrScannerState";

/**
 * Launch the native QR scanner. Result arrives via the 'dsm-event' channel
 * with topic 'qr_scan_result' (empty string on cancel/error).
 */
export async function startNativeQrScannerViaRouter(): Promise<void> {
  dispatchNativeQrScannerActive(true);
  try {
    await startNativeQrScan();
  } catch (error) {
    dispatchNativeQrScannerActive(false);
    throw error;
  }
}
