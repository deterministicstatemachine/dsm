// SPDX-License-Identifier: MIT OR Apache-2.0
// Diagnostics logging for beta support: the report goes into the native
// bridge log, and only with the user's consent.

import { callBin } from '../dsm/WebViewBridge';

export const DIAGNOSTICS_LOG_METHOD = 'diagnosticsLog';

/**
 * Writes `report` into the native bridge log (`BridgeLogger`). Without
 * consent nothing is sent; a bridge failure is the caller's to show.
 */
export async function sendDiagnostics(report: string, hasConsent: boolean): Promise<void> {
  if (!hasConsent) return;
  await callBin(DIAGNOSTICS_LOG_METHOD, new TextEncoder().encode(report));
}
