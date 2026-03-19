/* eslint-disable @typescript-eslint/no-explicit-any */
// Simple telemetry helper for diagnostics. Tests should mock this module.
export const TELEMETRY_ENDPOINT = '/telemetry/diagnostics';

export async function sendDiagnostics(payload: any, hasConsent: boolean = false): Promise<void> {
  if (!hasConsent) {
    // Consent gate: diagnostics must be opt-in.
    return;
  }

  // Clockless + protobuf-only rule: telemetry must not use wall-clock time or JSON.
  // Send raw text bytes across the bridge so BridgeLogger captures it in the log file (beta diagnostics).
  try {
    const encoder = new TextEncoder();
    const payloadBytes = encoder.encode(String(payload ?? ''));

    try {
      const wb = await import('../dsm/WebViewBridge');
      if (typeof wb.callBin === 'function') {
        await wb.callBin('diagnosticsLog', payloadBytes);
        return;
      }
    } catch {
      // fall through
    }

    const bridge = (window as any).DsmBridge || (window as any).dsmBridge;
    if (bridge && typeof bridge.__callBin === 'function') {
      const pb = await import('../proto/dsm_app_pb');
      const req = new pb.BridgeRpcRequest({
        method: 'diagnosticsLog',
        payload: { case: 'bytes', value: new pb.BytesPayload({ data: payloadBytes as Uint8Array<ArrayBuffer> }) },
      });
      await bridge.__callBin(req.toBinary());
      return;
    }
    if (bridge && typeof bridge.postMessage === 'function') {
      bridge.postMessage(payloadBytes);
    }
  } catch {
    // Swallow telemetry errors
  }
}

/**
 * Returns true when the user has opted into diagnostics sharing.
 * Reads the `diagnostics_consent` preference via the bridge; returns false on
 * any error (fail-closed).
 */
export async function hasUserConsentFromPrefs(): Promise<boolean> {
  try {
    const wb = await import('../dsm/WebViewBridge');
    if (typeof wb.callBin !== 'function') return false;
    const bytes = await wb.callBin('prefs.get', new TextEncoder().encode('diagnostics_consent'));
    return new TextDecoder().decode(bytes).trim() === '1';
  } catch {
    return false;
  }
}

/**
 * Export the persisted bridge diagnostics log as raw bytes.
 * The log is written by BridgeLogger (up to 5 MB tail) and contains
 * protobuf-envelope previews and bridge error metadata.
 */
export async function exportDiagnosticsReport(): Promise<Uint8Array> {
  try {
    const wb = await import('../dsm/WebViewBridge');
    if (typeof wb.getDiagnosticsLogStrict === 'function') {
      return wb.getDiagnosticsLogStrict();
    }
    return new Uint8Array(0);
  } catch {
    return new Uint8Array(0);
  }
}
