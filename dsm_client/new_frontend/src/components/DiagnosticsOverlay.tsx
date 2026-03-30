/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { useDiagnostics } from '../hooks/useDiagnostics';
import { useUX } from '../contexts/UXContext';
import { decodeBase32Crockford } from '../utils/textId';

export default function DiagnosticsOverlay() {
  const { notifyToast } = useUX();
  const {
    envConfigError,
    showDiagnostics,
    diagLoading,
    diagnostics,
    telemetryConsent,
    setEnvConfigError,
    setShowDiagnostics,
    setTelemetryConsent,
    gatherDiagnostics,
    copyDiagnostics,
    downloadDiagnostics,
    sendDiagnosticsTelemetry,
    openGitHubIssue,
    openGitHubFeedback,
  } = useDiagnostics(notifyToast);

  const hasBridgeError = !!(window as any).__lastBridgeError;

  // Show overlay if there's an env config error, diagnostics are shown, or there's a bridge error
  if (!envConfigError && !showDiagnostics && !hasBridgeError) return null;

  const EnvConfigErrorBanner = () => {
    if (!envConfigError) return null;

    // Parse error detail if available
    let errorMessage = envConfigError;
    let helpText = '';

    try {
      // Try to extract structured error from event
      const errorData = (window as any).__envConfigErrorDetail;
      if (errorData) {
        errorMessage = errorData.message || envConfigError;
        helpText = errorData.help || '';
      }
    } catch (_e) {
      // Use raw error message
    }

    return (
      <div style={{ position: 'absolute', left: 8, right: 8, top: 8, zIndex: 120, background: 'var(--stateboy-dark)', color: 'var(--text)', padding: '8px', borderRadius: 8, boxShadow: '0 2px 6px rgba(var(--text-rgb),0.2)', border: '2px solid var(--border)', flexDirection: 'column', maxHeight: 'calc(100% - 16px)', maxWidth: 'calc(100% - 16px)', overflow: 'auto', wordBreak: 'break-word', overflowWrap: 'anywhere', fontSize: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: helpText ? '8px' : '0', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ fontWeight: 700, minWidth: 0, flex: '1 1 100%' }}>CONFIGURATION ERROR: {errorMessage}</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => void gatherDiagnostics()} style={{ background: 'var(--stateboy-screen)', color: 'var(--text-dark)', padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', cursor: 'pointer', fontWeight: 600 }}>{diagLoading ? 'Gathering…' : 'Diagnostics'}</button>
            <button onClick={() => setEnvConfigError(null)} style={{ background: 'transparent', color: 'var(--text)', padding: '6px 8px', borderRadius: 6, border: '1px solid rgba(var(--text-rgb),0.35)', cursor: 'pointer' }}>Dismiss</button>
          </div>
        </div>
        {helpText && (
          <div style={{ fontSize: '11px', lineHeight: '1.4', opacity: 0.9, paddingTop: '4px', borderTop: '1px solid rgba(var(--text-rgb),0.35)' }}>
            &gt; <strong>Help:</strong> {helpText}
          </div>
        )}
      </div>
    );
  };

  const BridgeErrorBanner = () => {
    if (!hasBridgeError) return null;
    return (
      <div style={{ position: 'absolute', left: 8, right: 8, top: 8, zIndex: 120, background: 'var(--bg)', color: 'var(--text-dark)', padding: '8px', borderRadius: 8, boxShadow: '0 2px 6px rgba(var(--text-rgb),0.2)', border: '2px solid var(--border)', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', maxHeight: 'calc(100% - 16px)', maxWidth: 'calc(100% - 16px)', overflow: 'auto', wordBreak: 'break-word', overflowWrap: 'anywhere', fontSize: '10px' }}>
        <div style={{ fontWeight: 700, minWidth: 0, flex: '1 1 100%' }}>DSM error: {(window as any).__lastBridgeError?.message || 'Unknown error'}</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button onClick={() => setShowDiagnostics(true)} style={{ background: 'var(--stateboy-screen)', color: 'var(--text-dark)', padding: '6px 8px', borderRadius: 6, border: '1px solid var(--border)', cursor: 'pointer' }}>Show diagnostics</button>
          <button onClick={() => { try { (window as any).__lastBridgeError = null; } catch (_e) {} }} style={{ background: 'transparent', color: 'var(--text-dark)', padding: '6px 8px', borderRadius: 6, border: '1px solid rgba(var(--text-rgb),0.35)', cursor: 'pointer' }}>Dismiss</button>
        </div>
      </div>
    );
  };

  const DiagnosticsModal = () => {
    if (!showDiagnostics) return null;
    return (
      <div style={{ position: 'absolute', left: 0, right: 0, top: 0, bottom: 0, background: 'rgba(var(--text-dark-rgb),0.65)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200 }}>
        <div style={{ width: 'min(95%, calc(100% - 16px))', maxHeight: '85%', overflow: 'auto', background: 'var(--stateboy-screen)', borderRadius: 12, padding: '10px', border: '2px solid var(--border)', color: 'var(--text-dark)', fontSize: '10px', boxShadow: '0 4px 12px rgba(var(--text-dark-rgb),0.4)' }} role="dialog" aria-modal>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, fontSize: '11px' }}>
            <strong style={{ fontSize: '11px' }}>DSM Diagnostics</strong>
            <button onClick={() => { setShowDiagnostics(false); }} style={{ padding: '4px 8px', fontSize: '16px', background: 'var(--stateboy-dark)', color: 'var(--bg)', border: '2px solid var(--border)', borderRadius: 8, cursor: 'pointer', fontWeight: 'bold', lineHeight: '1' }}>×</button>
          </div>

          <div style={{ marginBottom: 8, color: 'var(--text-dark)', fontSize: '10px' }}>
            <div style={{ marginBottom: 6 }}>These diagnostics contain runtime state useful for debugging initialization failures. Suggested actions:</div>
            <ul style={{ marginTop: 0, marginBottom: 6, paddingLeft: 16, fontSize: '9px' }}>
              <li>Copy or download the diagnostics and attach them to an issue.</li>
              <li>Collect device logs (adb logcat) for a full trace.</li>
              <li>If you consent, save diagnostics into the local native log before filing a report.</li>
            </ul>

            <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '9px' }}>
              <input
                data-testid="telemetry-checkbox"
                type="checkbox"
                checked={telemetryConsent}
                onChange={(e) => setTelemetryConsent(e.target.checked)}
                style={{
                  width: 14,
                  height: 14,
                  accentColor: 'var(--border)',
                  border: '2px solid var(--border)',
                  borderRadius: 3,
                  cursor: 'pointer'
                }}
              />
              <span>Include diagnostics when preparing reports and save this preference on this device</span>
            </label>

            <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button data-testid="send-diagnostics" disabled={!telemetryConsent || !diagnostics} onClick={() => void sendDiagnosticsTelemetry()} style={{ padding: '4px 6px', fontSize: '9px', background: 'var(--bg)', color: 'var(--text-dark)', border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer', opacity: (!telemetryConsent || !diagnostics) ? 0.5 : 1 }}>Save to local log</button>
              <button data-testid="copy-diagnostics" onClick={() => void copyDiagnostics()} style={{ padding: '4px 6px', fontSize: '9px', background: 'var(--bg)', color: 'var(--text-dark)', border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer' }}>Copy</button>
              <button data-testid="download-diagnostics" onClick={() => downloadDiagnostics()} style={{ padding: '4px 6px', fontSize: '9px', background: 'var(--bg)', color: 'var(--text-dark)', border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer' }}>Download</button>
              <button data-testid="open-issue" onClick={() => openGitHubIssue()} style={{ padding: '4px 6px', fontSize: '9px', background: 'var(--bg)', color: 'var(--text-dark)', border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer' }}>Open beta bug report</button>
              <button data-testid="open-feedback" onClick={() => openGitHubFeedback()} style={{ padding: '4px 6px', fontSize: '9px', background: 'var(--bg)', color: 'var(--text-dark)', border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer' }}>Send feedback</button>
            </div>
          </div>

          <pre style={{ fontSize: '9px', lineHeight: 1.3, whiteSpace: 'pre-wrap', wordBreak: 'break-all', background: 'var(--bg)', padding: '8px', borderRadius: 8, border: '1px solid var(--border)', color: 'var(--text-dark)' }}>{diagnostics ?? 'No diagnostics collected yet.'}</pre>

          {/* Bridge error debug UI */}
          { (window as any).__lastBridgeError || null ? (() => {
            const errorObj = (window as any).__lastBridgeError;
            let decodedMessage = '';
            let hexDisplay = '';
            let decodeError = '';

            try {
              const bytes = decodeBase32Crockford(errorObj?.debugB32 || '');

              // Convert to hex for display (binary-safe)
              const hexArray: string[] = [];
              for (let i = 0; i < bytes.length; i++) {
                hexArray.push(bytes[i].toString(16).padStart(2, '0'));
              }
              hexDisplay = hexArray.join(' ');

              // Try UTF-8 decode, but show hex if it contains invalid sequences
              const utf8Text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
              if (utf8Text.includes('\ufffd')) {
                // Contains replacement characters - binary data, show hex
                decodedMessage = `Binary data (hex): ${  hexDisplay}`;
              } else {
                // Valid UTF-8, show text
                decodedMessage = utf8Text;
              }
            } catch (e: any) {
              decodeError = e?.message || String(e);
              decodedMessage = errorObj?.debugB32 || '';
            }

            return (
              <div style={{ marginTop: 10, padding: 8, border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg)', fontSize: '9px', maxWidth: '100%', overflow: 'hidden' }}>
                <strong style={{ fontSize: '10px' }}>Last Bridge Error</strong>
                <div style={{ marginTop: 6 }}>
                  <div style={{ wordBreak: 'break-word', overflowWrap: 'anywhere' }}><strong>Code:</strong> {errorObj?.code ?? ''}</div>
                  <div style={{ wordBreak: 'break-word', overflowWrap: 'anywhere' }}><strong>Message:</strong> {errorObj?.message ?? ''}</div>

                  <div style={{ marginTop: 8 }}><strong>{decodeError ? 'Raw Debug (decode failed):' : 'Debug Info:'}</strong></div>
                  <div style={{ wordBreak: 'break-word', overflowWrap: 'anywhere', fontSize: '9px', marginBottom: 6, background: 'var(--stateboy-screen)', padding: 6, borderRadius: 6, maxWidth: '100%', overflow: 'auto', whiteSpace: 'pre-wrap', fontFamily: 'monospace', lineHeight: 1.4 }}>{decodedMessage || 'No debug info'}</div>

                  {decodeError && (
                    <div style={{ marginTop: 4, fontSize: '8px', color: 'var(--text-dark)', opacity: 0.7 }}>Decode error: {decodeError}</div>
                  )}

                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 6 }}>
                    <button onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(decodedMessage);
                        alert('Copied to clipboard');
                      } catch {
                        alert('Copy failed');
                      }
                    }} style={{ padding: '4px 6px', fontSize: '9px', background: 'var(--stateboy-screen)', color: 'var(--text-dark)', border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer' }}>Copy</button>
                    <button onClick={() => {
                      try {
                        const bytes = decodeBase32Crockford(errorObj?.debugB32 || '');
                        const buf = bytes.buffer instanceof ArrayBuffer
                          ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
                          : new Uint8Array(bytes).buffer;
                        const blob = new Blob([buf], { type: 'application/octet-stream' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'dsm-error-debug.bin';
                        document.body.appendChild(a);
                        a.click();
                        a.remove();
                        URL.revokeObjectURL(url);
                      } catch { alert('decode/download failed'); }
                    }} style={{ padding: '4px 6px', fontSize: '9px', background: 'var(--stateboy-screen)', color: 'var(--text-dark)', border: '1px solid var(--border)', borderRadius: 8, cursor: 'pointer' }}>Download Binary</button>
                  </div>
                </div>
              </div>
            );
          })() : null }

          <div style={{ marginTop: 10, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
            <button onClick={() => void openGitHubIssue()} style={{ padding: '6px 10px', fontSize: '10px', background: 'var(--stateboy-dark)', color: 'var(--text)', borderRadius: 10, border: '2px solid var(--border)', cursor: 'pointer', fontWeight: 600 }}>
              Open beta bug report
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <>
      <EnvConfigErrorBanner />
      <BridgeErrorBanner />
      <DiagnosticsModal />
    </>
  );
}
