/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { useDiagnostics } from '../hooks/useDiagnostics';
import { useUX } from '../contexts/UXContext';
import { decodeBase32Crockford } from '../utils/textId';

const overlayBackdropStyle: React.CSSProperties = {
  position: 'absolute',
  inset: 0,
  background:
    'linear-gradient(180deg, rgba(var(--text-rgb),0.18), rgba(var(--text-rgb),0.1)), var(--bg)',
  display: 'flex',
  alignItems: 'stretch',
  justifyContent: 'stretch',
  zIndex: 220,
  padding: 4,
};

const overlayCardStyle: React.CSSProperties = {
  width: '100%',
  height: '100%',
  display: 'flex',
  flexDirection: 'column',
  overflow: 'hidden',
  background: 'var(--stateboy-screen)',
  borderRadius: 10,
  border: '2px solid var(--border)',
  color: 'var(--text-dark)',
  boxShadow: '0 8px 20px rgba(var(--text-dark-rgb),0.35)',
};

const sectionCardStyle: React.CSSProperties = {
  background: 'rgba(var(--bg-rgb),0.55)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: 10,
};

const actionButtonStyle: React.CSSProperties = {
  padding: '9px 10px',
  fontSize: '10px',
  lineHeight: 1.2,
  background:
    'linear-gradient(180deg, rgba(var(--bg-rgb),0.12), rgba(var(--bg-rgb),0.03)), var(--stateboy-dark)',
  color: 'var(--bg)',
  border: '2px solid var(--border)',
  borderRadius: 8,
  cursor: 'pointer',
  fontWeight: 700,
  letterSpacing: '0.3px',
  minHeight: 34,
  fontFamily: 'Martian Mono, monospace',
  textAlign: 'center',
  boxShadow: 'inset 0 -2px 0 rgba(var(--text-dark-rgb),0.2), inset 0 1px 0 rgba(var(--bg-rgb),0.14)',
};

const secondaryButtonStyle: React.CSSProperties = {
  ...actionButtonStyle,
  background:
    'linear-gradient(180deg, rgba(var(--text-rgb),0.08), rgba(var(--text-rgb),0.02)), rgba(var(--bg-rgb),0.82)',
  color: 'var(--text-dark)',
};

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
      <div style={overlayBackdropStyle} data-testid="diagnostics-overlay">
        <div style={overlayCardStyle} role="dialog" aria-modal>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, padding: '12px 12px 10px', borderBottom: '1px solid rgba(var(--text-rgb),0.16)', background: 'rgba(var(--bg-rgb),0.18)' }}>
            <div style={{ minWidth: 0 }}>
              <strong style={{ display: 'block', fontSize: '12px', letterSpacing: '0.4px' }}>DSM Diagnostics</strong>
              <span style={{ display: 'block', fontSize: '9px', opacity: 0.76, marginTop: 2, lineHeight: 1.3 }}>Prepare a report without leaving the in-app screen.</span>
            </div>
            <button onClick={() => { setShowDiagnostics(false); }} style={secondaryButtonStyle}>Close</button>
          </div>

          <div style={{ padding: '12px', overflowY: 'auto', flex: 1, minHeight: 0 }}>
            <div style={{ ...sectionCardStyle, marginBottom: 10, color: 'var(--text-dark)', fontSize: '11px' }}>
              <div style={{ marginBottom: 8, fontWeight: 700 }}>Suggested actions</div>
              <ul style={{ marginTop: 0, marginBottom: 8, paddingLeft: 18, fontSize: '10px', lineHeight: 1.35 }}>
              <li>Copy or download the diagnostics and attach them to an issue.</li>
              <li>Collect device logs (adb logcat) for a full trace.</li>
              <li>If you consent, save diagnostics into the local native log before filing a report.</li>
              </ul>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: '10px', lineHeight: 1.4 }}>
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
                    cursor: 'pointer',
                    marginTop: 1,
                    flexShrink: 0,
                  }}
                />
                <span>Include diagnostics when preparing reports and save this preference on this device</span>
              </label>
            </div>

            <div style={{ ...sectionCardStyle, marginBottom: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 8 }}>
                <button data-testid="send-diagnostics" disabled={!telemetryConsent || !diagnostics} onClick={() => void sendDiagnosticsTelemetry()} style={{ ...actionButtonStyle, opacity: (!telemetryConsent || !diagnostics) ? 0.5 : 1, cursor: (!telemetryConsent || !diagnostics) ? 'not-allowed' : 'pointer' }}>Save to local log</button>
                <button data-testid="copy-diagnostics" onClick={() => void copyDiagnostics()} style={actionButtonStyle}>Copy</button>
                <button data-testid="download-diagnostics" onClick={() => downloadDiagnostics()} style={actionButtonStyle}>Download</button>
                <button data-testid="open-issue" onClick={() => openGitHubIssue()} style={actionButtonStyle}>Open beta bug report</button>
                <button data-testid="open-feedback" onClick={() => openGitHubFeedback()} style={actionButtonStyle}>Send feedback</button>
              </div>
            </div>

            <pre style={{ fontSize: '10px', lineHeight: 1.4, whiteSpace: 'pre-wrap', wordBreak: 'break-all', background: 'rgba(var(--bg-rgb),0.78)', padding: '10px', borderRadius: 8, border: '1px solid var(--border)', color: 'var(--text-dark)', margin: 0 }}>{diagnostics ?? 'No diagnostics collected yet.'}</pre>

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
              <div style={{ ...sectionCardStyle, marginTop: 10, fontSize: '10px', maxWidth: '100%', overflow: 'hidden' }}>
                <strong style={{ fontSize: '11px' }}>Last Bridge Error</strong>
                <div style={{ marginTop: 6 }}>
                  <div style={{ wordBreak: 'break-word', overflowWrap: 'anywhere' }}><strong>Code:</strong> {errorObj?.code ?? ''}</div>
                  <div style={{ wordBreak: 'break-word', overflowWrap: 'anywhere' }}><strong>Message:</strong> {errorObj?.message ?? ''}</div>

                  <div style={{ marginTop: 8 }}><strong>{decodeError ? 'Raw Debug (decode failed):' : 'Debug Info:'}</strong></div>
                  <div style={{ wordBreak: 'break-word', overflowWrap: 'anywhere', fontSize: '10px', marginBottom: 6, background: 'rgba(var(--bg-rgb),0.74)', padding: 8, borderRadius: 6, maxWidth: '100%', overflow: 'auto', whiteSpace: 'pre-wrap', fontFamily: 'monospace', lineHeight: 1.4 }}>{decodedMessage || 'No debug info'}</div>

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
                    }} style={actionButtonStyle}>Copy</button>
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
                    }} style={actionButtonStyle}>Download Binary</button>
                  </div>
                </div>
              </div>
            );
            })() : null }
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
