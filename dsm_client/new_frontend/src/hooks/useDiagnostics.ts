/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useState } from 'react';
import { dsmClient } from '../services/dsmClient';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { buildGitHubIssueUrl } from '../utils/githubIssue';
import { nativeSessionStore } from '../runtime/nativeSessionStore';

type NotifyToast = (type: string, message?: string) => void;

type DiagnosticsState = {
  envConfigError: string | null;
  showDiagnostics: boolean;
  diagLoading: boolean;
  diagnostics: string | null;
  telemetryConsent: boolean;
};

export function useDiagnostics(notifyToast: NotifyToast) {
  const [envConfigError, setEnvConfigError] = useState<string | null>(null);
  const [lastBridgeError, setLastBridgeError] = useState<{ code: number; message: string; debugB32?: string } | null>(null);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [diagLoading, setDiagLoading] = useState(false);
  const [diagnostics, setDiagnostics] = useState<string | null>(null);
  const [telemetryConsent, setTelemetryConsent] = useState(false);

  useEffect(() => {
    const handler = (detail: { message: string; type?: string; help?: string }) => {
      try {
        const msg = detail?.message || 'Environment configuration error';
        console.warn('[Diagnostics] env.config.error received:', msg, detail);
        setEnvConfigError(String(msg));
        
        // Store full error detail for the banner to access
        try {
          (window as any).__envConfigErrorDetail = {
            message: msg,
            type: detail?.type || 'UNKNOWN',
            help: detail?.help || ''
          };
        } catch (_e) {
          // ignore
        }
      } catch (_e) {
        setEnvConfigError('Environment configuration error (unknown)');
      }
    };
    const unsubscribe = bridgeEvents.on('env.config.error', handler as any);

    const bridgeErrHandler = (detail: { code: number; message: string; debugB32?: string }) => {
      try {
        console.warn('[Diagnostics] bridge.error received:', detail.message, detail.debugB32 ? 'debug present' : 'no debug');
        const obj = { code: detail.code ?? 0, message: detail.message ?? '', debugB32: detail.debugB32 };
        setLastBridgeError(obj);
        // Mirror into global for simple modal consumption in tests/UI
        try { (window as any).__lastBridgeError = obj; } catch (_e) {}
      } catch {
        // ignore
      }
    };
    const unsub2 = bridgeEvents.on('bridge.error', bridgeErrHandler as any);

    return () => { unsubscribe(); unsub2(); };
  }, []);

  const gatherDiagnostics = useCallback(async () => {
    setDiagLoading(true);
    setDiagnostics(null);
    try {
      const wb = await import('../dsm/WebViewBridge');
      const info: Record<string, any> = {};
      try {
        const session = nativeSessionStore.getSnapshot();
        info.bridgeStatus = session.received ? `native-session:${session.phase}` : 'native-session:pending';
      } catch (e) {
        info.bridgeStatus = `error: ${String(e)}`;
      }
      try { info.selfTest = wb.runNativeBridgeSelfTest(); } catch (e) { info.selfTest = `error: ${String(e)}`; }
      try { info.lastError = (wb as any).getLastError?.() ?? (wb as any).lastError?.() ?? ''; } catch (e) { info.lastError = `error: ${String(e)}`; }
      try { const p = await dsmClient.getPreference('DSM_ENV_CONFIG_PATH'); info.envPath = p; } catch (e) { info.envPath = `error: ${String(e)}`; }
      try { const gh = await dsmClient.getPreference('genesis_hash_bytes'); info.genesisHash = gh; } catch (e) { info.genesisHash = `error: ${String(e)}`; }
      try { const did = await dsmClient.getPreference('device_id_bytes'); info.deviceId = did; } catch (e) { info.deviceId = `error: ${String(e)}`; }
      
      // Add architecture compatibility info
      try {
        const arch = await wb.getArchitectureInfo();
        info.archStatus = arch.status;
        info.archDevice = arch.deviceArch;
        info.archAbis = arch.supportedAbis;
        info.archMessage = arch.message;
        info.archRecommendation = arch.recommendation;
      } catch (e) {
        info.archStatus = 'UNKNOWN';
        info.archError = String(e);
      }

      const lines = [
        'DSM diagnostics (clockless)',
        `message=${envConfigError ?? ''}`,
        `bridgeStatus=${String(info.bridgeStatus ?? '')}`,
        `selfTest=${String(info.selfTest ?? '')}`,
        `lastError=${String(info.lastError ?? '')}`,
        `lastBridgeError=${lastBridgeError ? `${lastBridgeError.code}:${lastBridgeError.message}` : ''}`,
        `bridgeErrorDebugB32=${lastBridgeError?.debugB32 ?? ''}`,
        `envPath=${String(info.envPath ?? '')}`,
        `genesisHash=${String(info.genesisHash ?? '')}`,
        `deviceId=${String(info.deviceId ?? '')}`,
        `archStatus=${String(info.archStatus ?? 'UNKNOWN')}`,
        `archDevice=${String(info.archDevice ?? 'unknown')}`,
        `archAbis=${String(info.archAbis ?? '')}`,
        `archMessage=${String(info.archMessage ?? '')}`,
        `archRecommendation=${String(info.archRecommendation ?? '')}`,
      ];
      setDiagnostics(lines.join('\n'));
      setShowDiagnostics(true);
    } catch (e) {
      setDiagnostics(`Failed to gather diagnostics: ${String(e)}`);
      setShowDiagnostics(true);
    } finally {
      setDiagLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [envConfigError]);

  const openGitHubIssue = useCallback(() => {
    void (async () => {
      try {
      const title = `Env config error: ${envConfigError ? envConfigError.substring(0, 80) : 'configuration failure'}`;
      const excerpt = diagnostics ? diagnostics.substring(0, 1024) : '';
      const body =
        `**Describe the problem**\n\nEnvironment configuration failed during app startup. Please attach the diagnostics file you downloaded ("dsm-diagnostics.txt").\n\nDiagnostics excerpt:\n\n----BEGIN EXCERPT----\n${excerpt}\n----END EXCERPT----\n\n**Steps to reproduce**\n1. Install the app\n2. Launch the app\n3. Observe the configuration error\n\n**Additional info**\n- Attach adb logcat output if available\n`;
      const url = buildGitHubIssueUrl({ title, body });
      const popup = window.open(url, '_blank', 'noopener');
      if (!popup && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(url);
        notifyToast('success', 'Issue link copied to clipboard');
        return;
      }
      if (!popup) {
        throw new Error('Popup blocked and clipboard unavailable.');
      }
      notifyToast('success', 'GitHub issue opened');
      } catch {
        try {
        const defaultUrl = buildGitHubIssueUrl();
        const popup = window.open(defaultUrl, '_blank', 'noopener');
        if (!popup && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(defaultUrl);
          notifyToast('success', 'Issue link copied to clipboard');
          return;
        }
        if (!popup) {
          throw new Error('Popup blocked and clipboard unavailable.');
        }
        notifyToast('success', 'GitHub issue opened');
        } catch (_e) {
          notifyToast('error', 'Failed to open GitHub');
        }
      }
    })();
  }, [diagnostics, envConfigError, notifyToast]);

  const sendDiagnosticsTelemetry = useCallback(async () => {
    if (!diagnostics) return;
    try {
      const t = await import('../services/telemetry');
      await t.sendDiagnostics(diagnostics, telemetryConsent);
      notifyToast('success', 'Diagnostics sent');
    } catch (e) {
      notifyToast('error', `Failed to send diagnostics: ${String(e)}`);
    }
  }, [diagnostics, notifyToast, telemetryConsent]);

  const copyDiagnostics = useCallback(async () => {
    if (!diagnostics) return;
    try {
      await navigator.clipboard.writeText(diagnostics);
      notifyToast('success', 'Diagnostics copied to clipboard');
    } catch (e) {
      notifyToast('error', 'Copy failed');
      console.warn('Failed to copy diagnostics:', e);
    }
  }, [diagnostics, notifyToast]);

  const downloadDiagnostics = useCallback(() => {
    if (!diagnostics) return;
    const blob = new Blob([diagnostics], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'dsm-diagnostics.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    notifyToast('success', 'Diagnostics downloaded');
  }, [diagnostics, notifyToast]);

  const state: DiagnosticsState = {
    envConfigError,
    showDiagnostics,
    diagLoading,
    diagnostics,
    telemetryConsent,
  };

  return {
    ...state,
    setEnvConfigError,
    setShowDiagnostics,
    setTelemetryConsent,
    gatherDiagnostics,
    openGitHubIssue,
    sendDiagnosticsTelemetry,
    copyDiagnostics,
    downloadDiagnostics,
    lastBridgeError,
  };
}
