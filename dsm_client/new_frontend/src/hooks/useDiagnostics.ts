/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useState } from 'react';
import { dsmClient } from '../services/dsmClient';
import { bridgeEvents } from '../bridge/bridgeEvents';
import {
  BETA_BUG_TEMPLATE,
  BETA_FEEDBACK_TEMPLATE,
  buildGitHubIssueUrl,
} from '../utils/githubIssue';
import { nativeSessionStore } from '../runtime/nativeSessionStore';

type NotifyToast = (type: string, message?: string) => void;

type DiagnosticsState = {
  envConfigError: string | null;
  showDiagnostics: boolean;
  diagLoading: boolean;
  diagnostics: string | null;
  telemetryConsent: boolean;
};

const DIAGNOSTICS_CONSENT_PREF_KEY = 'diagnostics_consent';
const OPEN_DIAGNOSTICS_EVENT = 'dsm-open-diagnostics';

type DiagnosticsOpenDetail = {
  autoGather?: boolean;
};

export function useDiagnostics(notifyToast: NotifyToast) {
  const [envConfigError, setEnvConfigError] = useState<string | null>(null);
  const [lastBridgeError, setLastBridgeError] = useState<{ code: number; message: string; debugB32?: string } | null>(null);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [diagLoading, setDiagLoading] = useState(false);
  const [diagnostics, setDiagnostics] = useState<string | null>(null);
  const [telemetryConsent, setTelemetryConsent] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const pref = await dsmClient.getPreference(DIAGNOSTICS_CONSENT_PREF_KEY);
        if (!cancelled) {
          setTelemetryConsent(pref === '1' || pref === 'true');
        }
      } catch {
        if (!cancelled) {
          setTelemetryConsent(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

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

  const updateTelemetryConsent = useCallback(async (next: boolean) => {
    setTelemetryConsent(next);
    try {
      await dsmClient.setPreference(DIAGNOSTICS_CONSENT_PREF_KEY, next ? '1' : '0');
    } catch {
      notifyToast('error', 'Failed to save diagnostics consent');
    }
  }, [notifyToast]);

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

  const buildDiagnosticsBundle = useCallback(async (): Promise<string> => {
    const summary = diagnostics ?? 'No diagnostics collected yet.';
    try {
      const telemetry = await import('../services/telemetry');
      const logBytes = await telemetry.exportDiagnosticsReport();
      const bridgeLog = logBytes.length > 0
        ? new TextDecoder().decode(logBytes)
        : 'No native bridge log captured.';
      return [summary, '', '--- Native Bridge Log ---', bridgeLog].join('\n');
    } catch {
      return summary;
    }
  }, [diagnostics]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const handleOpenDiagnostics = (event: Event) => {
      const detail = (event as CustomEvent<DiagnosticsOpenDetail | undefined>).detail;
      setShowDiagnostics(true);
      if (detail?.autoGather !== false) {
        void gatherDiagnostics();
      }
    };
    window.addEventListener(OPEN_DIAGNOSTICS_EVENT, handleOpenDiagnostics as EventListener);
    return () => {
      window.removeEventListener(OPEN_DIAGNOSTICS_EVENT, handleOpenDiagnostics as EventListener);
    };
  }, [gatherDiagnostics]);

  const openGitHubIssue = useCallback(() => {
    void (async () => {
      try {
        const title = `Beta bug: ${envConfigError ? envConfigError.substring(0, 80) : 'diagnostics report'}`;
        const excerpt = telemetryConsent
          ? (await buildDiagnosticsBundle()).substring(0, 2200)
          : '';
        const diagnosticsSection = telemetryConsent
          ? `**Diagnostics excerpt**\n\n----BEGIN EXCERPT----\n${excerpt}\n----END EXCERPT----\n\n`
          : `**Diagnostics**\n\nAttach the downloaded \`dsm-diagnostics.txt\` file if you are comfortable sharing it.\n\n`;
        const body = `**Describe the problem**\n\nPlease describe the beta issue.\n\n${diagnosticsSection}**Steps to reproduce**\n1. Launch the app\n2. Reproduce the issue\n3. Note the exact screen, flow, and expected result\n\n**Additional info**\n- Attach adb logcat output if available\n`;
        const url = buildGitHubIssueUrl({ title, body, template: BETA_BUG_TEMPLATE });
        const popup = window.open(url, '_blank', 'noopener');
        if (!popup && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(url);
          notifyToast('success', 'Bug report link copied to clipboard');
          return;
        }
        if (!popup) {
          throw new Error('Popup blocked and clipboard unavailable.');
        }
        notifyToast('success', 'Beta bug report opened');
      } catch {
        try {
          const defaultUrl = buildGitHubIssueUrl({ template: BETA_BUG_TEMPLATE });
          const popup = window.open(defaultUrl, '_blank', 'noopener');
          if (!popup && navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(defaultUrl);
            notifyToast('success', 'Bug report link copied to clipboard');
            return;
          }
          if (!popup) {
            throw new Error('Popup blocked and clipboard unavailable.');
          }
          notifyToast('success', 'Beta bug report opened');
        } catch (_e) {
          notifyToast('error', 'Failed to open GitHub');
        }
      }
    })();
  }, [buildDiagnosticsBundle, envConfigError, notifyToast, telemetryConsent]);

  const openGitHubFeedback = useCallback(() => {
    void (async () => {
      try {
        const body = telemetryConsent && diagnostics
          ? `**Feedback**\n\nPlease share your beta feedback.\n\n**Optional diagnostics excerpt**\n\n${(await buildDiagnosticsBundle()).substring(0, 1200)}`
          : '**Feedback**\n\nPlease share your beta feedback.';
        const url = buildGitHubIssueUrl({
          template: BETA_FEEDBACK_TEMPLATE,
          title: 'Beta feedback',
          body,
        });
        const popup = window.open(url, '_blank', 'noopener');
        if (!popup && navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(url);
          notifyToast('success', 'Feedback link copied to clipboard');
          return;
        }
        if (!popup) {
          throw new Error('Popup blocked and clipboard unavailable.');
        }
        notifyToast('success', 'Beta feedback form opened');
      } catch {
        notifyToast('error', 'Failed to open feedback form');
      }
    })();
  }, [buildDiagnosticsBundle, diagnostics, notifyToast, telemetryConsent]);

  const sendDiagnosticsTelemetry = useCallback(async () => {
    if (!diagnostics) return;
    try {
      const t = await import('../services/telemetry');
      await t.sendDiagnostics(diagnostics, telemetryConsent);
      notifyToast('success', 'Diagnostics saved to local log');
    } catch (e) {
      notifyToast('error', `Failed to save diagnostics: ${String(e)}`);
    }
  }, [diagnostics, notifyToast, telemetryConsent]);

  const copyDiagnostics = useCallback(async () => {
    if (!diagnostics) return;
    try {
      await navigator.clipboard.writeText(await buildDiagnosticsBundle());
      notifyToast('success', 'Diagnostics copied to clipboard');
    } catch (e) {
      notifyToast('error', 'Copy failed');
      console.warn('Failed to copy diagnostics:', e);
    }
  }, [buildDiagnosticsBundle, diagnostics, notifyToast]);

  const downloadDiagnostics = useCallback(() => {
    if (!diagnostics) return;
    void (async () => {
      const bundle = await buildDiagnosticsBundle();
      const blob = new Blob([bundle], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'dsm-diagnostics.txt';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      notifyToast('success', 'Diagnostics downloaded');
    })();
  }, [buildDiagnosticsBundle, diagnostics, notifyToast]);

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
    setTelemetryConsent: updateTelemetryConsent,
    gatherDiagnostics,
    openGitHubIssue,
    openGitHubFeedback,
    sendDiagnosticsTelemetry,
    copyDiagnostics,
    downloadDiagnostics,
    lastBridgeError,
  };
}
