// SPDX-License-Identifier: Apache-2.0
// Diagnostics: a report of what was measured — Rust's identity, the native
// session phase, the architecture check as the native side answered it (or
// its failure as it happened), and the last errors this session saw.

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

export type BridgeErrorRecord = { code: number; message: string; debugB32?: string };

type DiagnosticsState = {
  envConfigError: string | null;
  envConfigHelp: string | null;
  showDiagnostics: boolean;
  diagLoading: boolean;
  diagnostics: string | null;
  telemetryConsent: boolean;
  lastBridgeError: BridgeErrorRecord | null;
};

const DIAGNOSTICS_CONSENT_PREF_KEY = 'diagnostics_consent';
const OPEN_DIAGNOSTICS_EVENT = 'dsm-open-diagnostics';

type DiagnosticsOpenDetail = {
  autoGather?: boolean;
};

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function useDiagnostics(notifyToast: NotifyToast) {
  const [envConfigError, setEnvConfigError] = useState<string | null>(null);
  const [envConfigHelp, setEnvConfigHelp] = useState<string | null>(null);
  const [lastBridgeError, setLastBridgeError] = useState<BridgeErrorRecord | null>(null);
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
    const envHandler = (detail: { message?: string; help?: string }) => {
      const msg = detail?.message || 'Environment configuration error';
      console.warn('[Diagnostics] env.config.error received:', msg, detail);
      setEnvConfigError(String(msg));
      setEnvConfigHelp(detail?.help || null);
    };
    const bridgeErrHandler = (detail: { code?: number; message?: string; debugB32?: string }) => {
      console.warn('[Diagnostics] bridge.error received:', detail?.message, detail?.debugB32 ? 'debug present' : 'no debug');
      setLastBridgeError({ code: detail?.code ?? 0, message: detail?.message ?? '', debugB32: detail?.debugB32 });
    };
    const offEnv = bridgeEvents.on('env.config.error', envHandler as never);
    const offBridge = bridgeEvents.on('bridge.error', bridgeErrHandler as never);
    return () => { offEnv(); offBridge(); };
  }, []);

  const clearBridgeError = useCallback(() => setLastBridgeError(null), []);

  const updateTelemetryConsent = useCallback(async (next: boolean) => {
    setTelemetryConsent(next);
    try {
      await dsmClient.setPreference(DIAGNOSTICS_CONSENT_PREF_KEY, next ? '1' : '0');
    } catch {
      notifyToast('error', 'Failed to save diagnostics consent');
    }
  }, [notifyToast]);

  // Every line states a measurement or names the failure of measuring it.
  const gatherDiagnostics = useCallback(async () => {
    setDiagLoading(true);
    setDiagnostics(null);
    try {
      const wb = await import('../dsm/WebViewBridge');

      const session = nativeSessionStore.getSnapshot();
      const sessionLine = `session=${session.received ? session.phase : 'pending'}`;

      let identityLine: string;
      try {
        const id = await dsmClient.getIdentity();
        identityLine = id
          ? `identity=device ${id.deviceId} genesis ${id.genesisHash}`
          : 'identity=none (getIdentity answered null)';
      } catch (e) {
        identityLine = `identity=not read: ${messageOf(e)}`;
      }

      let archLine: string;
      try {
        const arch = await wb.getArchitectureInfo();
        archLine = `arch=${arch.status} device=${arch.deviceArch} abis=${arch.supportedAbis} message=${arch.message} recommendation=${arch.recommendation}`;
      } catch (e) {
        archLine = `arch=not measured: ${messageOf(e)}`;
      }

      setDiagnostics([
        'DSM diagnostics',
        sessionLine,
        identityLine,
        archLine,
        `envConfigError=${envConfigError ?? ''}`,
        `lastBridgeError=${lastBridgeError ? `${lastBridgeError.code}:${lastBridgeError.message}` : ''}`,
        `bridgeErrorDebugB32=${lastBridgeError?.debugB32 ?? ''}`,
      ].join('\n'));
      setShowDiagnostics(true);
    } catch (e) {
      setDiagnostics(`Failed to gather diagnostics: ${messageOf(e)}`);
      setShowDiagnostics(true);
    } finally {
      setDiagLoading(false);
    }
  }, [envConfigError, lastBridgeError]);

  // The report plus the native bridge log, or the reason the log was not read.
  const buildDiagnosticsBundle = useCallback(async (): Promise<string> => {
    const summary = diagnostics ?? 'No diagnostics collected yet.';
    let bridgeLog: string;
    try {
      const wb = await import('../dsm/WebViewBridge');
      const logBytes = await wb.getDiagnosticsLog();
      bridgeLog = logBytes.length > 0 ? new TextDecoder().decode(logBytes) : 'empty';
    } catch (e) {
      bridgeLog = `not read: ${messageOf(e)}`;
    }
    return [summary, '', '--- Native Bridge Log ---', bridgeLog].join('\n');
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

  const openUrlOrCopy = useCallback(async (url: string, opened: string, copied: string) => {
    const popup = window.open(url, '_blank', 'noopener');
    if (popup) {
      notifyToast('success', opened);
      return;
    }
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(url);
      notifyToast('success', copied);
      return;
    }
    throw new Error('Popup blocked and clipboard unavailable.');
  }, [notifyToast]);

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
        await openUrlOrCopy(url, 'Beta bug report opened', 'Bug report link copied to clipboard');
      } catch {
        try {
          const defaultUrl = buildGitHubIssueUrl({ template: BETA_BUG_TEMPLATE });
          await openUrlOrCopy(defaultUrl, 'Beta bug report opened', 'Bug report link copied to clipboard');
        } catch {
          notifyToast('error', 'Failed to open GitHub');
        }
      }
    })();
  }, [buildDiagnosticsBundle, envConfigError, notifyToast, openUrlOrCopy, telemetryConsent]);

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
        await openUrlOrCopy(url, 'Beta feedback form opened', 'Feedback link copied to clipboard');
      } catch {
        notifyToast('error', 'Failed to open feedback form');
      }
    })();
  }, [buildDiagnosticsBundle, diagnostics, notifyToast, openUrlOrCopy, telemetryConsent]);

  const sendDiagnosticsTelemetry = useCallback(async () => {
    if (!diagnostics) return;
    try {
      const t = await import('../services/telemetry');
      await t.sendDiagnostics(diagnostics, telemetryConsent);
      notifyToast('success', 'Diagnostics saved to local log');
    } catch (e) {
      notifyToast('error', `Failed to save diagnostics: ${messageOf(e)}`);
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
    envConfigHelp,
    showDiagnostics,
    diagLoading,
    diagnostics,
    telemetryConsent,
    lastBridgeError,
  };

  return {
    ...state,
    setEnvConfigError,
    setShowDiagnostics,
    setTelemetryConsent: updateTelemetryConsent,
    clearBridgeError,
    gatherDiagnostics,
    openGitHubIssue,
    openGitHubFeedback,
    sendDiagnosticsTelemetry,
    copyDiagnostics,
    downloadDiagnostics,
  };
}
