/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
/**
 * DSM App Entry Point - Production Ready
 */

import React from 'react';
import { createRoot, type Root } from 'react-dom/client';
import App from './App';
import { bridgeSessionStore } from './runtime/bridgeSessionStore';
import { initializeNativeBridgeAdapter } from './bridge/nativeBridgeAdapter';
import { nativeSessionStore } from './runtime/nativeSessionStore';
import logger from './utils/logger';
import { runExternalCommitV2VectorsAndLog, runUiVectorsAndLog, runVectorsV1 } from './vectors';

// Initialize native -> web event bridge early (before app mounts)
initializeNativeBridgeAdapter();

// Pending bilateral sync is handled by the native-backed store listener.

  declare global {
    interface Window {
      __APP_BOOTED__?: boolean;
      __DSM_ROOT__?: Root;
      runVectorsV1?: (baseUrl?: string) => Promise<void>;
    }
  }/** Boot the React app exactly once, after the DOM is ready. */
function bootApp(): void {
  // Expose vector harness for developer console usage
  window.runVectorsV1 = runVectorsV1;

  // AUTO-RUN VECTORS: Only when debug flag is present (URL param or global).
  // To enable: add ?dsm_debug_vectors to URL or set window.__DSM_DEBUG_VECTORS__ = true
  const shouldRunVectors =
    new URLSearchParams(window.location.search).has('dsm_debug_vectors') ||
    (window as any).__DSM_DEBUG_VECTORS__;

  if (shouldRunVectors) {
    logger.info('[DSM] Debug vectors enabled. Starting vector harness after genesis completes...');

    let harnessStarted = false;
    let attempts = 0;
    const maxAttempts = 30;
    const checkInterval = setInterval(async () => {
      attempts++;

      try {
        const snapshot = nativeSessionStore.getSnapshot();
        const hasIdentity = snapshot.identity_status === 'ready';

        if (hasIdentity) {
          clearInterval(checkInterval);

          if (harnessStarted) {
            logger.info('[DSM] Identity ready but harness already started. Skipping.');
            return;
          }
          harnessStarted = true;

          logger.info(`[DSM] Identity exists after ${attempts} checks. AppRouter should be ready.`);

          setTimeout(() => {
            const isAndroidWebView =
              window.location.protocol === 'https:' &&
              window.location.hostname === 'appassets.androidplatform.net';
            const vectorBaseUrl = isAndroidWebView ? '/assets/vectors/v1' : '/vectors/v1';

            logger.info(`[DSM] Auto-starting Vector Harness from ${vectorBaseUrl}...`);
            runVectorsV1(vectorBaseUrl)
              .then(() => {
                logger.info('[DSM] Vector Harness Finished.');
                return runExternalCommitV2VectorsAndLog();
              })
              .then(() => {
                logger.info('[DSM] ExternalCommit v2 vectors finished.');
                return runUiVectorsAndLog();
              })
              .then(() => logger.info('[DSM] UI vectors finished.'))
              .catch((e) => logger.error('[DSM] Vector Harness Failed:', e));
          }, 1000);
        } else if (attempts >= maxAttempts) {
          clearInterval(checkInterval);
          logger.error(`[DSM] Identity not created after ${maxAttempts} attempts. Skipping vector harness.`);
        } else {
          logger.info(`[DSM] Waiting for identity creation (attempt ${attempts}/${maxAttempts})...`);
        }
      } catch (e) {
        logger.warn(`[DSM] Error checking identity (attempt ${attempts}):`, e);
      }
    }, 1000);
  }

  const container = document.getElementById('dsm-app-root');
  if (!container) {
    // If DOM not ready yet, retry once it is.
    if (document.readyState === 'loading') {
      window.addEventListener('DOMContentLoaded', bootApp, { once: true });
      return;
    }
    throw new Error('DSM app root element not found');
  }

  if (window.__APP_BOOTED__) return;

  const root = window.__DSM_ROOT__ ?? createRoot(container);
  window.__DSM_ROOT__ = root;

  // Single ErrorBoundary lives inside App.tsx - do NOT double-wrap here
  // Double ErrorBoundary masks where exceptions actually occur
  root.render(<App />);

  // Signal to native bridge that JS side is fully mounted and listeners are in place.
  try {
    // Some platforms expose DsmBridge on window; guard for absence.
    const b: any = (window as any).DsmBridge;
    // New hardening: require a per-load session handshake before jsReady().
    if (b?.beginSession && b?.confirmSession) {
      const token = b.beginSession();
      const ok = b.confirmSession(token);
      if (!ok) {
        bridgeSessionStore.markSessionError('DsmBridge session confirmation failed');
        logger.warn('DsmBridge session confirmation failed');
        return;
      }
      bridgeSessionStore.markSessionConfirmed();
    }
    b?.jsReady?.();
  } catch (e) {
    // Non-fatal: log to console only.
    bridgeSessionStore.markSessionError(e instanceof Error ? e.message : String(e));
    console.warn('DsmBridge.jsReady() call failed:', e);
  }

  window.__APP_BOOTED__ = true;
}

bootApp();

/** Register Service Worker for offline support (tiles + app shell) */
(function registerServiceWorker() {
  // Skip in Android WebView (appassets.androidplatform.net doesn't support SW)
  const isAndroidWebView =
    window.location.protocol === 'https:' &&
    window.location.hostname === 'appassets.androidplatform.net';

  const isLocalhost =
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1' ||
    window.location.hostname.endsWith('.local');

  const httpsOrLocal = window.location.protocol === 'https:' || isLocalhost;

  if (!('serviceWorker' in navigator)) return;
  if (isAndroidWebView) return;
  if (!httpsOrLocal) return;

  const swUrl = new URL('/service-worker.js', window.location.origin).toString();

  // Defer to onload to avoid competing with critical path
  window.addEventListener(
    'load',
    () => {
      navigator.serviceWorker
        .register(swUrl)
        .catch((err) => console.warn('ServiceWorker registration failed:', err));
    },
    { once: true }
  );
})();
