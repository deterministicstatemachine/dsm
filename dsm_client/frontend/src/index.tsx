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
import logger from './utils/logger';

// Initialize native -> web event bridge early (before app mounts)
initializeNativeBridgeAdapter();

// Pending bilateral sync is handled by the native-backed store listener.

  declare global {
    interface Window {
      __APP_BOOTED__?: boolean;
      __DSM_ROOT__?: Root;
    }
  }/** Boot the React app exactly once, after the DOM is ready. */
function bootApp(): void {
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
