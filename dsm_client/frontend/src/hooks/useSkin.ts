// SPDX-License-Identifier: Apache-2.0
// Reads the skin preferences once the identity is ready, and dresses the page
// for the skin in use: `data-skin` and `data-scheme` on <html> select the
// Simple skin's styles (public/index.html, styles/simple.css), which put the
// Game Boy device away and let the app fill the screen.

import { useEffect, useRef } from 'react';
import { clearSkinPreferences, loadSkinPreferences } from '../runtime/skinPreferences';
import type { AppState } from '../types/app';
import type { Scheme, Skin } from '../runtime/appRuntimeStore';
import { setSystemBars } from '../dsm/WebViewBridge/systemBars';
import logger from '../utils/logger';

/** The skin the page is drawn in now: Simple only once the wallet is ready. */
export function skinInUse(skin: Skin | null, appState: AppState): Skin {
  return skin === 'simple' && appState === 'wallet_ready' ? 'simple' : 'classic';
}

export function useSkin(identityStatus: string, skin: Skin | null, scheme: Scheme, appState: AppState): Skin {
  useEffect(() => {
    if (identityStatus !== 'ready') {
      clearSkinPreferences();
      return;
    }
    loadSkinPreferences().then(
      () => undefined,
      (e: unknown) => logger.warn('[skin] the preferences were not read:', e),
    );
  }, [identityStatus]);

  const inUse = skinInUse(skin, appState);
  // The bars native set at start: dark, around the device.
  const bars = useRef<Scheme>('dark');

  useEffect(() => {
    const html = document.documentElement;
    html.setAttribute('data-skin', inUse);
    html.setAttribute('data-scheme', scheme);
    // The phone's status and navigation bars follow: dark around the device,
    // the scheme's own colour around the Simple skin. Asked only on a change.
    const wanted: Scheme = inUse === 'simple' ? scheme : 'dark';
    if (wanted === bars.current) return;
    bars.current = wanted;
    setSystemBars(wanted).then(
      () => undefined,
      (e: unknown) => logger.warn('[skin] the system bars were not set:', e),
    );
  }, [inUse, scheme]);

  return inUse;
}
