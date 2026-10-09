// SPDX-License-Identifier: Apache-2.0
// Reads the skin preferences once the bridge is up, and dresses the page for
// the skin in use: `data-skin` and `data-scheme` on <html> select the Simple
// skin's styles (styles/simple.css), which put the Game Boy device away and
// let the app fill the screen. The choice is the app's, made before anything
// else, so every screen from the first is in it.

import { useEffect, useLayoutEffect, useRef } from 'react';
import { loadSkinPreferences, readSkinHint } from '../runtime/skinPreferences';
import { appRuntimeStore, type Scheme, type Skin } from '../runtime/appRuntimeStore';
import type { AppState } from '../types/app';
import type { NativeSessionLockStatus } from '../runtime/nativeSessionTypes';
import { setSystemBars } from '../dsm/WebViewBridge/systemBars';
import logger from '../utils/logger';

/**
 * The skin the page is drawn in now. Simple in every phase once it is the
 * choice, except a wallet locked with a button combo: the combo is entered on
 * the Game Boy's buttons, so its lock screen shows the device.
 */
export function skinInUse(skin: Skin | null, appState: AppState, lockMethod: NativeSessionLockStatus['method']): Skin {
  if (skin !== 'simple') return 'classic';
  if (appState === 'locked' && lockMethod === 'combo') return 'classic';
  return 'simple';
}

export function useSkin(
  bridgeUp: boolean,
  skin: Skin | null,
  scheme: Scheme,
  appState: AppState,
  lockMethod: NativeSessionLockStatus['method'],
): Skin {
  // The first paint is in the look the page last drew; the preference, read
  // below, is the authority.
  useLayoutEffect(() => {
    const hint = readSkinHint();
    if (hint !== null && appRuntimeStore.getSnapshot().skin === null) appRuntimeStore.setSkin(hint);
  }, []);

  useEffect(() => {
    if (!bridgeUp) return;
    loadSkinPreferences().then(
      () => undefined,
      (e: unknown) => logger.warn('[skin] the preferences were not read:', e),
    );
  }, [bridgeUp]);

  const inUse = skinInUse(skin, appState, lockMethod);
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
