// SPDX-License-Identifier: Apache-2.0

import { navigationStore } from '../navigationStore';
import type { ScreenType } from '../../types/app';

// Reset navigation state to 'home' between tests by walking back
// through history.  navigationStore is a module-level singleton so
// tests must clean up after themselves.
function resetToHome(): void {
  // Hard-reset by repeatedly going back until at home.
  for (let i = 0; i < 100; i++) {
    if (navigationStore.getSnapshot().currentScreen === 'home') return;
    navigationStore.goBack('wallet_ready');
  }
}

describe('navigationStore VALID_NAV_TARGETS coverage', () => {
  beforeEach(() => resetToHome());
  afterAll(() => resetToHome());

  // Every screen routed by AppScreenRouter that the user can reach
  // from a button/menu MUST be navigable.  Adding a screen anywhere
  // (ScreenType, AppScreenRouter, SettingsMainScreen) without also
  // adding it to VALID_NAV_TARGETS in navigationStore.ts causes a
  // silent navigation drop — the user clicks and nothing happens.
  //
  // This list is the source of truth; bump it when you add a new
  // navigable screen.
  const navigableScreens: ScreenType[] = [
    'wallet',
    'transactions',
    'contacts',
    'accounts',
    'storage',
    'settings',
    'tokens',
    'qr',
    'mycontact',
    'dev_dlv',
    'dev_cdbrw',
    'dev_policy',
    'dev_detfi_launch',
    'liquidity',
    'mail',
    'lock_setup',
    'recovery',
    'nfc_recovery',
    'recovery_pipeline',
    'vault',
    'bluetooth',
  ];

  it.each(navigableScreens)(
    'navigate(%s) advances currentScreen (not silently dropped by allowlist)',
    (target) => {
      navigationStore.navigate(target);
      expect(navigationStore.getSnapshot().currentScreen).toBe(target);
    },
  );
});
