// SPDX-License-Identifier: Apache-2.0

import { navigationStore } from '../navigationStore';
import { SCREEN_TYPES, type ScreenType } from '../../types/app';

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

  // Every screen the app has is navigable: the targets navigation accepts
  // and the screens `ScreenType` names come from the one list, so this walks
  // all of them. (A hand-kept copy here once omitted 'sofi' exactly as the
  // store's own allowlist did, and the TRADE brick went dead with both green.)
  const navigableScreens: ScreenType[] = SCREEN_TYPES.filter((s) => s !== 'home');

  it.each(navigableScreens)(
    'navigate(%s) advances currentScreen (not silently dropped by allowlist)',
    (target) => {
      navigationStore.navigate(target);
      expect(navigationStore.getSnapshot().currentScreen).toBe(target);
    },
  );
});

describe('the home screen\'s TRADE brick', () => {
  beforeEach(() => resetToHome());
  afterAll(() => resetToHome());

  it('opens the SoFi screen', () => {
    navigationStore.navigate('sofi');
    expect(navigationStore.getSnapshot().currentScreen).toBe('sofi');
  });

  it('refuses a target that is not a screen', () => {
    navigationStore.navigate('not-a-screen' as ScreenType);
    expect(navigationStore.getSnapshot().currentScreen).toBe('home');
  });
});
