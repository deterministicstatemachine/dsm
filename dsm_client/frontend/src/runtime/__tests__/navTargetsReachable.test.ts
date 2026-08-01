// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every destination a production screen offers must actually be navigable.
//!
//! `VALID_NAV_TARGETS` is a runtime Set and `ScreenType` is a compile-time
//! union. They are not derived from one another, so a target can be a perfectly
//! valid `ScreenType`, be handled by `AppScreenRouter`, be wired to a visible
//! button — and still be dropped, because `navigate` returns silently when the
//! Set does not contain it.
//!
//! That is what happened to `'swap'`. The SoFi hub's SWAP brick was dead on a
//! real handset: the click fired, the handler ran, nothing moved, and no error
//! appeared anywhere. It was the trader's only route into the swap surface.

import { navigationStore } from '../navigationStore';
import type { ScreenType } from '../../types/app';

// The three destinations SofiHubScreen renders as bricks.
const SOFI_HUB_TARGETS: ScreenType[] = ['swap', 'liquidity', 'mail'];

describe('navigation targets offered by production screens', () => {
  it.each(SOFI_HUB_TARGETS)('the SoFi hub can actually reach %s', (target) => {
    navigationStore.navigate('home');
    navigationStore.navigate(target);
    expect(navigationStore.getSnapshot().currentScreen).toBe(target);
  });
});
