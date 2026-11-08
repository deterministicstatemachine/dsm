// SPDX-License-Identifier: Apache-2.0
// A screen holds a phone-level guard (runtime/screenGuards.ts) for as long as
// it is mounted. Taken before the browser paints, so the guard is asked for
// with the screen's first frame rather than after it.

import { useLayoutEffect } from 'react';
import { holdScreenGuard, type ScreenGuardKind } from '../runtime/screenGuards';

export function useScreenGuard(kind: ScreenGuardKind): void {
  useLayoutEffect(() => holdScreenGuard(kind), [kind]);
}
