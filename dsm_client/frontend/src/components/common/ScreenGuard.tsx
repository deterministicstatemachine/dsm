// SPDX-License-Identifier: Apache-2.0
// The guard a part of a screen needs while it is shown: placed inside a
// confirmation sheet or a phrase field, it holds the guard exactly as long as
// that part is rendered.

import { useScreenGuard } from '../../hooks/useScreenGuard';
import type { ScreenGuardKind } from '../../runtime/screenGuards';

export function ScreenGuard({ kind }: { kind: ScreenGuardKind }): null {
  useScreenGuard(kind);
  return null;
}
