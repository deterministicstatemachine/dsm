// SPDX-License-Identifier: Apache-2.0
// What the phone's window guards while the page shows something that needs it
// (audit 2026-10-15, items 1 and 3):
//   secret   a recovery phrase is on screen or being typed: no screenshot,
//            recording or Recents thumbnail holds it, and the keyboard learns
//            nothing from what is typed;
//   confirm  an irreversible confirmation is on screen (a connect approval, a
//            send): other apps' overlay windows are hidden (Android 12+).
// A screen holds a guard while it is mounted, and the window holds every guard
// some screen holds. The phone is asked one request at a time, so the requests
// reach it in the order they were made.

import { setScreenGuards } from '../dsm/WebViewBridge/screenGuards';
import logger from '../utils/logger';

export type ScreenGuardKind = 'secret' | 'confirm';

const BITS: Record<ScreenGuardKind, number> = { secret: 1, confirm: 2 };

const holders: Record<ScreenGuardKind, number> = { secret: 0, confirm: 0 };

/** The guards last asked of the phone. A page that has just loaded asked for none. */
let asked = 0;
let phone: 'idle' | 'asking' = 'idle';

/** The guards the screens hold now, as the bits the phone reads. */
export function heldScreenGuards(): number {
  return (holders.secret > 0 ? BITS.secret : 0) | (holders.confirm > 0 ? BITS.confirm : 0);
}

function askPhone(): void {
  if (phone === 'asking') return;
  const wanted = heldScreenGuards();
  if (wanted === asked) return;
  phone = 'asking';
  asked = wanted;
  setScreenGuards(wanted)
    .then(
      () => undefined,
      (e: unknown) => logger.warn('[screen-guards] the phone did not take the guards:', e),
    )
    .finally(() => {
      phone = 'idle';
      askPhone();
    });
}

/** Holds `kind` until the answer is called; calling it again does nothing. */
export function holdScreenGuard(kind: ScreenGuardKind): () => void {
  holders[kind] += 1;
  askPhone();
  let held: 'held' | 'released' = 'held';
  return () => {
    if (held === 'released') return;
    held = 'released';
    holders[kind] -= 1;
    askPhone();
  };
}
