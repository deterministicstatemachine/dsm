// SPDX-License-Identifier: Apache-2.0
// The guards the phone's window holds for what the page shows, as one byte of
// bits: 1 while a recovery phrase is on screen or being typed (no screenshot,
// recording or Recents thumbnail of it, and a keyboard that learns nothing from
// it), 2 while an irreversible confirmation is on screen (other apps' overlay
// windows hidden, Android 12+). runtime/screenGuards.ts decides the bits.

import { callBin } from "./transportCore";

export async function setScreenGuards(bits: number): Promise<void> {
  if (!Number.isInteger(bits) || bits < 0 || bits > 3) {
    throw new Error(`setScreenGuards: no guards have bits ${bits}`);
  }
  await callBin("setScreenGuards", Uint8Array.of(bits));
}
