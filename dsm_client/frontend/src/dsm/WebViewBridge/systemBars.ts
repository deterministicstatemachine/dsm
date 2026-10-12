// SPDX-License-Identifier: Apache-2.0
// The phone's status and navigation bars for what the page shows: `device` is
// the DGen Game Boy, edge to edge under dark bars; `light` and `dark` are the
// Modern skin (and the screens before a look is chosen), kept between the bars
// with the bars in the page's own colour.

import { callBin } from "./transportCore";

export type BarsLook = "light" | "dark" | "device";

export async function setSystemBars(look: BarsLook): Promise<void> {
  await callBin("setSystemBars", new TextEncoder().encode(look));
}
