// SPDX-License-Identifier: Apache-2.0
// The phone's status and navigation bars in the colours of the skin in use.

import { callBin } from "./transportCore";

export async function setSystemBars(scheme: "light" | "dark"): Promise<void> {
  await callBin("setSystemBars", new TextEncoder().encode(scheme));
}
