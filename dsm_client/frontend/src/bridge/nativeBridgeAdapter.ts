// path: src/bridge/nativeBridgeAdapter.ts
// SPDX-License-Identifier: Apache-2.0
// Installs the event bridge and turns the one DOM signal the app reacts to —
// visibility — into a bus event. Every native lifecycle topic reaches the bus
// from the event bridge directly; the DOM hops that used to sit between them
// (and the ones nothing ever dispatched) are gone.

import { initializeEventBridge } from '../dsm/EventBridge';
import { bridgeEvents } from './bridgeEvents';

let installed = false;

export function initializeNativeBridgeAdapter(): void {
  if (installed) return;
  installed = true;

  initializeEventBridge();

  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', () => {
      bridgeEvents.emit('visibility.change', { state: document.visibilityState });
    });
  }
}
