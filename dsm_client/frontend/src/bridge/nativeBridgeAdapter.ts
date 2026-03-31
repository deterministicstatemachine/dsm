/* eslint-disable @typescript-eslint/no-explicit-any */
// path: src/bridge/nativeBridgeAdapter.ts
// SPDX-License-Identifier: Apache-2.0

import { initializeEventBridge } from '../dsm/EventBridge';
import { DSM_WALLET_REFRESH_EVENT } from '../dsm/events';
import { bridgeEvents } from './bridgeEvents';

let installed = false;

export function initializeNativeBridgeAdapter(): void {
  if (installed) return;
  installed = true;

  initializeEventBridge();

  if (typeof document !== 'undefined') {
    document.addEventListener('dsm-identity-ready', () => {
      bridgeEvents.emit('identity.ready', undefined as any);
    });

    document.addEventListener('dsm-env-config-error', (evt: any) => {
      const msg = String(evt?.detail?.message || 'Environment configuration error');
      bridgeEvents.emit('env.config.error', { message: msg });
    });

    document.addEventListener('DSM_PORT_TX', () => bridgeEvents.emit('port.tx', undefined as any));
    document.addEventListener('DSM_PORT_RX', () => bridgeEvents.emit('port.rx', undefined as any));
    document.addEventListener('DSM_UI_TICK', () => bridgeEvents.emit('ui.tick', undefined as any));

    document.addEventListener('visibilitychange', () => {
      bridgeEvents.emit('visibility.change', { state: document.visibilityState });
    });
  }

  if (typeof window !== 'undefined') {
    window.addEventListener('dsm-bilateral-committed', (evt: any) => {
      bridgeEvents.emit('wallet.bilateralCommitted', evt?.detail ?? {});
    });

    window.addEventListener(DSM_WALLET_REFRESH_EVENT, (evt: any) => {
      const detail = evt?.detail ?? { source: 'unknown' };
      bridgeEvents.emit('wallet.refresh', detail);
    });

    window.addEventListener('dsm-history-updated', () => {
      bridgeEvents.emit('wallet.historyUpdated', undefined as any);
    });

    window.addEventListener('dsm-balances-updated', () => {
      bridgeEvents.emit('wallet.balancesUpdated', undefined as any);
    });

    window.addEventListener('dsm-wallet-send-committed', (evt: any) => {
      bridgeEvents.emit('wallet.sendCommitted', evt?.detail ?? {});
    });

    window.addEventListener('dsm-contact-added', (evt: any) => {
      bridgeEvents.emit('contact.added', evt?.detail ?? {});
    });

  }
}
