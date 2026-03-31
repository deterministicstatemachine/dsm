/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useEffect } from 'react';
import type { ScreenType } from '../types/app';
import { openBluetoothSettings } from '../dsm/WebViewBridge';

type Navigate = (to: ScreenType) => void;

type Options = {
  currentScreen: ScreenType;
  navigate: Navigate;
};

export function useBottomNav({ currentScreen, navigate }: Options): void {
  useEffect(() => {
    if (typeof document === 'undefined') return;

    const els = Array.from(document.querySelectorAll<HTMLDivElement>('.screen-nav-icon'));
    const onClick = (el: HTMLDivElement) => () => {
      const navKey = el.getAttribute('data-nav') as ScreenType | null;
      if (!navKey) return;
      if (navKey === 'wallet') {
        navigate('wallet');
        return;
      }
      if (navKey === 'bluetooth') {
        openBluetoothSettings().catch(e =>
          console.error('Failed to open Bluetooth settings:', e)
        );
        return;
      }
      if (navKey === 'qr') {
        navigate('contacts');
        return;
      }
      navigate(navKey);
    };

    els.forEach((el) => {
      const handler = onClick(el);
      el.addEventListener('click', handler);
      (el as any)._dsm_handler = handler;
    });

    return () => {
      els.forEach((el) => {
        const h = (el as any)._dsm_handler as (() => void) | undefined;
        if (h) el.removeEventListener('click', h);
        delete (el as any)._dsm_handler;
      });
    };
  }, [navigate]);

  useEffect(() => {
    if (typeof document === 'undefined') return;
    const els = Array.from(document.querySelectorAll<HTMLDivElement>('.screen-nav-icon'));
    const activeKey = currentScreen === 'vault' ? 'wallet' : currentScreen;
    els.forEach((el) => {
      const navKey = el.getAttribute('data-nav');
      el.classList.toggle('active', navKey === activeKey);
    });
  }, [currentScreen]);
}
