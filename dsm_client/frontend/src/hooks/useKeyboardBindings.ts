/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useEffect } from 'react';

type Intents = {
  prevItem: () => void;
  nextItem: () => void;
  select: () => void;
  back: () => void;
  toggleTheme?: () => void;
  start?: () => void;
};

export function useKeyboardBindings(intents: Intents): void {
  useEffect(() => {
    if (typeof document === 'undefined') return;

    const handleKeyDown = (e: KeyboardEvent) => {
      // When a sub-screen has its own D-pad nav active, defer arrow/select keys to it.
      // The screen's capture-phase handler already handled these.
      const screenNav = !!(window as any).__dsmScreenNavActive;

      switch (e.key) {
        case 'ArrowUp':
          if (screenNav) return;
          e.preventDefault();
          intents.prevItem();
          break;
        case 'ArrowDown':
          if (screenNav) return;
          e.preventDefault();
          intents.nextItem();
          break;
        case 'ArrowLeft':
          if (screenNav) return;
          e.preventDefault();
          intents.prevItem();
          break;
        case 'ArrowRight':
          if (screenNav) return;
          e.preventDefault();
          intents.nextItem();
          break;
        case 'Enter':
        case ' ':
          if (screenNav) return;
          e.preventDefault();
          if (!(window as any).__dsmComboEntryActive) intents.select();
          break;
        case 'Escape':
          e.preventDefault();
          if (!(window as any).__dsmComboEntryActive) intents.back();
          break;
        case 'Tab':
          e.preventDefault();
          intents.toggleTheme?.();
          break;
        case 'Shift':
          e.preventDefault();
          intents.start?.();
          break;
      }
    };

    const add = (sel: string, fn: () => void) => document.querySelector(sel)?.addEventListener('click', fn);
    const remove = (sel: string, fn: () => void) => document.querySelector(sel)?.removeEventListener('click', fn);

    add('#dpad-up', intents.prevItem);
    add('#dpad-down', intents.nextItem);
    add('#dpad-left', intents.prevItem);
    add('#dpad-right', intents.nextItem);

    add('.dpad-up', intents.prevItem);
    add('.dpad-down', intents.nextItem);
    add('.dpad-left', intents.prevItem);
    add('.dpad-right', intents.nextItem);

    add('#button-a', intents.select);
    add('#button-b', intents.back);
    add('.button-a', intents.select);
    add('.button-b', intents.back);

    add('#button-select', intents.toggleTheme ?? (() => {}));
    add('#button-start', intents.start ?? (() => {}));
    add('.button-select', intents.toggleTheme ?? (() => {}));
    add('.button-start', intents.start ?? (() => {}));

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      remove('#dpad-up', intents.prevItem);
      remove('#dpad-down', intents.nextItem);
      remove('#dpad-left', intents.prevItem);
      remove('#dpad-right', intents.nextItem);

      remove('.dpad-up', intents.prevItem);
      remove('.dpad-down', intents.nextItem);
      remove('.dpad-left', intents.prevItem);
      remove('.dpad-right', intents.nextItem);

      remove('#button-a', intents.select);
      remove('#button-b', intents.back);
      remove('.button-a', intents.select);
      remove('.button-b', intents.back);

      remove('#button-select', intents.toggleTheme ?? (() => {}));
      remove('#button-start', intents.start ?? (() => {}));
      remove('.button-select', intents.toggleTheme ?? (() => {}));
      remove('.button-start', intents.start ?? (() => {}));

      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [intents]);
}
