/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Reusable D-pad navigation hook for sub-screens.
// Manages a focused index over a flat list of interactive items.
// Intercepts arrow keys + A button in capture phase so the app-level
// useKeyboardBindings handler doesn't fire for navigation keys.
// B button (back/Escape) is NOT intercepted — app-level back always works.

import { useState, useEffect, useCallback, useRef } from 'react';

interface UseDpadNavOptions {
  /** Number of navigable items on screen */
  itemCount: number;
  /** Called when A button / Enter is pressed on the focused item */
  onSelect?: (index: number) => void;
  /** Starting index (default 0) */
  initialIndex?: number;
}

interface UseDpadNavResult {
  /** Currently focused item index */
  focusedIndex: number;
  /** Override focused index (e.g. when items change) */
  setFocusedIndex: React.Dispatch<React.SetStateAction<number>>;
}

export function useDpadNav({
  itemCount,
  onSelect,
  initialIndex = 0,
}: UseDpadNavOptions): UseDpadNavResult {
  const [focusedIndexRaw, setFocusedIndex] = useState(initialIndex);
  const onSelectRef = useRef(onSelect);

  useEffect(() => {
    onSelectRef.current = onSelect;
  }, [onSelect]);

  const focusedIndex = itemCount <= 0 ? 0 : Math.min(focusedIndexRaw, itemCount - 1);

  // Set global flag so app-level useKeyboardBindings defers to us
  useEffect(() => {
    (window as any).__dsmScreenNavActive = true;
    return () => {
      (window as any).__dsmScreenNavActive = false;
    };
  }, []);

  // Stable nav callbacks
  const prev = useCallback(() => {
    if (itemCount <= 0) return;
    setFocusedIndex((i) => {
      const current = Math.min(i, itemCount - 1);
      return current > 0 ? current - 1 : itemCount - 1;
    });
  }, [itemCount]);

  const next = useCallback(() => {
    if (itemCount <= 0) return;
    setFocusedIndex((i) => {
      const current = Math.min(i, itemCount - 1);
      return current < itemCount - 1 ? current + 1 : 0;
    });
  }, [itemCount]);

  const select = useCallback(() => {
    // Respect combo entry suppression (same pattern as useKeyboardBindings)
    if ((window as any).__dsmComboEntryActive) return;
    onSelectRef.current?.(focusedIndex);
  }, [focusedIndex]);

  // Capture-phase keydown on document — fires before the app-level bubble-phase listener
  useEffect(() => {
    if (typeof document === 'undefined') return;

    const handleKeyDown = (e: KeyboardEvent) => {
      // When combo entry is active, don't intercept keys — StateboyComboInput handles them
      if ((window as any).__dsmComboEntryActive) return;
      switch (e.key) {
        case 'ArrowUp':
        case 'ArrowLeft':
          e.preventDefault();
          e.stopImmediatePropagation();
          prev();
          break;
        case 'ArrowDown':
        case 'ArrowRight':
          e.preventDefault();
          e.stopImmediatePropagation();
          next();
          break;
        case 'Enter':
        case ' ':
          e.preventDefault();
          e.stopImmediatePropagation();
          select();
          break;
        // Escape is NOT intercepted — app-level back handler works
      }
    };

    document.addEventListener('keydown', handleKeyDown, true); // capture phase

    return () => {
      document.removeEventListener('keydown', handleKeyDown, true);
    };
  }, [prev, next, select]);

  // Capture-phase click listeners on physical D-pad buttons
  useEffect(() => {
    if (typeof document === 'undefined') return;

    const stopAndCall = (fn: () => void) => (e: Event) => {
      // When combo entry is active, don't intercept — let sb-btn event fire
      if ((window as any).__dsmComboEntryActive) return;
      e.stopImmediatePropagation();
      fn();
    };

    const handlers: Array<[Element, (e: Event) => void]> = [];

    const bind = (sel: string, fn: () => void) => {
      const el = document.querySelector(sel);
      if (!el) return;
      const handler = stopAndCall(fn);
      el.addEventListener('click', handler, true); // capture phase
      handlers.push([el, handler]);
    };

    bind('.dpad-up', prev);
    bind('.dpad-down', next);
    bind('.dpad-left', prev);
    bind('.dpad-right', next);
    bind('#dpad-up', prev);
    bind('#dpad-down', next);
    bind('#dpad-left', prev);
    bind('#dpad-right', next);

    bind('.button-a', select);
    bind('#button-a', select);
    // NOTE: B button (.button-b / #button-b) is NOT intercepted — app-level back works

    return () => {
      // IMPORTANT: remove from the exact element instance we bound to.
      // If we re-query by selector after navigation, we might accidentally detach
      // the next screen's handlers (because the DOM nodes were replaced).
      for (const [el, handler] of handlers) {
        el.removeEventListener('click', handler, true);
      }
    };
  }, [prev, next, select]);

  return { focusedIndex, setFocusedIndex };
}
