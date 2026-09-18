/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Route the shell's B button (and Escape) to a screen-local "back" while a
// sub-view is open, so B closes the sub-view instead of leaving the screen.
// Same capture-phase mechanism useDpadNav uses for A; nothing is intercepted
// while `active` is false, so the app-level back keeps working everywhere else.
import { useEffect, useRef } from 'react';

export function useBackButton(active: boolean, onBack: () => void): void {
  const onBackRef = useRef(onBack);
  onBackRef.current = onBack;

  useEffect(() => {
    if (!active || typeof document === 'undefined') return;

    const handleKey = (e: KeyboardEvent) => {
      if ((window as any).__dsmComboEntryActive) return;
      if (e.key !== 'Escape') return;
      e.preventDefault();
      e.stopImmediatePropagation();
      onBackRef.current();
    };
    const handleClick = (e: Event) => {
      if ((window as any).__dsmComboEntryActive) return;
      e.stopImmediatePropagation();
      onBackRef.current();
    };

    document.addEventListener('keydown', handleKey, true);
    const buttons = Array.from(document.querySelectorAll('#button-b, .button-b'));
    buttons.forEach((el) => el.addEventListener('click', handleClick, true));

    return () => {
      document.removeEventListener('keydown', handleKey, true);
      // Remove from the exact elements bound above; the DOM may have changed.
      buttons.forEach((el) => el.removeEventListener('click', handleClick, true));
    };
  }, [active]);
}
