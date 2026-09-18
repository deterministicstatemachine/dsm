/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Route the shell's B button (and Escape) to a screen-local "back" while
// something is open on top of the screen — a sub-view, a form, a popup — so B
// closes that instead of leaving the screen.
//
// Active handlers form a stack: the innermost (most recently activated) one
// takes the press, so B on a popup inside the Deposit sub-view closes the popup
// and the next press closes the sub-view. The shell listeners are installed
// only while the stack is non-empty, so the app-level back keeps working
// everywhere else. Same capture-phase mechanism useDpadNav uses for A.
import { useEffect, useRef } from 'react';

type Entry = { current: () => void };

const stack: Entry[] = [];
let installed = false;
let boundButtons: Element[] = [];

function top(): Entry | undefined {
  return stack[stack.length - 1];
}

function handleKey(e: KeyboardEvent): void {
  if ((window as any).__dsmComboEntryActive) return;
  if (e.key !== 'Escape') return;
  const entry = top();
  if (!entry) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  entry.current();
}

function handleClick(e: Event): void {
  if ((window as any).__dsmComboEntryActive) return;
  const entry = top();
  if (!entry) return;
  e.stopImmediatePropagation();
  entry.current();
}

function install(): void {
  if (installed || typeof document === 'undefined') return;
  installed = true;
  document.addEventListener('keydown', handleKey, true);
  boundButtons = Array.from(document.querySelectorAll('#button-b, .button-b'));
  boundButtons.forEach((el) => el.addEventListener('click', handleClick, true));
}

function uninstall(): void {
  if (!installed) return;
  installed = false;
  document.removeEventListener('keydown', handleKey, true);
  // Remove from the exact elements bound above; the DOM may have changed.
  boundButtons.forEach((el) => el.removeEventListener('click', handleClick, true));
  boundButtons = [];
}

export function useBackButton(active: boolean, onBack: () => void): void {
  const entry = useRef<Entry>({ current: onBack });
  entry.current.current = onBack;

  useEffect(() => {
    if (!active) return;
    const mine = entry.current;
    stack.push(mine);
    install();
    return () => {
      const i = stack.lastIndexOf(mine);
      if (i >= 0) stack.splice(i, 1);
      if (stack.length === 0) uninstall();
    };
  }, [active]);
}
