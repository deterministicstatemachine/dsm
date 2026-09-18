/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// Route the shell's physical buttons to whatever is open on top of the screen.
//
// B (and Escape) close: a sub-view, a form, a popup — so B closes that instead
// of leaving the screen. A (and Enter / Space) confirm the same thing, so the
// press that would otherwise reach the d-pad list behind a modal dismisses the
// modal instead.
//
// Active handlers form a stack per button: the innermost (most recently
// activated) one takes the press, so B on a popup inside the Deposit sub-view
// closes the popup and the next press closes the sub-view. Listeners are
// installed only while a stack is non-empty, so the app-level back keeps
// working everywhere else.
//
// B binds on `document` (capture), the same mechanism useDpadNav uses. A binds
// on `window` (capture), one hop earlier in the capture path, because
// useDpadNav's own document-level handler is registered first by the screen
// underneath and would otherwise take the press.
import { useEffect, useRef } from 'react';

type Entry = { current: () => void };

function top(stack: Entry[]): Entry | undefined {
  return stack[stack.length - 1];
}

function isTextEntry(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el || !el.tagName) return false;
  const tag = el.tagName.toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable === true;
}

// ---------------------------------------------------------------- B / back

const backStack: Entry[] = [];
let backInstalled = false;
let backButtons: Element[] = [];

function handleBackKey(e: KeyboardEvent): void {
  if ((window as any).__dsmComboEntryActive) return;
  if (e.key !== 'Escape') return;
  const entry = top(backStack);
  if (!entry) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  entry.current();
}

function handleBackClick(e: Event): void {
  if ((window as any).__dsmComboEntryActive) return;
  const entry = top(backStack);
  if (!entry) return;
  e.stopImmediatePropagation();
  entry.current();
}

function installBack(): void {
  if (backInstalled || typeof document === 'undefined') return;
  backInstalled = true;
  document.addEventListener('keydown', handleBackKey, true);
  backButtons = Array.from(document.querySelectorAll('#button-b, .button-b'));
  backButtons.forEach((el) => el.addEventListener('click', handleBackClick, true));
}

function uninstallBack(): void {
  if (!backInstalled) return;
  backInstalled = false;
  document.removeEventListener('keydown', handleBackKey, true);
  // Remove from the exact elements bound above; the DOM may have changed.
  backButtons.forEach((el) => el.removeEventListener('click', handleBackClick, true));
  backButtons = [];
}

// ------------------------------------------------------------- A / confirm

const confirmStack: Entry[] = [];
let confirmInstalled = false;

function handleConfirmKey(e: KeyboardEvent): void {
  if ((window as any).__dsmComboEntryActive) return;
  if (e.key !== 'Enter' && e.key !== ' ') return;
  if (isTextEntry(e.target)) return;
  const entry = top(confirmStack);
  if (!entry) return;
  e.preventDefault();
  e.stopPropagation();
  e.stopImmediatePropagation();
  entry.current();
}

function handleConfirmClick(e: Event): void {
  if ((window as any).__dsmComboEntryActive) return;
  const entry = top(confirmStack);
  if (!entry) return;
  const target = e.target as HTMLElement | null;
  if (!target || typeof target.closest !== 'function') return;
  if (!target.closest('#button-a, .button-a')) return;
  e.stopPropagation();
  e.stopImmediatePropagation();
  entry.current();
}

function installConfirm(): void {
  if (confirmInstalled || typeof window === 'undefined') return;
  confirmInstalled = true;
  window.addEventListener('keydown', handleConfirmKey, true);
  window.addEventListener('click', handleConfirmClick, true);
}

function uninstallConfirm(): void {
  if (!confirmInstalled) return;
  confirmInstalled = false;
  window.removeEventListener('keydown', handleConfirmKey, true);
  window.removeEventListener('click', handleConfirmClick, true);
}

function useShellButton(
  stack: Entry[],
  install: () => void,
  uninstall: () => void,
  active: boolean,
  onPress: () => void,
): void {
  const entry = useRef<Entry>({ current: onPress });
  entry.current.current = onPress;

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
  }, [active, stack, install, uninstall]);
}

/** While `active`, the shell's B button (and Escape) run `onBack`. */
export function useBackButton(active: boolean, onBack: () => void): void {
  useShellButton(backStack, installBack, uninstallBack, active, onBack);
}

/**
 * While `active`, the shell's A button (and Enter / Space) run `onConfirm`
 * instead of reaching the list behind an open popup.
 */
export function useConfirmButton(active: boolean, onConfirm: () => void): void {
  useShellButton(confirmStack, installConfirm, uninstallConfirm, active, onConfirm);
}
