/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, act, fireEvent, createEvent } from '@testing-library/react';
import { useDpadNav } from '../useDpadNav';

type HookResult = ReturnType<typeof useDpadNav>;
let hookResult: HookResult;

function Harness(props: { itemCount: number; onSelect?: (i: number) => void; initialIndex?: number }) {
  hookResult = useDpadNav(props);
  return null;
}

describe('useDpadNav', () => {
  afterEach(() => {
    delete (window as any).__dsmScreenNavActive;
    delete (window as any).__dsmComboEntryActive;
  });

  it('initializes focused index to 0 by default', () => {
    render(<Harness itemCount={5} />);
    expect(hookResult.focusedIndex).toBe(0);
  });

  it('initializes focused index to initialIndex', () => {
    render(<Harness itemCount={5} initialIndex={3} />);
    expect(hookResult.focusedIndex).toBe(3);
  });

  it('sets __dsmScreenNavActive on mount and clears on unmount', () => {
    const { unmount } = render(<Harness itemCount={3} />);
    expect((window as any).__dsmScreenNavActive).toBe(true);
    unmount();
    expect((window as any).__dsmScreenNavActive).toBe(false);
  });

  describe('a key typed into a field', () => {
    function FieldHarness(props: { pressed: number[] }) {
      hookResult = useDpadNav({ itemCount: 3, onSelect: (i) => props.pressed.push(i) });
      return (
        <>
          <input aria-label="name" />
          <textarea aria-label="note" />
        </>
      );
    }

    function pressKey(target: Element, key: string): KeyboardEvent {
      const event = createEvent.keyDown(target, { key }) as KeyboardEvent;
      fireEvent(target, event);
      return event;
    }

    // iOS keyboards send a space as a real keydown (2026-11-04, the simulator:
    // "Ab", space, "c" read "Abc" and the focused row was pressed).
    // MUTATION CONTROL: removing the isTextEntry check turns these red.
    it.each(['name', 'note'])('leaves a space in the %s field and presses no row', (label) => {
      const pressed: number[] = [];
      const { getByLabelText } = render(<FieldHarness pressed={pressed} />);
      expect(pressKey(getByLabelText(label), ' ').defaultPrevented).toBeFalsy();
      expect(pressed).toEqual([]);
    });

    it('leaves Enter and the arrows in the field', () => {
      const pressed: number[] = [];
      const { getByLabelText } = render(<FieldHarness pressed={pressed} />);
      const field = getByLabelText('name');
      expect(pressKey(field, 'Enter').defaultPrevented).toBeFalsy();
      expect(pressKey(field, 'ArrowDown').defaultPrevented).toBeFalsy();
      expect(pressed).toEqual([]);
      expect(hookResult.focusedIndex).toBe(0);
    });

    it('still takes a space pressed outside a field', () => {
      const pressed: number[] = [];
      render(<FieldHarness pressed={pressed} />);
      expect(pressKey(document.body, ' ').defaultPrevented).toBeTruthy();
      expect(pressed).toEqual([0]);
    });
  });

  describe('keyboard navigation', () => {
    it('ArrowDown increments focused index', () => {
      render(<Harness itemCount={3} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowDown' }); });
      expect(hookResult.focusedIndex).toBe(1);
    });

    it('ArrowUp decrements focused index', () => {
      render(<Harness itemCount={3} initialIndex={2} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowUp' }); });
      expect(hookResult.focusedIndex).toBe(1);
    });

    it('ArrowRight increments focused index', () => {
      render(<Harness itemCount={3} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowRight' }); });
      expect(hookResult.focusedIndex).toBe(1);
    });

    it('ArrowLeft decrements focused index', () => {
      render(<Harness itemCount={3} initialIndex={1} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowLeft' }); });
      expect(hookResult.focusedIndex).toBe(0);
    });

    it('wraps around when going past the last item', () => {
      render(<Harness itemCount={3} initialIndex={2} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowDown' }); });
      expect(hookResult.focusedIndex).toBe(0);
    });

    it('wraps around when going before the first item', () => {
      render(<Harness itemCount={3} initialIndex={0} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowUp' }); });
      expect(hookResult.focusedIndex).toBe(2);
    });

    it('Enter calls onSelect with current index', () => {
      const onSelect = jest.fn();
      render(<Harness itemCount={3} onSelect={onSelect} initialIndex={1} />);
      act(() => { fireEvent.keyDown(document, { key: 'Enter' }); });
      expect(onSelect).toHaveBeenCalledWith(1);
    });

    it('Space calls onSelect with current index', () => {
      const onSelect = jest.fn();
      render(<Harness itemCount={3} onSelect={onSelect} />);
      act(() => { fireEvent.keyDown(document, { key: ' ' }); });
      expect(onSelect).toHaveBeenCalledWith(0);
    });

    it('does not navigate when itemCount is 0', () => {
      render(<Harness itemCount={0} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowDown' }); });
      expect(hookResult.focusedIndex).toBe(0);
    });
  });

  describe('combo entry suppression', () => {
    it('does not call onSelect when __dsmComboEntryActive is true', () => {
      const onSelect = jest.fn();
      render(<Harness itemCount={3} onSelect={onSelect} />);
      (window as any).__dsmComboEntryActive = true;
      act(() => { fireEvent.keyDown(document, { key: 'Enter' }); });
      expect(onSelect).not.toHaveBeenCalled();
    });

    it('does not intercept arrow keys when __dsmComboEntryActive is true', () => {
      render(<Harness itemCount={3} />);
      (window as any).__dsmComboEntryActive = true;
      act(() => { fireEvent.keyDown(document, { key: 'ArrowDown' }); });
      // When combo entry active, handler returns early — index stays at 0
      expect(hookResult.focusedIndex).toBe(0);
    });
  });

  describe('clamping on itemCount change', () => {
    it('clamps focused index when itemCount shrinks', () => {
      const { rerender } = render(<Harness itemCount={5} initialIndex={4} />);
      expect(hookResult.focusedIndex).toBe(4);
      rerender(<Harness itemCount={3} />);
      expect(hookResult.focusedIndex).toBe(2);
    });

    it('does not clamp when index is within bounds', () => {
      const { rerender } = render(<Harness itemCount={5} initialIndex={1} />);
      rerender(<Harness itemCount={3} />);
      expect(hookResult.focusedIndex).toBe(1);
    });
  });

  describe('setFocusedIndex', () => {
    it('allows manual override of focused index', () => {
      render(<Harness itemCount={5} />);
      act(() => { hookResult.setFocusedIndex(3); });
      expect(hookResult.focusedIndex).toBe(3);
    });
  });

  describe('D-pad button click handlers', () => {
    it('handles click on .dpad-down element', () => {
      const el = document.createElement('div');
      el.classList.add('dpad-down');
      document.body.appendChild(el);

      render(<Harness itemCount={5} />);
      act(() => { el.click(); });
      expect(hookResult.focusedIndex).toBe(1);

      document.body.removeChild(el);
    });

    it('handles click on .button-a element (select)', () => {
      const onSelect = jest.fn();
      const el = document.createElement('div');
      el.classList.add('button-a');
      document.body.appendChild(el);

      render(<Harness itemCount={3} onSelect={onSelect} />);
      act(() => { el.click(); });
      expect(onSelect).toHaveBeenCalledWith(0);

      document.body.removeChild(el);
    });
  });
});
