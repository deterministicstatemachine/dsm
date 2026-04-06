/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, act, fireEvent } from '@testing-library/react';
import { useKeyboardBindings } from '../useKeyboardBindings';

type Intents = Parameters<typeof useKeyboardBindings>[0];

function Harness({ intents }: { intents: Intents }) {
  useKeyboardBindings(intents);
  return null;
}

function makeIntents(): Intents & { [K in keyof Intents]: jest.Mock } {
  return {
    prevItem: jest.fn(),
    nextItem: jest.fn(),
    select: jest.fn(),
    back: jest.fn(),
    toggleTheme: jest.fn(),
    start: jest.fn(),
  };
}

describe('useKeyboardBindings', () => {
  afterEach(() => {
    delete (window as any).__dsmScreenNavActive;
    delete (window as any).__dsmComboEntryActive;
  });

  describe('keyboard events', () => {
    it('ArrowUp calls prevItem', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowUp' }); });
      expect(intents.prevItem).toHaveBeenCalledTimes(1);
    });

    it('ArrowDown calls nextItem', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowDown' }); });
      expect(intents.nextItem).toHaveBeenCalledTimes(1);
    });

    it('ArrowLeft calls prevItem', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowLeft' }); });
      expect(intents.prevItem).toHaveBeenCalledTimes(1);
    });

    it('ArrowRight calls nextItem', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'ArrowRight' }); });
      expect(intents.nextItem).toHaveBeenCalledTimes(1);
    });

    it('Enter calls select', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'Enter' }); });
      expect(intents.select).toHaveBeenCalledTimes(1);
    });

    it('Space calls select', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: ' ' }); });
      expect(intents.select).toHaveBeenCalledTimes(1);
    });

    it('Escape calls back', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'Escape' }); });
      expect(intents.back).toHaveBeenCalledTimes(1);
    });

    it('Tab calls toggleTheme', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'Tab' }); });
      expect(intents.toggleTheme).toHaveBeenCalledTimes(1);
    });

    it('Shift calls start', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      act(() => { fireEvent.keyDown(document, { key: 'Shift' }); });
      expect(intents.start).toHaveBeenCalledTimes(1);
    });
  });

  describe('__dsmScreenNavActive deference', () => {
    it('defers arrow keys when screen nav is active', () => {
      const intents = makeIntents();
      (window as any).__dsmScreenNavActive = true;
      render(<Harness intents={intents} />);

      act(() => {
        fireEvent.keyDown(document, { key: 'ArrowUp' });
        fireEvent.keyDown(document, { key: 'ArrowDown' });
        fireEvent.keyDown(document, { key: 'ArrowLeft' });
        fireEvent.keyDown(document, { key: 'ArrowRight' });
        fireEvent.keyDown(document, { key: 'Enter' });
        fireEvent.keyDown(document, { key: ' ' });
      });

      expect(intents.prevItem).not.toHaveBeenCalled();
      expect(intents.nextItem).not.toHaveBeenCalled();
      expect(intents.select).not.toHaveBeenCalled();
    });

    it('still fires Escape when screen nav is active', () => {
      const intents = makeIntents();
      (window as any).__dsmScreenNavActive = true;
      render(<Harness intents={intents} />);

      act(() => { fireEvent.keyDown(document, { key: 'Escape' }); });
      expect(intents.back).toHaveBeenCalledTimes(1);
    });
  });

  describe('__dsmComboEntryActive suppression', () => {
    it('suppresses select when combo entry is active', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      (window as any).__dsmComboEntryActive = true;

      act(() => { fireEvent.keyDown(document, { key: 'Enter' }); });
      expect(intents.select).not.toHaveBeenCalled();
    });

    it('suppresses back when combo entry is active', () => {
      const intents = makeIntents();
      render(<Harness intents={intents} />);
      (window as any).__dsmComboEntryActive = true;

      act(() => { fireEvent.keyDown(document, { key: 'Escape' }); });
      expect(intents.back).not.toHaveBeenCalled();
    });
  });

  describe('DOM button bindings', () => {
    it('binds click on #dpad-up and #dpad-down', () => {
      const intents = makeIntents();
      const upEl = document.createElement('div');
      upEl.id = 'dpad-up';
      const downEl = document.createElement('div');
      downEl.id = 'dpad-down';
      document.body.appendChild(upEl);
      document.body.appendChild(downEl);

      render(<Harness intents={intents} />);

      act(() => {
        upEl.click();
        downEl.click();
      });

      expect(intents.prevItem).toHaveBeenCalledTimes(1);
      expect(intents.nextItem).toHaveBeenCalledTimes(1);

      document.body.removeChild(upEl);
      document.body.removeChild(downEl);
    });

    it('binds click on #button-a and #button-b', () => {
      const intents = makeIntents();
      const aEl = document.createElement('div');
      aEl.id = 'button-a';
      const bEl = document.createElement('div');
      bEl.id = 'button-b';
      document.body.appendChild(aEl);
      document.body.appendChild(bEl);

      render(<Harness intents={intents} />);

      act(() => {
        aEl.click();
        bEl.click();
      });

      expect(intents.select).toHaveBeenCalledTimes(1);
      expect(intents.back).toHaveBeenCalledTimes(1);

      document.body.removeChild(aEl);
      document.body.removeChild(bEl);
    });
  });

  describe('cleanup on unmount', () => {
    it('removes keydown listener on unmount', () => {
      const intents = makeIntents();
      const { unmount } = render(<Harness intents={intents} />);
      unmount();

      act(() => { fireEvent.keyDown(document, { key: 'ArrowUp' }); });
      expect(intents.prevItem).not.toHaveBeenCalled();
    });
  });

  describe('optional intents', () => {
    it('works when toggleTheme and start are undefined', () => {
      const intents: Intents = {
        prevItem: jest.fn(),
        nextItem: jest.fn(),
        select: jest.fn(),
        back: jest.fn(),
      };
      render(<Harness intents={intents} />);
      // Should not throw
      act(() => {
        fireEvent.keyDown(document, { key: 'Tab' });
        fireEvent.keyDown(document, { key: 'Shift' });
      });
    });
  });
});
