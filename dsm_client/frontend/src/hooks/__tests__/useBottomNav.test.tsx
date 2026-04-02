/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, act } from '@testing-library/react';
import { useBottomNav } from '../useBottomNav';
import type { ScreenType } from '../../types/app';

jest.mock('../../dsm/WebViewBridge', () => ({
  openBluetoothSettings: jest.fn().mockResolvedValue(undefined),
}));

import { openBluetoothSettings } from '../../dsm/WebViewBridge';

const mockedOpenBluetooth = openBluetoothSettings as jest.MockedFunction<typeof openBluetoothSettings>;

function Harness({ currentScreen, navigate }: { currentScreen: ScreenType; navigate: (to: ScreenType) => void }) {
  useBottomNav({ currentScreen, navigate });
  return null;
}

function createNavIcon(navKey: string): HTMLDivElement {
  const el = document.createElement('div');
  el.classList.add('screen-nav-icon');
  el.setAttribute('data-nav', navKey);
  document.body.appendChild(el);
  return el;
}

describe('useBottomNav', () => {
  let navElements: HTMLDivElement[] = [];

  afterEach(() => {
    navElements.forEach(el => {
      if (el.parentNode) el.parentNode.removeChild(el);
    });
    navElements = [];
    jest.clearAllMocks();
  });

  describe('click navigation', () => {
    it('navigates to wallet when wallet icon is clicked', () => {
      const walletEl = createNavIcon('wallet');
      navElements.push(walletEl);
      const navigate = jest.fn();

      render(<Harness currentScreen="home" navigate={navigate} />);
      act(() => { walletEl.click(); });

      expect(navigate).toHaveBeenCalledWith('wallet');
    });

    it('opens Bluetooth settings when bluetooth icon is clicked', () => {
      const bleEl = createNavIcon('bluetooth');
      navElements.push(bleEl);
      const navigate = jest.fn();

      render(<Harness currentScreen="wallet" navigate={navigate} />);
      act(() => { bleEl.click(); });

      expect(mockedOpenBluetooth).toHaveBeenCalled();
      expect(navigate).not.toHaveBeenCalled();
    });

    it('navigates to contacts when qr icon is clicked', () => {
      const qrEl = createNavIcon('qr');
      navElements.push(qrEl);
      const navigate = jest.fn();

      render(<Harness currentScreen="wallet" navigate={navigate} />);
      act(() => { qrEl.click(); });

      expect(navigate).toHaveBeenCalledWith('contacts');
    });

    it('navigates to the navKey for generic icons', () => {
      const settingsEl = createNavIcon('settings');
      navElements.push(settingsEl);
      const navigate = jest.fn();

      render(<Harness currentScreen="wallet" navigate={navigate} />);
      act(() => { settingsEl.click(); });

      expect(navigate).toHaveBeenCalledWith('settings');
    });

    it('does nothing when element has no data-nav attribute', () => {
      const el = document.createElement('div');
      el.classList.add('screen-nav-icon');
      document.body.appendChild(el);
      navElements.push(el);
      const navigate = jest.fn();

      render(<Harness currentScreen="wallet" navigate={navigate} />);
      act(() => { el.click(); });

      expect(navigate).not.toHaveBeenCalled();
    });
  });

  describe('active state highlighting', () => {
    it('adds active class to matching nav icon', () => {
      const walletEl = createNavIcon('wallet');
      const settingsEl = createNavIcon('settings');
      navElements.push(walletEl, settingsEl);

      render(<Harness currentScreen="wallet" navigate={jest.fn()} />);

      expect(walletEl.classList.contains('active')).toBe(true);
      expect(settingsEl.classList.contains('active')).toBe(false);
    });

    it('maps vault screen to wallet nav key', () => {
      const walletEl = createNavIcon('wallet');
      navElements.push(walletEl);

      render(<Harness currentScreen="vault" navigate={jest.fn()} />);

      expect(walletEl.classList.contains('active')).toBe(true);
    });

    it('updates active state on screen change', () => {
      const walletEl = createNavIcon('wallet');
      const settingsEl = createNavIcon('settings');
      navElements.push(walletEl, settingsEl);
      const navigate = jest.fn();

      const { rerender } = render(<Harness currentScreen="wallet" navigate={navigate} />);
      expect(walletEl.classList.contains('active')).toBe(true);
      expect(settingsEl.classList.contains('active')).toBe(false);

      rerender(<Harness currentScreen="settings" navigate={navigate} />);
      expect(walletEl.classList.contains('active')).toBe(false);
      expect(settingsEl.classList.contains('active')).toBe(true);
    });
  });

  describe('cleanup on unmount', () => {
    it('removes click handlers on unmount', () => {
      const walletEl = createNavIcon('wallet');
      navElements.push(walletEl);
      const navigate = jest.fn();

      const { unmount } = render(<Harness currentScreen="wallet" navigate={navigate} />);
      unmount();

      act(() => { walletEl.click(); });
      expect(navigate).not.toHaveBeenCalled();
    });
  });

  describe('bluetooth error handling', () => {
    it('catches error from openBluetoothSettings', () => {
      jest.spyOn(console, 'error').mockImplementation(() => {});
      mockedOpenBluetooth.mockRejectedValueOnce(new Error('no ble'));

      const bleEl = createNavIcon('bluetooth');
      navElements.push(bleEl);
      const navigate = jest.fn();

      render(<Harness currentScreen="wallet" navigate={navigate} />);
      act(() => { bleEl.click(); });

      expect(mockedOpenBluetooth).toHaveBeenCalled();
    });
  });
});
