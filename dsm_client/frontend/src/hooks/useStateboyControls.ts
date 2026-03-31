/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback } from 'react';
import { dsmClient } from '../services/dsmClient';
import { AudioManager } from '../utils/audio';
import { applyTheme, ThemeName } from '../utils/theme';
import logger from '../utils/logger';
import type { AppState, ScreenType } from '../types/app';

type Params = {
  appState: AppState;
  menuItems: string[];
  currentMenuIndex: number;
  setCurrentMenuIndex: React.Dispatch<React.SetStateAction<number>>;
  currentScreen: ScreenType;
  setCurrentScreen: React.Dispatch<React.SetStateAction<ScreenType>>;
  themes: ThemeName[];
  theme: ThemeName;
  setTheme: React.Dispatch<React.SetStateAction<ThemeName>>;
  setThemeIndex: React.Dispatch<React.SetStateAction<number>>;
  navigate: (to: ScreenType) => void;
  handleGenerateGenesis: () => Promise<void> | void;
  navHistoryRef: React.MutableRefObject<ScreenType[]>;
  setPressedButtons: React.Dispatch<React.SetStateAction<Set<string>>>;
};

export function useStateboyControls({
  appState,
  menuItems,
  currentMenuIndex,
  setCurrentMenuIndex,
  currentScreen,
  setCurrentScreen,
  themes,
  theme,
  setTheme,
  setThemeIndex,
  navigate,
  handleGenerateGenesis,
  navHistoryRef,
  setPressedButtons,
}: Params) {
  const handleButtonPress = useCallback((buttonId: string) => {
    setPressedButtons((prev) => new Set([...prev, buttonId]));
    if (typeof document !== 'undefined') {
      const htmlButton = document.getElementById(buttonId);
      if (htmlButton) htmlButton.classList.add('pressed');
      try {
        requestAnimationFrame(() => {
          setPressedButtons((prev2) => {
            const ns = new Set(prev2);
            ns.delete(buttonId);
            return ns;
          });
          if (htmlButton) htmlButton.classList.remove('pressed');
        });
      } catch {
        setPressedButtons((prev2) => {
          const ns = new Set(prev2);
          ns.delete(buttonId);
          return ns;
        });
        if (htmlButton) htmlButton.classList.remove('pressed');
      }
    }
  }, [setPressedButtons]);

  const handleDpadUp = useCallback(() => {
    handleButtonPress('dpad-up');
    AudioManager.unlock();
    AudioManager.play('tick');
    if (menuItems.length > 0) {
      setCurrentMenuIndex((prev) => (prev > 0 ? prev - 1 : menuItems.length - 1));
    }
  }, [handleButtonPress, menuItems, setCurrentMenuIndex]);

  const handleDpadDown = useCallback(() => {
    handleButtonPress('dpad-down');
    AudioManager.unlock();
    AudioManager.play('tick');
    if (menuItems.length > 0) {
      setCurrentMenuIndex((prev) => (prev < menuItems.length - 1 ? prev + 1 : 0));
    }
  }, [handleButtonPress, menuItems, setCurrentMenuIndex]);

  const handleDpadLeft = useCallback(() => {
    handleButtonPress('dpad-left');
    AudioManager.unlock();
    AudioManager.play('tick');
    logger.debug('D-pad Left pressed');
  }, [handleButtonPress]);

  const handleDpadRight = useCallback(() => {
    handleButtonPress('dpad-right');
    AudioManager.unlock();
    AudioManager.play('tick');
    logger.debug('D-pad Right pressed');
  }, [handleButtonPress]);

  const handleButtonA = useCallback(() => {
    handleButtonPress('button-a');
    AudioManager.unlock();
    AudioManager.play('bleep');

    const currentItem = menuItems[currentMenuIndex];
    switch (currentItem) {
      case 'INITIALIZE':
        void handleGenerateGenesis();
        break;
      case 'RETRY CONNECTION':
        window.location.reload();
        break;
      case 'BACK TO HOME':
        navigate('home');
        break;
      case 'WALLET':
        navigate('wallet');
        break;
      case 'TOKENS':
        navigate('accounts');
        break;
      case 'CONTACTS':
        navigate('contacts');
        break;
      case 'STORAGE':
        navigate('storage');
        break;
      case 'SETTINGS':
        navigate('settings');
        break;
      case 'IMPORT EXISTING':
        logger.info('IMPORT EXISTING selected - implement import functionality');
        break;
      case 'VIEW DOCUMENTATION':
        logger.info('VIEW DOCUMENTATION selected - implement documentation viewer');
        break;
      default:
        if (currentItem) logger.info(`Selected: ${currentItem}`);
    }
  }, [currentMenuIndex, menuItems, handleButtonPress, handleGenerateGenesis, navigate]);

  const handleButtonB = useCallback(() => {
    handleButtonPress('button-b');
    AudioManager.unlock();
    AudioManager.play('boop');

    if (navHistoryRef.current.length > 0) {
      const prev = navHistoryRef.current.pop() as ScreenType;
      setCurrentScreen(prev);
    } else if (currentScreen !== 'home') {
      setCurrentScreen('home');
    } else if (appState === 'wallet_ready') {
      logger.debug('Back navigation (no-op at home)');
    }
  }, [appState, currentScreen, handleButtonPress, navHistoryRef, setCurrentScreen]);

  const handleButtonSelect = useCallback(() => {
    handleButtonPress('button-select');
    AudioManager.unlock();
    AudioManager.play('boop');

    const currentIndex = themes.indexOf(theme);
    const nextIndex = (currentIndex + 1) % themes.length;
    const nextTheme = themes[nextIndex];

    setTheme(nextTheme);
    setThemeIndex(nextIndex);
    applyTheme(nextTheme);

    (async () => {
      try {
        await dsmClient.setPreference('ui_theme', nextTheme);
      } catch (e) {
        logger.warn('Failed to persist theme preference:', e);
      }
    })();
  }, [handleButtonPress, theme, themes, setTheme, setThemeIndex]);

  const handleButtonStart = useCallback(() => {
    handleButtonPress('button-start');
    AudioManager.unlock();
    AudioManager.play('tick');

    if (currentScreen !== 'home') {
      setCurrentScreen('home');
      setCurrentMenuIndex(0);
      return;
    }

    if (appState === 'wallet_ready') {
      setCurrentScreen('wallet');
    }
  }, [appState, currentScreen, handleButtonPress, setCurrentScreen, setCurrentMenuIndex]);

  return {
    handleButtonPress,
    handleDpadUp,
    handleDpadDown,
    handleDpadLeft,
    handleDpadRight,
    handleButtonA,
    handleButtonB,
    handleButtonSelect,
    handleButtonStart,
  };
}
