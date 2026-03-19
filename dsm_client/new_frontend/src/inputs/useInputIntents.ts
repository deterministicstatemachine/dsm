/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback } from 'react';
import { dsmClient } from '../services/dsmClient';
import { AudioManager } from '../utils/audio';
import logger from '../utils/logger';
import { applyTheme, type ThemeName } from '../utils/theme';
import type { AppState, ScreenType } from '../types/app';

type Params = {
  appState: AppState;
  menuItems: string[];
  currentMenuIndex: number;
  setCurrentMenuIndex: (update: number | ((prev: number) => number)) => void;
  themes: ThemeName[];
  theme: ThemeName;
  setTheme: (theme: ThemeName) => void;
  setThemeIndex: React.Dispatch<React.SetStateAction<number>>;
  navigate: (to: ScreenType) => void;
  goBack: (appState: AppState) => void;
  handleGenerateGenesis: () => Promise<void> | void;
  soundEnabled: boolean;
  setSoundEnabled: (enabled: boolean) => void;
};

export function useInputIntents({
  appState,
  menuItems,
  currentMenuIndex,
  setCurrentMenuIndex,
  themes,
  theme,
  setTheme,
  setThemeIndex,
  navigate,
  goBack,
  handleGenerateGenesis,
  soundEnabled,
  setSoundEnabled,
}: Params) {
  const select = useCallback(() => {
    if ((window as any).__dsmComboEntryActive) return;
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
  }, [currentMenuIndex, handleGenerateGenesis, menuItems, navigate]);

  const back = useCallback(() => {
    if ((window as any).__dsmComboEntryActive) return;
    AudioManager.unlock();
    AudioManager.play('boop');
    goBack(appState);
  }, [appState, goBack]);

  const nextItem = useCallback(() => {
    AudioManager.unlock();
    AudioManager.play('tick');
    if (menuItems.length > 0) {
      setCurrentMenuIndex((prev) => (prev < menuItems.length - 1 ? prev + 1 : 0));
    }
  }, [menuItems, setCurrentMenuIndex]);

  const prevItem = useCallback(() => {
    AudioManager.unlock();
    AudioManager.play('tick');
    if (menuItems.length > 0) {
      setCurrentMenuIndex((prev) => (prev > 0 ? prev - 1 : menuItems.length - 1));
    }
  }, [menuItems, setCurrentMenuIndex]);

  const toggleTheme = useCallback(() => {
    AudioManager.unlock();
    AudioManager.play('boop');
    const currentIndex = themes.indexOf(theme);
    const nextIndex = (currentIndex + 1) % themes.length;
    const nextTheme = themes[nextIndex];
    setTheme(nextTheme);
    setThemeIndex(nextIndex);
    applyTheme(nextTheme);
    void (async () => {
      try {
        await dsmClient.setPreference('ui_theme', nextTheme);
      } catch (e) {
        logger.warn('Failed to persist theme preference:', e);
      }
    })();
  }, [setTheme, setThemeIndex, theme, themes]);

  const start = useCallback(() => {
    AudioManager.unlock();
    const next = !soundEnabled;
    setSoundEnabled(next);
    AudioManager.enabled = next;
    if (next) {
      AudioManager.play('confirm');
    }
    void (async () => {
      try {
        await dsmClient.setPreference('sfx_enabled', next ? 'true' : 'false');
      } catch (e) {
        logger.warn('Failed to persist sfx preference:', e);
      }
    })();
  }, [setSoundEnabled, soundEnabled]);

  return {
    select,
    back,
    nextItem,
    prevItem,
    toggleTheme,
    start,
  };
}
