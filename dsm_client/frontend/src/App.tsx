/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import AppContent from './components/AppContent';
import { UXProvider } from './contexts/UXContext';
import GlobalToast from './components/GlobalToast';
import BilateralTransferDialog from './components/BilateralTransferDialog';
import { BleProvider } from './contexts/BleContext';
import ScreenContainer from './components/ScreenContainer';
import { useLockState } from './hooks/useLockState';
import { getLockPrefs } from './services/lock/lockService';
import { getAvailableThemes } from './utils/theme';
import DiagnosticsOverlay from './components/DiagnosticsOverlay';
import { useGenesisFlow } from './hooks/useGenesisFlow';
import { useIntroGate } from './hooks/useIntroGate';
import { useThemeAssets } from './hooks/useThemeAssets';
import { useInputIntents } from './inputs/useInputIntents';
import { StateBoyInputProvider } from './inputs/providers/StateBoyInputProvider';
import type { AndroidBridgeV3 } from './dsm/bridgeTypes';
import { installPendingBilateralSync } from './services/pendingBilateralSync';
import logger from './utils/logger';
import { appRuntimeStore, useAppRuntimeStore } from './runtime/appRuntimeStore';
import { navigationStore, useNavigationStore } from './runtime/navigationStore';
import { buildHomeMenuItems } from './viewmodels/homeViewModel';
import { useBottomNav } from './hooks/useBottomNav';
import { WalletProvider } from './contexts/WalletContext';
import { ContactsProvider } from './contexts/ContactsContext';
import { BridgeProvider } from './bridge/BridgeProvider';
import { useNativeSessionBridge } from './hooks/useNativeSessionBridge';

export default function App() {
  const runtime = useAppRuntimeStore();
  const navigation = useNavigationStore();
  const lockPromptCheckedRef = useRef(false);
  const [_themeIndex, setThemeIndex] = useState(0);

  const themes = useMemo(() => getAvailableThemes(), []);
  const { handleGenerateGenesis } = useGenesisFlow({
    setError: appRuntimeStore.setError,
    setSecuringProgress: appRuntimeStore.setSecuringProgress,
  });

  useEffect(() => {
    logger.info('FRONTEND: App mounted');
    return () => logger.info('FRONTEND: App unmounted');
  }, []);

  const session = useNativeSessionBridge({
    themes,
    setThemeIndex,
  });

  useEffect(() => {
    if (runtime.appState !== 'wallet_ready') return;
    const uninstall = installPendingBilateralSync();
    return () => uninstall();
  }, [runtime.appState]);

  const showIntro = useIntroGate(runtime.appState);
  const {
    chameleonSrc,
    setChameleonSrc,
    introGifSrc,
    eraTokenSrc,
    btcLogoSrc,
    dsmLogoSrc,
  } = useThemeAssets(runtime.theme);

  const { unlock } = useLockState({ appState: runtime.appState });
  useBottomNav({ currentScreen: navigation.currentScreen, navigate: navigationStore.navigate });

  useEffect(() => navigationStore.installGlobalNavigate(), []);

  useEffect(() => {
    if (runtime.appState !== 'wallet_ready') return;
    if (lockPromptCheckedRef.current) return;
    if (!session.received || session.lock_status.enabled) return;
    lockPromptCheckedRef.current = true;
    getLockPrefs()
      .then((prefs) => {
        if (!prefs.promptDismissed) {
          appRuntimeStore.setShowLockPrompt(true);
        }
      })
      .catch(() => {});
  }, [runtime.appState, session.received, session.lock_status.enabled]);

  useEffect(() => {
    const shell = document.querySelector('.stateboy') as HTMLElement | null;
    const root = document.getElementById('dsm-app-root');
    if (shell) shell.setAttribute('data-theme', runtime.theme);
    if (root) root.setAttribute('data-theme', runtime.theme);
  }, [runtime.theme]);

  const menuItems = useMemo(
    () => buildHomeMenuItems(runtime.appState, navigation.currentScreen),
    [navigation.currentScreen, runtime.appState],
  );

  useEffect(() => {
    if (navigation.currentScreen === 'home') {
      navigationStore.resetMenuIndex();
    }
  }, [navigation.currentScreen, runtime.appState]);

  const intents = useInputIntents({
    appState: runtime.appState,
    menuItems,
    currentMenuIndex: navigation.currentMenuIndex,
    setCurrentMenuIndex: navigationStore.setCurrentMenuIndex,
    themes,
    theme: runtime.theme,
    setTheme: appRuntimeStore.setTheme,
    setThemeIndex,
    navigate: navigationStore.navigate,
    goBack: navigationStore.goBack,
    handleGenerateGenesis,
    soundEnabled: runtime.soundEnabled,
    setSoundEnabled: appRuntimeStore.setSoundEnabled,
  });

  useLayoutEffect(() => {
    const screenHost = document.querySelector('.stateboy-screen-host');
    if (screenHost) screenHost.scrollTop = 0;
  }, [navigation.currentScreen, runtime.appState]);

  return (
    <UXProvider defaultHideComplexity={true}>
      <WalletProvider>
        <ContactsProvider>
          <BleProvider>
            <BridgeProvider bridge={(globalThis as any)?.window?.DsmBridge as AndroidBridgeV3 | undefined}>
              <ErrorBoundary>
                <StateBoyInputProvider intents={intents}>
                  <ScreenContainer theme={runtime.theme}>
                    <AppContent
                      appState={runtime.appState}
                      error={runtime.error}
                      showIntro={showIntro}
                      introGifSrc={introGifSrc}
                      eraTokenSrc={eraTokenSrc}
                      btcLogoSrc={btcLogoSrc}
                      dsmLogoSrc={dsmLogoSrc}
                      chameleonSrc={chameleonSrc}
                      setChameleonSrc={setChameleonSrc}
                      soundEnabled={runtime.soundEnabled}
                      securingProgress={runtime.securingProgress}
                      currentScreen={navigation.currentScreen}
                      navigate={navigationStore.navigate}
                      handleGenerateGenesis={handleGenerateGenesis}
                      showLockPrompt={runtime.showLockPrompt}
                      dismissLockPrompt={() => appRuntimeStore.setShowLockPrompt(false)}
                      unlockToWallet={() => { void unlock(); }}
                      menuItems={menuItems}
                      currentMenuIndex={navigation.currentMenuIndex}
                      setCurrentMenuIndex={(next) => navigationStore.setCurrentMenuIndex(next)}
                    />
                    <GlobalToast />
                    <DiagnosticsOverlay />
                    <BilateralTransferDialog />
                  </ScreenContainer>
                </StateBoyInputProvider>
              </ErrorBoundary>
            </BridgeProvider>
          </BleProvider>
        </ContactsProvider>
      </WalletProvider>
    </UXProvider>
  );
}
