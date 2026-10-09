/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import AppContent from './components/AppContent';
import { UXProvider } from './contexts/UXContext';
import GlobalToast from './components/GlobalToast';
import BilateralTransferDialog from './components/BilateralTransferDialog';
import GuidedTour from './components/tour/GuidedTour';
import TourOffer from './components/tour/TourOffer';
import LockPromptModal from './components/lock/LockPromptModal';
import { useTourStore } from './components/tour/tourStore';
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
import logger from './utils/logger';
import { appRuntimeStore, useAppRuntimeStore } from './runtime/appRuntimeStore';
import { navigationStore, useNavigationStore } from './runtime/navigationStore';
import { buildHomeMenuItems } from './viewmodels/homeViewModel';
import { useBottomNav } from './hooks/useBottomNav';
import { WalletProvider } from './contexts/WalletContext';
import { ContactsProvider } from './contexts/ContactsContext';
import { BridgeProvider } from './bridge/BridgeProvider';
import { FxLayer, FxProvider } from './components/fx/FxProvider';
import { useNativeSessionBridge } from './hooks/useNativeSessionBridge';
import './styles/screen.css';
import './styles/simple.css';
import { useSkin } from './hooks/useSkin';
import SkinChoice from './components/simple/SkinChoice';

export default function App() {
  const runtime = useAppRuntimeStore();
  const navigation = useNavigationStore();
  const tour = useTourStore();
  const lockPromptCheckedRef = useRef(false);
  const [_themeIndex, setThemeIndex] = useState(0);

  const themes = useMemo(() => getAvailableThemes(), []);
  const { handleGenerateGenesis, cancelPhraseBackup, answerPhraseCheck } = useGenesisFlow({
    appState: runtime.appState,
    setAppState: appRuntimeStore.setAppState,
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

  // Which skin the page is drawn in: Simple once the wallet is ready and the
  // owner chose it, the Game Boy otherwise.
  const skin = useSkin(session.identity_status, runtime.skin, runtime.scheme, runtime.appState);

  const { showIntro, dismissIntro } = useIntroGate();
  const {
    chameleonSrc,
    setChameleonSrc,
    introGifSrc,
    eraTokenSrc,
    btcLogoSrc,
    dsmLogoSrc,
  } = useThemeAssets(runtime.theme);

  useLockState({ appState: runtime.appState });
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

  const menuIntents = useInputIntents({
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

  // While the intro is on the screen, A (select) moves past it.
  const intents = showIntro ? { ...menuIntents, select: dismissIntro } : menuIntents;

  useLayoutEffect(() => {
    const screenHost = document.querySelector('.stateboy-screen-host');
    if (screenHost) screenHost.scrollTop = 0;
  }, [navigation.currentScreen, runtime.appState]);

  return (
    <UXProvider defaultHideComplexity={true}>
      <WalletProvider>
        <ContactsProvider>
            <BridgeProvider bridge={(globalThis as any)?.window?.DsmBridge as AndroidBridgeV3 | undefined}>
              <ErrorBoundary>
                <StateBoyInputProvider intents={intents}>
                  <FxProvider appState={runtime.appState} soundEnabled={runtime.soundEnabled}>
                  <ScreenContainer theme={runtime.theme}>
                    <AppContent
                      appState={runtime.appState}
                      skin={skin}
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
                      cancelPhraseBackup={cancelPhraseBackup}
                      answerPhraseCheck={answerPhraseCheck}
                      menuItems={menuItems}
                      currentMenuIndex={navigation.currentMenuIndex}
                      setCurrentMenuIndex={(next) => navigationStore.setCurrentMenuIndex(next)}
                    />
                    <GlobalToast />
                    <DiagnosticsOverlay />
                    <BilateralTransferDialog walletReady={runtime.appState === 'wallet_ready' && !showIntro} />
                    <FxLayer />
                    {/* The tour walks the Game Boy's menus and buttons: it runs in
                        Classic, and is offered once Classic is the owner's choice. */}
                    {skin === 'classic' ? <GuidedTour appState={runtime.appState} /> : null}
                    {runtime.skin === 'classic' ? <TourOffer appState={runtime.appState} showIntro={showIntro} /> : null}
                    <SkinChoice appState={runtime.appState} />
                  </ScreenContainer>
                  {/* The passcode prompt is its own layer, not part of the home
                      screen's content: it portals over the whole display, the
                      screen and its nav bar. The tour portals above the shell,
                      so it stays on top; while a tour runs the prompt waits,
                      rather than covering what the tour points at, and comes
                      back when the tour ends at home. */}
                  {runtime.showLockPrompt && !showIntro && !tour.active && runtime.appState === 'wallet_ready' && navigation.currentScreen === 'home' ? (
                    <LockPromptModal
                      onNavigate={navigationStore.navigate}
                      onDismiss={() => appRuntimeStore.setShowLockPrompt(false)}
                    />
                  ) : null}
                  </FxProvider>
                </StateBoyInputProvider>
              </ErrorBoundary>
            </BridgeProvider>
        </ContactsProvider>
      </WalletProvider>
    </UXProvider>
  );
}
