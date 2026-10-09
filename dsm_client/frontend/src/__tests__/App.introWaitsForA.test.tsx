// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { act, render, screen } from '@testing-library/react';
import App from '../App';

jest.mock('../contexts/UXContext', () => ({
  UXProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../contexts/WalletContext', () => ({
  WalletProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../contexts/ContactsContext', () => ({
  ContactsProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../bridge/BridgeProvider', () => ({
  BridgeProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../components/ErrorBoundary', () => ({
  __esModule: true,
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// The screen shows the intro or the app's phase, as App tells it to.
jest.mock('../components/AppContent', () => ({
  __esModule: true,
  default: ({ showIntro }: { showIntro: boolean }) => <div>{showIntro ? 'INTRO' : 'PHASE SCREEN'}</div>,
}));

jest.mock('../components/GlobalToast', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/BilateralTransferDialog', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/ScreenContainer', () => ({
  __esModule: true,
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../components/DiagnosticsOverlay', () => ({
  __esModule: true,
  default: () => null,
}));

// The shell's buttons reach App as intents; the test presses A through them.
const pressed: { intents: { select?: () => void } } = { intents: {} };
jest.mock('../inputs/providers/StateBoyInputProvider', () => ({
  StateBoyInputProvider: ({ intents, children }: { intents: { select?: () => void }; children: React.ReactNode }) => {
    pressed.intents = intents;
    return <>{children}</>;
  },
}));

jest.mock('../hooks/useGenesisFlow', () => ({
  useGenesisFlow: () => ({ handleGenerateGenesis: jest.fn() }),
}));

jest.mock('../hooks/useThemeAssets', () => ({
  useThemeAssets: () => ({
    chameleonSrc: '',
    setChameleonSrc: jest.fn(),
    introGifSrc: '',
    eraTokenSrc: '',
    btcLogoSrc: '',
    dsmLogoSrc: '',
  }),
}));

const menuSelect = jest.fn();
jest.mock('../inputs/useInputIntents', () => ({
  useInputIntents: () => ({ select: menuSelect }),
}));

jest.mock('../hooks/useBottomNav', () => ({
  useBottomNav: () => undefined,
}));

jest.mock('../hooks/useLockState', () => ({
  useLockState: () => ({ unlock: jest.fn() }),
}));

jest.mock('../utils/theme', () => ({
  getAvailableThemes: () => ['stateboy'],
}));

jest.mock('../runtime/navigationStore', () => ({
  navigationStore: {
    installGlobalNavigate: jest.fn(),
    navigate: jest.fn(),
    goBack: jest.fn(),
    resetMenuIndex: jest.fn(),
    setCurrentMenuIndex: jest.fn(),
  },
  useNavigationStore: () => ({ currentScreen: 'home', currentMenuIndex: 0 }),
}));

jest.mock('../viewmodels/homeViewModel', () => ({
  buildHomeMenuItems: () => [],
}));

jest.mock('../runtime/appRuntimeStore', () => ({
  appRuntimeStore: {
    setAppState: jest.fn(),
    setError: jest.fn(),
    setSecuringProgress: jest.fn(),
    setShowLockPrompt: jest.fn(),
    setTheme: jest.fn(),
    setSoundEnabled: jest.fn(),
  },
  useAppRuntimeStore: () => ({
    appState: 'wallet_ready',
    error: null,
    securingProgress: 0,
    showLockPrompt: false,
    soundEnabled: true,
    theme: 'stateboy',
    // The intro plays for the Game Boy, once it is the owner's choice.
    skin: 'dgen',
    skinRead: 'read',
    scheme: 'light',
  }),
}));

jest.mock('../hooks/useNativeSessionBridge', () => ({
  useNativeSessionBridge: () => ({
    received: true,
    phase: 'wallet_ready',
    identity_status: 'ready',
    fatal_error: null,
    lock_status: { enabled: false, locked: false },
  }),
}));

jest.mock('../services/lock/lockService', () => ({
  getLockPrefs: jest.fn().mockResolvedValue({
    enabled: true,
    method: 'pin',
    pinHash: '',
    comboHash: '',
    timeoutMs: 60000,
    lockOnPause: true,
    promptDismissed: false,
  }),
}));

describe('the boot intro waits for A', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('a settled app keeps the intro until A is pressed, and A moves past it', async () => {
    render(<App />);
    await act(async () => {});

    // The wallet is ready, and the intro is still on the screen.
    expect(screen.getByText('INTRO')).toBeTruthy();

    act(() => pressed.intents.select?.());

    expect(screen.getByText('PHASE SCREEN')).toBeTruthy();
    // A moved past the intro; it did not also act on the menu behind it.
    expect(menuSelect).not.toHaveBeenCalled();

    // Past the intro, A is the menu's again.
    act(() => pressed.intents.select?.());
    expect(menuSelect).toHaveBeenCalledTimes(1);
  });
});
