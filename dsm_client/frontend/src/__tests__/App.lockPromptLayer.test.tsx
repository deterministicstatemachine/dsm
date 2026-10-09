// SPDX-License-Identifier: MIT OR Apache-2.0
// The passcode prompt is a layer of its own over the whole display: the screen
// and the nav bar under it, which share the shell's screen wrapper. Inside the
// home screen's content its shade stopped at the screen's bottom edge and left
// the nav bar lit (owner, on the A54).

import React from 'react';
import { render, screen } from '@testing-library/react';
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

jest.mock('../components/AppContent', () => ({
  __esModule: true,
  default: () => <div data-testid="home-content" />,
}));

jest.mock('../components/GlobalToast', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/BilateralTransferDialog', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/DiagnosticsOverlay', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../inputs/providers/StateBoyInputProvider', () => ({
  StateBoyInputProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../hooks/useGenesisFlow', () => ({
  useGenesisFlow: () => ({ handleGenerateGenesis: jest.fn() }),
}));

const mockTour = { active: false, index: 0 };
jest.mock('../components/tour/tourStore', () => ({
  useTourStore: () => mockTour,
}));
jest.mock('../components/tour/GuidedTour', () => ({ __esModule: true, default: () => null }));
jest.mock('../components/tour/TourOffer', () => ({ __esModule: true, default: () => null }));

const mockIntro = { showIntro: false };
jest.mock('../hooks/useIntroGate', () => ({
  useIntroGate: () => ({ showIntro: mockIntro.showIntro, dismissIntro: () => {} }),
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

jest.mock('../inputs/useInputIntents', () => ({
  useInputIntents: () => ({}),
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

const mockScreen = { current: 'home' };
jest.mock('../runtime/navigationStore', () => ({
  navigationStore: {
    installGlobalNavigate: jest.fn(),
    navigate: jest.fn(),
    goBack: jest.fn(),
    resetMenuIndex: jest.fn(),
    setCurrentMenuIndex: jest.fn(),
  },
  useNavigationStore: () => ({ currentScreen: mockScreen.current, currentMenuIndex: 0 }),
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
    showLockPrompt: true,
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
  saveLockPrefs: jest.fn().mockResolvedValue(undefined),
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

describe('App passcode prompt layer', () => {
  // The shell's markup (public/index.html): the screen and its nav bar in one wrapper.
  let wrapper: HTMLElement;
  beforeEach(() => {
    mockScreen.current = 'home';
    mockIntro.showIntro = false;
    mockTour.active = false;
    wrapper = document.createElement('div');
    wrapper.className = 'screen-wrapper';
    wrapper.innerHTML = '<div class="screen" id="stateboy-screen"></div><div class="screen-nav-bar"></div>';
    document.body.appendChild(wrapper);
  });
  afterEach(() => wrapper.remove());

  test("shades the screen and its nav bar, not just the home screen's content", () => {
    render(<App />);
    const dialog = screen.getByRole('dialog', { name: 'Protect your wallet?' });
    const shade = dialog.parentElement as HTMLElement;
    expect(shade).toHaveClass('sb-popover-backdrop');
    expect(dialog.closest('.stateboy-screen-host')).toBeNull();
    expect(screen.getByTestId('home-content').closest('.stateboy-screen-host')).not.toBeNull();
    // Its shade's box is the wrapper's: the screen and the nav bar together.
    expect(shade.parentElement).toBe(wrapper);
    expect(wrapper.querySelector('.screen-nav-bar')).not.toBeNull();
  });

  test('is not shown off the home screen', () => {
    mockScreen.current = 'wallet';
    render(<App />);
    expect(screen.queryByRole('dialog', { name: 'Protect your wallet?' })).toBeNull();
  });

  // The tour is the layer above everything: the prompt used to cover the
  // WALLET brick the tour asks for, and caught the tap.
  test('waits while a tour runs', () => {
    mockTour.active = true;
    render(<App />);
    expect(screen.queryByRole('dialog', { name: 'Protect your wallet?' })).toBeNull();
  });

  test('is not shown over the intro', () => {
    mockIntro.showIntro = true;
    render(<App />);
    expect(screen.queryByRole('dialog', { name: 'Protect your wallet?' })).toBeNull();
  });
});
