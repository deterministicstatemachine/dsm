import React from 'react';
import { render, waitFor } from '@testing-library/react';
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

jest.mock('../contexts/BleContext', () => ({
  BleProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
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
  default: () => null,
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

jest.mock('../components/BluetoothIndicatorController', () => ({
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

jest.mock('../hooks/useIntroGate', () => ({
  useIntroGate: () => false,
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

jest.mock('../services/pendingBilateralSync', () => ({
  installPendingBilateralSync: () => () => undefined,
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

const runtimeStoreMock = jest.requireMock('../runtime/appRuntimeStore') as {
  appRuntimeStore: { setShowLockPrompt: jest.Mock };
};

describe('App lock prompt gating', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('uses session.status as source of truth and only checks promptDismissed from prefs', async () => {
    render(<App />);

    await waitFor(() => {
      expect(runtimeStoreMock.appRuntimeStore.setShowLockPrompt).toHaveBeenCalledWith(true);
    });
  });
});
