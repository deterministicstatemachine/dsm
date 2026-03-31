import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import App from '../App';
import { getBridgeInstance, setBridgeInstance } from '../bridge/BridgeRegistry';

jest.mock('../contexts/UXContext', () => ({
  UXProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../contexts/WalletContext', () => ({
  WalletProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useWallet: () => ({
    balances: [],
    transactions: [],
    isInitialized: false,
    isLoading: false,
    error: null,
    refreshBalances: async () => {},
    refreshTransactions: async () => {},
    refreshAll: async () => {},
    setError: () => {},
    dsmClient: {},
  }),
}));

jest.mock('../contexts/ContactsContext', () => ({
  ContactsProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../contexts/BleContext', () => ({
  BleProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('../inputs/providers/StateBoyInputProvider', () => ({
  StateBoyInputProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));


jest.mock('../hooks/useIntroGate', () => ({
  useIntroGate: () => false,
}));

jest.mock('../hooks/useThemeAssets', () => ({
  useThemeAssets: () => ({
    chameleonSrc: 'chameleon.gif',
    setChameleonSrc: jest.fn(),
    introGifSrc: 'intro.gif',
    eraTokenSrc: 'era.gif',
    btcLogoSrc: 'btc.gif',
    dsmLogoSrc: 'logo.gif',
  }),
}));

jest.mock('../hooks/useBottomNav', () => ({
  useBottomNav: () => undefined,
}));

jest.mock('../inputs/useInputIntents', () => ({
  useInputIntents: () => ({}),
}));

jest.mock('../hooks/useLockState', () => ({
  useLockState: () => ({ lock: null }),
}));

jest.mock('../hooks/useGenesisFlow', () => ({
  useGenesisFlow: () => ({ handleGenerateGenesis: jest.fn() }),
}));

jest.mock('../services/pendingBilateralSync', () => ({
  installPendingBilateralSync: () => () => undefined,
}));

jest.mock('../services/lock/lockService', () => ({
  getLockPrefs: jest.fn().mockResolvedValue({ enabled: false, promptDismissed: true, lockOnPause: true }),
}));

jest.mock('../components/ScreenContainer', () => ({
  __esModule: true,
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

jest.mock('../components/common/LoadingSpinner', () => ({
  __esModule: true,
  default: () => {
    throw new Error('boom');
  },
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

jest.mock('../components/BluetoothIndicatorController', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/SplashController', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/EnhancedWalletScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/SettingsMainScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/LockSetupScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/lock/LockScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/lock/LockPromptModal', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/DevDlvScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/DevPolicyScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/ContactsTabScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/AccountsScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/StorageScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/TokenManagementScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/MyContactInfoScreen', () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock('../components/screens/QRCodeScannerScreen', () => ({
  __esModule: true,
  default: () => null,
}));

describe('App UI error boundary placement', () => {
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    setBridgeInstance(undefined);
    (globalThis as any).window = globalThis.window ?? globalThis;
    (window as any).DsmBridge = { jsReady: jest.fn() };
  });

  afterEach(() => {
    setBridgeInstance(undefined);
    consoleErrorSpy.mockRestore();
  });

  it('keeps the bridge registered when a screen render crashes', async () => {
    render(<App />);

    await waitFor(() => expect(getBridgeInstance()).toBe((window as any).DsmBridge));
    await waitFor(() => expect(screen.getByText('Something went wrong.')).toBeInTheDocument());
  });
});
