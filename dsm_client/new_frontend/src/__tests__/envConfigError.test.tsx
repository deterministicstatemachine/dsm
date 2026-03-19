import React, { act } from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { bridgeEvents } from '../bridge/bridgeEvents';

// App is default export
import App from '../App';

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


jest.mock('../hooks/useLockState', () => ({
  useLockState: () => ({ lock: null }),
}));

jest.mock('../hooks/useGenesisFlow', () => ({
  useGenesisFlow: () => ({ handleGenerateGenesis: jest.fn() }),
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

// Mock WebViewBridge dynamic import used by gatherDiagnostics
jest.mock('../dsm/WebViewBridge', () => ({
  runNativeBridgeSelfTest: jest.fn().mockReturnValue({ ok: true }),
  getLastError: jest.fn().mockReturnValue(''),
  getArchitectureInfo: jest.fn().mockResolvedValue({ status: 'OK', deviceArch: 'arm64-v8a', supportedAbis: ['arm64-v8a'], message: '', recommendation: '' }),
  addDsmEventListener: jest.fn().mockReturnValue(() => {}),
}));

// Mock dsmClient.getPreference
jest.mock('../services/dsmClient', () => ({
  dsmClient: {
    getPreference: jest.fn().mockImplementation(async (k: string) => {
      if (k === 'DSM_ENV_CONFIG_PATH') return '/data/user/0/app/files/dsm_env_config.toml';
      if (k === 'genesis_hash_bytes') return 'deadbeef';
      if (k === 'device_id_bytes') return 'cafebabe';
      return null;
    }),
    getBluetoothStatus: jest.fn().mockResolvedValue({ enabled: false, advertising: false, scanning: false }),
    getContacts: jest.fn().mockResolvedValue({ contacts: [] }),
  },
}));

// Skip intro animation so App renders the main UI
jest.mock('../hooks/useIntroGate', () => ({ useIntroGate: () => false }));

// Mock telemetry sendDiagnostics
const mockSend = jest.fn().mockResolvedValue(undefined);
jest.mock('../services/telemetry', () => ({ sendDiagnostics: (p: any) => mockSend(p) }));

describe('Env config error banner & diagnostics', () => {
  let warnSpy: jest.SpyInstance;
  let logSpy: jest.SpyInstance;

  beforeAll(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterAll(() => {
    warnSpy.mockRestore();
    logSpy.mockRestore();
  });

  test('shows banner and collects diagnostics, allows send when consented', async () => {
    const batteryEl = document.createElement('div');
    batteryEl.className = 'battery-light';
    document.body.appendChild(batteryEl);

    render(<App />);

    // Trigger the event
    await act(async () => {
      bridgeEvents.emit('env.config.error', { message: 'Materialize failed' });
    });

    // Banner should appear
    expect(await screen.findByText(/Configuration Error/i)).toBeInTheDocument();
    expect(screen.getByText(/Materialize failed/)).toBeInTheDocument();

    // Click Diagnostics (env config banner uses this label)
    fireEvent.click(screen.getByText(/Diagnostics/i));

    // Wait for modal
    expect(await screen.findByText(/DSM Diagnostics/)).toBeInTheDocument();

    // Check that diagnostics text was collected
    await waitFor(() => expect(screen.getByText(/DSM Diagnostics/)).toBeInTheDocument());

    // Consent checkbox
    const checkbox = screen.getByTestId('telemetry-checkbox') as HTMLInputElement;
    expect(checkbox).toBeInTheDocument();
    fireEvent.click(checkbox);
    expect(checkbox.checked).toBe(true);

    // Click send diagnostics
    const sendButton = screen.getByTestId('send-diagnostics');
    expect(sendButton).toBeEnabled();
    fireEvent.click(sendButton);

    await waitFor(() => expect(mockSend).toHaveBeenCalled());

    // Open GitHub issue: mock window.open and assert URL contains repo
    const openSpy = jest.spyOn(window, 'open').mockImplementation(() => null as any);
    const openBtn = screen.getByTestId('open-issue');
    expect(openBtn).toBeInTheDocument();
    fireEvent.click(openBtn);
    await waitFor(() => expect(openSpy).toHaveBeenCalled());
    const calledUrl = String(openSpy.mock.calls[0][0]);
    expect(calledUrl).toContain('github.com/DSM-Deterministic-State-Machine/deterministic-state-machine/issues/new');
    openSpy.mockRestore();
    batteryEl.remove();
  });

  test('shows bridge error debug UI when bridge.error emitted', async () => {
    render(<App />);
    // Emit bridge.error
    await act(async () => {
      bridgeEvents.emit('bridge.error', { code: 42, message: 'native failure', debugB32: 'CF2XJANV0' });
    });

    // Open diagnostics modal
    fireEvent.click(screen.getByText(/Show diagnostics/i));
    expect(await screen.findByText(/DSM Diagnostics/)).toBeInTheDocument();

    // Debug UI should display code and message
    expect(screen.getByText(/Last Bridge Error/)).toBeInTheDocument();
    expect(screen.getByText(/Code:/)).toBeInTheDocument();
    expect(screen.getByText(/Message:/)).toBeInTheDocument();
    expect(screen.getByText(/Debug Info:/)).toBeInTheDocument();
  });
});
