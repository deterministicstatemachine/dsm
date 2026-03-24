import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SettingsMainScreen from '../SettingsMainScreen';

const mockGetPreference = jest.fn();
const mockSetPreference = jest.fn();
const mockGetNfcBackupStatus = jest.fn();

jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    getPreference: (...args: unknown[]) => mockGetPreference(...args),
    setPreference: (...args: unknown[]) => mockSetPreference(...args),
  },
}));

jest.mock('../../../dsm/EventBridge', () => ({
  initializeEventBridge: jest.fn(),
  on: jest.fn(() => jest.fn()),
}));

jest.mock('../../../services/settings/backupService', () => ({
  exportStateBackupFile: jest.fn(),
  importStateBackupFile: jest.fn(),
}));

jest.mock('../../../services/recovery/nfcRecoveryService', () => ({
  getNfcBackupStatus: (...args: unknown[]) => mockGetNfcBackupStatus(...args),
}));

describe('SettingsMainScreen developer unlock', () => {
  beforeEach(() => {
    mockGetPreference.mockReset();
    mockSetPreference.mockReset();
    mockGetNfcBackupStatus.mockReset();
    mockGetNfcBackupStatus.mockResolvedValue({
      enabled: false,
      configured: false,
      pendingCapsule: false,
      capsuleCount: 0,
      lastCapsuleIndex: 0,
    });
  });

  it('keeps developer options unlocked across remounts while prefs reload', async () => {
    mockGetPreference.mockResolvedValueOnce('false');
    mockSetPreference.mockResolvedValue(undefined);

    const { unmount } = render(<SettingsMainScreen />);

    await waitFor(() =>
      expect(screen.getByText(/TAP 7X FOR DEV OPTIONS/i)).toBeInTheDocument(),
    );

    const versionButton = screen.getByText('VERSION').closest('button');
    expect(versionButton).not.toBeNull();

    for (let i = 0; i < 7; i += 1) {
      fireEvent.click(versionButton as HTMLButtonElement);
    }

    await waitFor(() =>
      expect(mockSetPreference).toHaveBeenCalledWith('dev_mode', '1'),
    );
    await waitFor(() =>
      expect(screen.getByText('DEVELOPER OPTIONS')).toBeInTheDocument(),
    );

    unmount();

    let resolveDevPref: ((value: string) => void) | undefined;
    mockGetPreference.mockImplementationOnce(
      () =>
        new Promise<string>((resolve) => {
          resolveDevPref = resolve;
        }),
    );

    render(<SettingsMainScreen />);

    expect(screen.getByText('DEVELOPER OPTIONS')).toBeInTheDocument();

    resolveDevPref?.('true');
    await waitFor(() => expect(mockGetPreference).toHaveBeenCalled());
  });

  it('shows the compact NFC summary with pending-aware state', async () => {
    mockGetPreference.mockResolvedValueOnce('false');
    mockGetNfcBackupStatus.mockResolvedValueOnce({
      enabled: true,
      configured: true,
      pendingCapsule: false,
      capsuleCount: 4,
      lastCapsuleIndex: 9,
    });

    render(<SettingsMainScreen />);

    await waitFor(() =>
      expect(screen.getByText('ON / WAITING')).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/Enabled, but nothing is armed right now\./i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /INSPECT OR RECOVER/i }),
    ).toBeInTheDocument();
  });
});
