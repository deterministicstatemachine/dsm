import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SettingsMainScreen from '../SettingsMainScreen';

const mockGetPreference = jest.fn();
const mockSetPreference = jest.fn();

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
  getNfcBackupStatus: jest.fn(async () => ({
    enabled: false,
    configured: false,
    capsuleCount: 0,
    lastCapsuleIndex: 0,
  })),
}));

describe('SettingsMainScreen developer unlock', () => {
  beforeEach(() => {
    mockGetPreference.mockReset();
    mockSetPreference.mockReset();
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
});
