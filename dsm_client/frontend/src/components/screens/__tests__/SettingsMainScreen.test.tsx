// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import SettingsMainScreen from '../SettingsMainScreen';
// githubIssue import removed — feedback button now uses diagnostics overlay

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

    const versionButton = screen.getByText('Version').closest('button');
    expect(versionButton).not.toBeNull();

    for (let i = 0; i < 7; i += 1) {
      fireEvent.click(versionButton as HTMLButtonElement);
    }

    await waitFor(() =>
      expect(mockSetPreference).toHaveBeenCalledWith('dev_mode', '1'),
    );
    await waitFor(() =>
      expect(screen.getByText('Developer options')).toBeInTheDocument(),
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

    expect(screen.getByText('Developer options')).toBeInTheDocument();

    resolveDevPref?.('true');
    await waitFor(() => expect(mockGetPreference).toHaveBeenCalled());
  });

  it('dispatches diagnostics event from report-issue button (dev mode)', async () => {
    // Button is inside DEVELOPER OPTIONS — need dev mode enabled
    mockGetPreference.mockResolvedValueOnce('true');

    render(<SettingsMainScreen />);

    await waitFor(() =>
      expect(screen.getByText('Developer options')).toBeInTheDocument(),
    );

    const handler = jest.fn();
    window.addEventListener('dsm-open-diagnostics', handler);

    const reportBtn = screen.getByRole('button', { name: /REPORT ISSUE \/ FEEDBACK/i });
    expect(reportBtn).toBeInTheDocument();

    fireEvent.click(reportBtn);

    expect(handler).toHaveBeenCalledTimes(1);
    expect((handler.mock.calls[0][0] as CustomEvent).detail).toEqual({
      autoGather: true,
    });

    window.removeEventListener('dsm-open-diagnostics', handler);
  });
});
