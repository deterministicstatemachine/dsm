import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';

import QRCodeScannerPanel from '../QRCodeScannerPanel';

const startNativeQrScannerViaRouter = jest.fn().mockResolvedValue(undefined);

jest.mock('../../../contexts/ContactsContext', () => ({
  useContacts: () => ({
    addContact: jest.fn().mockResolvedValue(true),
  }),
}));

jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    isReady: jest.fn().mockResolvedValue(true),
  },
}));

jest.mock('../../../dsm/WebViewBridge', () => ({
  startNativeQrScannerViaRouter: () => startNativeQrScannerViaRouter(),
}));

describe('QRCodeScannerPanel', () => {
  beforeEach(() => {
    startNativeQrScannerViaRouter.mockClear();
  });

  it('does not auto-launch the native scanner on mount', () => {
    render(<QRCodeScannerPanel />);

    expect(startNativeQrScannerViaRouter).not.toHaveBeenCalled();
  });

  it('shows manual contact-code entry on the same screen', () => {
    render(<QRCodeScannerPanel />);

    expect(screen.getByText('Enter Contact Code')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('dsm:contact/v3:... or the Base32 code shown under the QR')).toBeInTheDocument();
  });

  it('opens the native scanner only when the user taps Open Camera', async () => {
    render(<QRCodeScannerPanel />);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Open Camera' }));
    });

    expect(startNativeQrScannerViaRouter).toHaveBeenCalledTimes(1);
  });

  it('keeps the add-contact screen open when the native scan is cancelled', async () => {
    const onCancel = jest.fn();
    render(<QRCodeScannerPanel onCancel={onCancel} />);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Open Camera' }));
    });

    act(() => {
      window.dispatchEvent(new CustomEvent('dsm-event', {
        detail: { topic: 'qr_scan_result', payloadText: '' },
      }));
    });

    expect(onCancel).not.toHaveBeenCalled();
    expect(screen.getByText('Add Contact')).toBeInTheDocument();
  });
});
