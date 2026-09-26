// SPDX-License-Identifier: MIT OR Apache-2.0

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';

import QRCodeScannerPanel from '../QRCodeScannerPanel';
import type { AddContactResult, ContactCard } from '../../../dsm/types';

const startNativeQrScannerViaRouter = jest.fn().mockResolvedValue(undefined);
const readContactCode = jest.fn<Promise<ContactCard>, [string]>();
const addContact = jest.fn<Promise<AddContactResult>, [string, ContactCard]>();

jest.mock('../../../contexts/ContactsContext', () => ({
  useContacts: () => ({ addContact: (alias: string, card: ContactCard) => addContact(alias, card) }),
}));

jest.mock('../../../dsm/contacts', () => ({
  readContactCode: (text: string) => readContactCode(text),
}));

jest.mock('../../../dsm/WebViewBridge', () => ({
  startNativeQrScannerViaRouter: () => startNativeQrScannerViaRouter(),
}));

const CARD: ContactCard = {
  deviceId: new Uint8Array(32).fill(1),
  genesisHash: new Uint8Array(32).fill(2),
  signingPublicKey: new Uint8Array(64).fill(3),
  network: 'dsm-testnet',
};

async function scan(text: string): Promise<void> {
  await act(async () => {
    window.dispatchEvent(new CustomEvent('dsm-event', {
      detail: { topic: 'qr_scan_result', payloadText: text },
    }));
  });
}

async function paste(text: string): Promise<void> {
  fireEvent.change(screen.getByPlaceholderText('dsm:contact/v3:...'), { target: { value: text } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Use Contact Code' }));
  });
}

describe('QRCodeScannerPanel', () => {
  beforeEach(() => {
    startNativeQrScannerViaRouter.mockClear();
    readContactCode.mockReset();
    addContact.mockReset();
  });

  it('does not auto-launch the native scanner on mount', () => {
    render(<QRCodeScannerPanel />);

    expect(startNativeQrScannerViaRouter).not.toHaveBeenCalled();
  });

  it('shows manual contact-code entry on the same screen', () => {
    render(<QRCodeScannerPanel />);

    expect(screen.getByText('Enter Contact Code')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('dsm:contact/v3:...')).toBeInTheDocument();
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
    await scan('');

    expect(onCancel).not.toHaveBeenCalled();
    expect(readContactCode).not.toHaveBeenCalled();
    expect(screen.getByText('Add Contact')).toBeInTheDocument();
  });

  // The screen does not parse a contact code: the scanned text goes to Rust
  // as it was read, and the card shown is the card Rust answered.
  it('shows the card Rust read from the scanned code', async () => {
    readContactCode.mockResolvedValue({ ...CARD, preferredAlias: 'Bob' });
    render(<QRCodeScannerPanel />);

    await scan('dsm:contact/v3:SCANNED');

    expect(readContactCode).toHaveBeenCalledWith('dsm:contact/v3:SCANNED');
    expect(screen.getByText('Contact Found')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Bob')).toBeInTheDocument();
  });

  it('shows Rust’s refusal of a pasted code as Rust worded it', async () => {
    readContactCode.mockRejectedValue(new Error('the contact is on network "other"; this device is on "dsm-testnet"'));
    render(<QRCodeScannerPanel />);

    await paste('dsm:contact/v3:PASTED');

    expect(readContactCode).toHaveBeenCalledWith('dsm:contact/v3:PASTED');
    expect(screen.queryByText('Contact Found')).not.toBeInTheDocument();
    expect(screen.getByText(/the contact is on network "other"; this device is on "dsm-testnet"/)).toBeInTheDocument();
  });

  // An empty alias goes to Rust, which names the contact by its device; the
  // success line shows the alias Rust stored.
  it('adds the card Rust read and names the contact as Rust stored it', async () => {
    readContactCode.mockResolvedValue(CARD);
    addContact.mockResolvedValue({ accepted: true, contactId: 'DEVICE', alias: '04080G20' });
    render(<QRCodeScannerPanel />);

    await scan('dsm:contact/v3:SCANNED');
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    });

    expect(addContact).toHaveBeenCalledWith('', CARD);
    expect(screen.getByText(/Contact "04080G20" added\./)).toBeInTheDocument();
  });

  it('shows Rust’s refusal of the add as Rust worded it', async () => {
    readContactCode.mockResolvedValue(CARD);
    addContact.mockResolvedValue({
      accepted: false,
      error: 'no member of the pinned set holds a directory entry for this device that proves itself',
    });
    render(<QRCodeScannerPanel />);

    await scan('dsm:contact/v3:SCANNED');
    fireEvent.change(screen.getByPlaceholderText('Blank: named by its device'), { target: { value: 'Carol' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    });

    expect(addContact).toHaveBeenCalledWith('Carol', CARD);
    expect(screen.getByText(/no member of the pinned set holds a directory entry/)).toBeInTheDocument();
    expect(screen.queryByText(/added\./)).not.toBeInTheDocument();
  });
});
