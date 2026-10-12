// SPDX-License-Identifier: Apache-2.0
// The ring-backup screen shows the status Rust reported, or why it could
// not; never a status of defaults while nothing has been read.

import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

const getNfcBackupStatus = jest.fn();
const getCapsulePreview = jest.fn();
const writeToNfcRing = jest.fn();
jest.mock('../../../services/recovery/nfcRecoveryService', () => ({
  getNfcBackupStatus: (...a: unknown[]) => getNfcBackupStatus(...a),
  getCapsulePreview: (...a: unknown[]) => getCapsulePreview(...a),
  writeToNfcRing: (...a: unknown[]) => writeToNfcRing(...a),
  createCapsule: jest.fn(),
  disableNfcBackup: jest.fn(),
  enableNfcBackup: jest.fn(),
  generateMnemonic: jest.fn(),
}));

jest.mock('../../../dsm/EventBridge', () => ({
  initializeEventBridge: jest.fn(),
  on: jest.fn(() => jest.fn()),
}));

import NfcRecoveryScreen from '../NfcRecoveryScreen';

beforeEach(() => {
  jest.clearAllMocks();
  getCapsulePreview.mockResolvedValue(null);
});

describe('NfcRecoveryScreen', () => {
  it('shows a failed status read as its failure, with nothing to arm or write', async () => {
    getNfcBackupStatus.mockRejectedValueOnce(new Error('recovery.status: the recovery tables are not migrated'));
    render(<NfcRecoveryScreen />);

    expect(await screen.findByText(/Status not read: recovery.status: the recovery tables are not migrated/)).toBeInTheDocument();
    expect(screen.queryByText('NOT SET')).toBeNull();
    expect(screen.queryByRole('button', { name: /Set up/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /Write/ })).toBeNull();

    // Try Again asks Rust once more.
    getNfcBackupStatus.mockResolvedValueOnce({
      enabled: false, configured: false, pendingCapsule: false, capsuleCount: 0, lastCapsuleIndex: 0, autoWriteEnabled: false,
    });
    fireEvent.click(screen.getByRole('button', { name: 'Try Again' }));
    expect(await screen.findByText('NOT SET')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Set up' })).toBeInTheDocument();
  });

  it('shows the armed status Rust reported and writes on request', async () => {
    getNfcBackupStatus.mockResolvedValue({
      enabled: true, configured: true, pendingCapsule: true, capsuleCount: 4, lastCapsuleIndex: 9, autoWriteEnabled: false,
    });
    writeToNfcRing.mockResolvedValueOnce(undefined);
    render(<NfcRecoveryScreen />);

    expect(await screen.findByText('ARMED')).toBeInTheDocument();
    expect(screen.getByText('#9')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Write to ring' }));
    await waitFor(() => expect(writeToNfcRing).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Hold the ring to the back of the phone/)).toBeInTheDocument();
  });
});
