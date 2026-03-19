/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
// Tests for BilateralRelationshipsScreen component

declare const describe: any;
declare const test: any;
declare const expect: any;
declare const beforeEach: any;
declare const jest: any;

import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';

// Create mock functions before importing the component
const mockGetContacts = jest.fn();
const mockGetWalletHistory = jest.fn();

// Mock the dsmClient module (domain wrapper)
jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    getContacts: mockGetContacts,
    getWalletHistory: mockGetWalletHistory,
  },
}));

import BilateralRelationshipsScreen from '../BilateralRelationshipsScreen';

describe('BilateralRelationshipsScreen', () => {
  beforeEach(() => {
    mockGetContacts.mockClear();
    mockGetWalletHistory.mockClear();
  });

  describe('Empty State', () => {
    test('renders empty state when no contacts exist', async () => {
      // Mock empty contacts response
      mockGetContacts.mockResolvedValue({
        contacts: [],
      });

      render(<BilateralRelationshipsScreen />);

      // Wait for loading to finish
      await waitFor(() => {
        expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
      });

      // Check empty state message
      expect(screen.getByText('NO CONTACTS YET')).toBeInTheDocument();
      expect(screen.getByText(/Scan a contact's QR code to get started/i)).toBeInTheDocument();
    });

    test('shows CTA button in empty state', async () => {
      mockGetContacts.mockResolvedValue({
        contacts: [],
      });

      render(<BilateralRelationshipsScreen />);

      await waitFor(() => {
        expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
      });

      // Check that SCAN QR CODE button exists in empty state
      const ctaButton = screen.getByRole('button', { name: /SCAN QR CODE/i });
      expect(ctaButton).toBeInTheDocument();
    });

    test('calls onNavigate when empty state CTA is clicked', async () => {
      mockGetContacts.mockResolvedValue({
        contacts: [],
      });

      const mockNavigate = jest.fn();
      render(<BilateralRelationshipsScreen onNavigate={mockNavigate} />);

      await waitFor(() => {
        expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
      });

      const ctaButton = screen.getByRole('button', { name: /SCAN QR CODE/i });
      fireEvent.click(ctaButton);

      expect(mockNavigate).toHaveBeenCalledWith('qr');
    });
  });

  describe('With Contacts', () => {
    const mockContacts = [
      { alias: 'Alice', genesisHash: 'ALICEGEN', deviceId: 'ALICEDEV' },
      { alias: 'Bob', genesisHash: 'BOBGEN', deviceId: 'BOBDEV' },
    ];

    test('renders contact list when contacts exist', async () => {
      mockGetContacts.mockResolvedValue({
        contacts: mockContacts,
      });

      render(<BilateralRelationshipsScreen />);

      await waitFor(() => {
        expect(screen.getAllByText('Alice').length).toBeGreaterThan(0);
      });

      expect(screen.getByText('Bob')).toBeInTheDocument();
      expect(screen.queryByText('NO CONTACTS YET')).not.toBeInTheDocument();
    });

    test('shows INSPECT button when contact is selected', async () => {
      mockGetContacts.mockResolvedValue({
        contacts: mockContacts,
      });

      render(<BilateralRelationshipsScreen />);

      await waitFor(() => {
        expect(screen.getAllByText('Alice').length).toBeGreaterThan(0);
      });

      // First contact should be auto-selected, INSPECT button should appear
      expect(screen.getByRole('button', { name: /INSPECT/i })).toBeInTheDocument();
    });

    test('opens transaction history modal when INSPECT is clicked', async () => {
      mockGetContacts.mockResolvedValue({
        contacts: mockContacts,
      });
      mockGetWalletHistory.mockResolvedValue({
        transactions: [],
      });

      render(<BilateralRelationshipsScreen />);

      await waitFor(() => {
        expect(screen.getAllByText('Alice').length).toBeGreaterThan(0);
      });

      const inspectButton = screen.getByRole('button', { name: /INSPECT/i });
      fireEvent.click(inspectButton);

      await waitFor(() => {
        expect(screen.getByText(/TRANSACTION HISTORY: Alice/i)).toBeInTheDocument();
      });
    });
  });

  describe('Action Buttons', () => {
    test('calls onNavigate with "qr" when SCAN QR is clicked', async () => {
      mockGetContacts.mockResolvedValue({
        contacts: [],
      });

      const mockNavigate = jest.fn();
      render(<BilateralRelationshipsScreen onNavigate={mockNavigate} />);

      await waitFor(() => {
        expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
      });

      const scanButton = screen.getAllByRole('button', { name: /SCAN QR/i })[0];
      fireEvent.click(scanButton);

      expect(mockNavigate).toHaveBeenCalledWith('qr');
    });

    test('calls onNavigate with "mycontact" when MY QR is clicked', async () => {
      mockGetContacts.mockResolvedValue({
        contacts: [],
      });

      const mockNavigate = jest.fn();
      render(<BilateralRelationshipsScreen onNavigate={mockNavigate} />);

      await waitFor(() => {
        expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
      });

      const myQrButton = screen.getByRole('button', { name: /MY QR/i });
      fireEvent.click(myQrButton);

      expect(mockNavigate).toHaveBeenCalledWith('mycontact');
    });
  });

  describe('Error Handling', () => {
    test('displays error message when contact loading fails', async () => {
      mockGetContacts.mockRejectedValue(
        new Error('Network error')
      );

      render(<BilateralRelationshipsScreen />);

      await waitFor(() => {
        expect(screen.getByText('Network error')).toBeInTheDocument();
      });
    });
  });
});
