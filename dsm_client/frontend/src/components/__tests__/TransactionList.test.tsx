/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { TransactionList } from '../TransactionList';

jest.mock('../../hooks/useTransactions', () => ({
  useTransactions: jest.fn(),
}));

const { useTransactions } = jest.requireMock('../../hooks/useTransactions');

describe('TransactionList', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  test('renders empty state when no transactions', () => {
    useTransactions.mockReturnValue({
      transactions: [],
      isProcessing: false,
      error: null,
      refresh: jest.fn(),
    });
    render(<TransactionList />);
    expect(screen.getByText(/No transactions yet/i)).toBeInTheDocument();
  });

  test('renders error state and allows retry', () => {
    const refresh = jest.fn();
    useTransactions.mockReturnValue({
      transactions: [],
      isProcessing: false,
      error: 'oops',
      refresh,
    });
    render(<TransactionList />);
    expect(screen.getByText(/Failed to load transactions: oops/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Retry/i }));
    expect(refresh).toHaveBeenCalled();
  });

  test('renders a transaction item with status and sync indicator', () => {
    const refresh = jest.fn();
    useTransactions.mockReturnValue({
      transactions: [{
        txId: 'tx123',
        type: 'online',
        amount: BigInt(-12345000000), // -123.45 (outgoing, decimals=8 base units)
        recipient: 'abcdef1234567890abcdef',
        status: 'pending',
        syncStatus: 'syncing',
      }],
      isProcessing: false,
      error: null,
      refresh,
    });
    render(<TransactionList />);
    expect(screen.getByText(/ONLINE/)).toBeInTheDocument();
    expect(screen.getByText(/-12345000000/)).toBeInTheDocument();
    expect(screen.getByText(/pending/)).toBeInTheDocument();
    expect(screen.getByText(/SYNCING/)).toBeInTheDocument();
  });
});
