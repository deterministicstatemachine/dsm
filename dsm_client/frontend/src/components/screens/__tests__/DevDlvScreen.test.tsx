import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DevDlvScreen from '../DevDlvScreen';
import { encodeBase32Crockford32 } from '../../../utils/textId';

jest.mock('../../../services/dsmClient', () => ({
  dsmClient: {
    getContacts: jest.fn(async () => ({ contacts: [
      {
        alias: 'bob',
        deviceId: encodeBase32Crockford32(new Uint8Array(32).fill(0xaa)),
        genesisHash: encodeBase32Crockford32(new Uint8Array(32).fill(0xbb)),
        chainTip: encodeBase32Crockford32(new Uint8Array(32).fill(0xcc)),
        verifying_storage_nodes: ['http://127.0.0.1:8080']
      }
    ] }))
  }
}));

jest.mock('../../../services/dlv/b0xService', () => ({
  computeB0xAddressFromBase32: jest.fn(() => 'B0XDEVTEST')
}));

describe('DevDlvScreen debug b0x tools', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('loads contacts and computes b0x', async () => {
    render(<DevDlvScreen />);

    const loadBtn = screen.getByText(/Load Contacts/i);
    fireEvent.click(loadBtn);

    await waitFor(() => expect(screen.getByRole('combobox')).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText(/bob/i)).toBeInTheDocument());

    const select = screen.getByRole('combobox') as HTMLSelectElement;
    fireEvent.change(select, { target: { value: '0' } });

    const computeBtn = screen.getByText(/Compute b0x/i);
    fireEvent.click(computeBtn);

    await waitFor(() => expect(screen.getByText(/b0x:/i)).toBeInTheDocument());
    expect(screen.getByText(/B0XDEVTEST/)).toBeInTheDocument();

    await waitFor(() => expect(screen.getByText(/b0x:/i)).toBeInTheDocument());
  });
});
