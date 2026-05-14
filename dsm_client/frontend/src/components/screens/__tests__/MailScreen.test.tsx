// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import MailScreen from '../MailScreen';
import * as postedDlv from '../../../dsm/posted_dlv';
import * as dlv from '../../../dsm/dlv';

jest.mock('../../../dsm/posted_dlv');
jest.mock('../../../dsm/dlv');

const mockedList = jest.mocked(postedDlv.listPostedDlvs);
const mockedSync = jest.mocked(postedDlv.syncPostedDlvs);
const mockedClaim = jest.mocked(postedDlv.claimPostedDlv);
const mockedSend = jest.mocked(dlv.createPostedDlv);

describe('MailScreen', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('inbox renders empty state when no DLVs are pending', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    render(<MailScreen />);
    await waitFor(() => expect(screen.getByText(/0 pending DLV/)).toBeInTheDocument());
    expect(screen.getByText(/No pending posted DLVs/)).toBeInTheDocument();
  });

  it('inbox row sync→claim happy path', async () => {
    mockedList.mockResolvedValue({
      success: true,
      vaults: [
        {
          dlvIdBase32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJK',
          creatorPublicKeyBase32: 'ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJKMNPQRSTVWX',
        },
      ],
    });
    mockedSync.mockResolvedValue({
      success: true,
      newlyMirroredBase32: ['0123456789ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJK'],
    });
    mockedClaim.mockResolvedValue({ success: true, vaultIdBase32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJK' });

    render(<MailScreen />);
    await waitFor(() => expect(screen.getByText(/1 pending DLV/)).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /Sync all/ }));
    await waitFor(() => expect(screen.getByText('mirrored')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: /^Claim$/ }));
    await waitFor(() => expect(screen.getByRole('button', { name: /Claimed ✓/ })).toBeInTheDocument());
  });

  it('compose tab rejects empty recipient + policy + content', () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    render(<MailScreen />);
    fireEvent.click(screen.getByRole('button', { name: /^Compose$/ }));
    const send = screen.getByRole('button', { name: /^Send$/ });
    expect(send).toBeDisabled();
  });

  it('compose tab rejects wrong-length policy anchor', async () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    render(<MailScreen />);
    fireEvent.click(screen.getByRole('button', { name: /^Compose$/ }));
    fireEvent.change(screen.getByLabelText(/Recipient/), { target: { value: 'ZYXWVT0123456789ABCDEFGHJKMNPQRSTVWXYZ' } });
    fireEvent.change(screen.getByLabelText(/Policy anchor/), { target: { value: '00000000' } });
    fireEvent.change(screen.getByLabelText(/^Content$/), { target: { value: 'Hi' } });
    fireEvent.click(screen.getByRole('button', { name: /^Send$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));
    await waitFor(() => expect(screen.getByText(/policy anchor must decode to 32 bytes/)).toBeInTheDocument());
    expect(mockedSend).not.toHaveBeenCalled();
  });

  it('compose happy path: send → resets form, switches to inbox', async () => {
    mockedList
      .mockResolvedValueOnce({ success: true, vaults: [] })
      .mockResolvedValueOnce({ success: true, vaults: [] });
    mockedSend.mockResolvedValue({ success: true, id: '0123456789ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJK' });

    render(<MailScreen />);
    fireEvent.click(screen.getByRole('button', { name: /^Compose$/ }));
    fireEvent.change(screen.getByLabelText(/Recipient/), { target: { value: 'ZYXWVT0123456789ABCDEFGHJKMNPQRSTVWXYZ' } });
    fireEvent.change(screen.getByLabelText(/Policy anchor/), {
      target: { value: '0000000000000000000000000000000000000000000000000000' },
    });
    fireEvent.change(screen.getByLabelText(/^Content$/), { target: { value: 'Hi' } });
    fireEvent.click(screen.getByRole('button', { name: /^Send$/ }));
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));

    await waitFor(() => expect(mockedSend).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText(/Sent\. id=/)).toBeInTheDocument());
  });

  it('back button navigates to home', () => {
    mockedList.mockResolvedValue({ success: true, vaults: [] });
    const onNavigate = jest.fn();
    render(<MailScreen onNavigate={onNavigate} />);
    fireEvent.click(screen.getByRole('button', { name: /^Back$/ }));
    expect(onNavigate).toHaveBeenCalledWith('home');
  });
});
