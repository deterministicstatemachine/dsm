import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DevPostedSendScreen from '../DevPostedSendScreen';

jest.mock('../../../dsm/dlv', () => ({
  createPostedDlv: jest.fn(),
}));

import { createPostedDlv } from '../../../dsm/dlv';
import { encodeBase32Crockford } from '../../../utils/textId';

describe('DevPostedSendScreen', () => {
  beforeEach(() => jest.clearAllMocks());

  test('default render shows empty form with Send disabled', () => {
    render(<DevPostedSendScreen />);
    // Two Base32-Crockford inputs (recipient + anchor) — both render.
    expect(screen.getAllByPlaceholderText(/Base32 Crockford\.\.\./).length).toBe(2);
    const sendBtn = screen.getByText(/Send posted DLV/i) as HTMLButtonElement;
    expect(sendBtn.disabled).toBe(true);
  });

  test('rejects empty / non-decoding recipient pk', async () => {
    render(<DevPostedSendScreen />);
    const recipientPasteArea = screen.getAllByPlaceholderText(/Base32 Crockford\.\.\./)[0] as HTMLTextAreaElement;
    fireEvent.change(recipientPasteArea, { target: { value: '$$$invalid$$$' } });
    expect(
      screen.getByText(/Recipient pk must decode to non-empty bytes/i),
    ).toBeInTheDocument();
  });

  test('rejects wrong-length policy anchor', async () => {
    render(<DevPostedSendScreen />);
    // Set a valid recipient pk first
    const recipient = encodeBase32Crockford(new Uint8Array(32).fill(0xAB));
    const inputs = screen.getAllByPlaceholderText(/Base32 Crockford\.\.\./);
    fireEvent.change(inputs[0], { target: { value: recipient } });
    // Anchor that decodes to wrong length (shorter)
    fireEvent.change(inputs[1], { target: { value: 'AAAAA' } });
    expect(
      screen.getByText(/Anchor must decode to exactly 32 bytes/i),
    ).toBeInTheDocument();
  });

  test('rejects non-numeric locked amount on submit', async () => {
    (createPostedDlv as jest.Mock).mockResolvedValue({
      success: true,
      id: 'VAULT_B32',
    });
    render(<DevPostedSendScreen />);
    const recipient = encodeBase32Crockford(new Uint8Array(32).fill(0xAB));
    const anchor = encodeBase32Crockford(new Uint8Array(32).fill(0xCD));
    const inputs = screen.getAllByPlaceholderText(/Base32 Crockford\.\.\./);
    fireEvent.change(inputs[0], { target: { value: recipient } });
    fireEvent.change(inputs[1], { target: { value: anchor } });
    // Locked amount input — find by current value default '0' then override
    const amountInput = screen.getByDisplayValue('0') as HTMLInputElement;
    fireEvent.change(amountInput, { target: { value: 'abc' } });
    fireEvent.click(screen.getByText(/Send posted DLV/i));
    await waitFor(() =>
      expect(screen.getByText(/lockedAmount/i)).toBeInTheDocument(),
    );
    expect(createPostedDlv).not.toHaveBeenCalled();
  });

  test('happy path calls createPostedDlv with empty pk + signature semantics', async () => {
    (createPostedDlv as jest.Mock).mockResolvedValue({
      success: true,
      id: 'STAMPED_VAULT_ID',
    });
    render(<DevPostedSendScreen />);
    const recipient = encodeBase32Crockford(new Uint8Array(32).fill(0xAB));
    const anchor = encodeBase32Crockford(new Uint8Array(32).fill(0xCD));
    const inputs = screen.getAllByPlaceholderText(/Base32 Crockford\.\.\./);
    fireEvent.change(inputs[0], { target: { value: recipient } });
    fireEvent.change(inputs[1], { target: { value: anchor } });

    const sendBtn = await screen.findByText(/Send posted DLV/i);
    await waitFor(() => expect((sendBtn as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(sendBtn);
    await waitFor(() => expect(createPostedDlv).toHaveBeenCalledTimes(1));
    const arg = (createPostedDlv as jest.Mock).mock.calls[0][0];
    // Recipient pk decoded to 32 bytes (matching the encoded value).
    expect(arg.recipientKyberPk.length).toBe(32);
    // Policy anchor decoded to 32 bytes.
    expect(arg.policyDigest.length).toBe(32);
    await waitFor(() =>
      expect(screen.getByText(/Posted DLV created\. id=STAMPED_VAULT_ID/i)).toBeInTheDocument(),
    );
  });

  test('surfaces error envelopes verbatim', async () => {
    (createPostedDlv as jest.Mock).mockResolvedValue({
      success: false,
      error: 'wallet locked',
    });
    render(<DevPostedSendScreen />);
    const recipient = encodeBase32Crockford(new Uint8Array(32).fill(0xAB));
    const anchor = encodeBase32Crockford(new Uint8Array(32).fill(0xCD));
    const inputs = screen.getAllByPlaceholderText(/Base32 Crockford\.\.\./);
    fireEvent.change(inputs[0], { target: { value: recipient } });
    fireEvent.change(inputs[1], { target: { value: anchor } });
    fireEvent.click(await screen.findByText(/Send posted DLV/i));
    await waitFor(() =>
      expect(screen.getByText(/Send failed: wallet locked/i)).toBeInTheDocument(),
    );
  });
});
