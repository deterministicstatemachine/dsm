import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DevPostedInboxScreen from '../DevPostedInboxScreen';

jest.mock('../../../dsm/posted_dlv', () => ({
  listPostedDlvs: jest.fn(),
  syncPostedDlvs: jest.fn(),
  claimPostedDlv: jest.fn(),
}));

import {
  listPostedDlvs,
  syncPostedDlvs,
  claimPostedDlv,
} from '../../../dsm/posted_dlv';
import { encodeBase32Crockford } from '../../../utils/textId';

const v1 = encodeBase32Crockford(new Uint8Array(32).fill(0x11));
const v2 = encodeBase32Crockford(new Uint8Array(32).fill(0x22));
const pk1 = encodeBase32Crockford(new Uint8Array(32).fill(0xAA));
const pk2 = encodeBase32Crockford(new Uint8Array(32).fill(0xBB));

describe('DevPostedInboxScreen', () => {
  beforeEach(() => jest.clearAllMocks());

  test('initial render shows empty-state hint', () => {
    render(<DevPostedInboxScreen />);
    expect(screen.getByText(/No pending DLVs/i)).toBeInTheDocument();
    const sync = screen.getByText(/Sync all/i) as HTMLButtonElement;
    expect(sync.disabled).toBe(true);
  });

  test('Refresh populates inbox + enables Sync', async () => {
    (listPostedDlvs as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [
        { dlvIdBase32: v1, creatorPublicKeyBase32: pk1 },
        { dlvIdBase32: v2, creatorPublicKeyBase32: pk2 },
      ],
    });
    render(<DevPostedInboxScreen />);
    fireEvent.click(screen.getByText(/Refresh inbox/i));
    await waitFor(() =>
      expect(screen.getByText(/2 pending DLV\(s\)/i)).toBeInTheDocument(),
    );
    const sync = screen.getByText(/Sync all \(2\)/i) as HTMLButtonElement;
    expect(sync.disabled).toBe(false);
  });

  test('Sync all marks vaults mirrored', async () => {
    (listPostedDlvs as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [{ dlvIdBase32: v1, creatorPublicKeyBase32: pk1 }],
    });
    (syncPostedDlvs as jest.Mock).mockResolvedValue({
      success: true,
      newlyMirroredBase32: [v1],
    });
    render(<DevPostedInboxScreen />);
    fireEvent.click(screen.getByText(/Refresh inbox/i));
    await waitFor(() => expect(listPostedDlvs).toHaveBeenCalledTimes(1));
    fireEvent.click(await screen.findByText(/Sync all/i));
    await waitFor(() =>
      expect(syncPostedDlvs).toHaveBeenCalledTimes(1),
    );
    await waitFor(() =>
      expect(screen.getByText(/state: mirrored/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/1 newly mirrored/i)).toBeInTheDocument();
  });

  test('Claim sends DlvClaimV1 with the vault id and renders claimed state', async () => {
    (listPostedDlvs as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [{ dlvIdBase32: v1, creatorPublicKeyBase32: pk1 }],
    });
    (claimPostedDlv as jest.Mock).mockResolvedValue({
      success: true,
      vaultIdBase32: v1,
    });
    render(<DevPostedInboxScreen />);
    fireEvent.click(screen.getByText(/Refresh inbox/i));
    await waitFor(() => expect(listPostedDlvs).toHaveBeenCalled());
    const claimBtn = await screen.findByText(/^Claim$/i);
    fireEvent.click(claimBtn);
    await waitFor(() => expect(claimPostedDlv).toHaveBeenCalledTimes(1));
    const arg = (claimPostedDlv as jest.Mock).mock.calls[0][0];
    expect(arg.vaultId.length).toBe(32);
    await waitFor(() =>
      expect(screen.getByText(/state: claimed/i)).toBeInTheDocument(),
    );
  });

  test('Claim failure renders error state on the row', async () => {
    (listPostedDlvs as jest.Mock).mockResolvedValue({
      success: true,
      vaults: [{ dlvIdBase32: v1, creatorPublicKeyBase32: pk1 }],
    });
    (claimPostedDlv as jest.Mock).mockResolvedValue({
      success: false,
      error: 'vault not found',
    });
    render(<DevPostedInboxScreen />);
    fireEvent.click(screen.getByText(/Refresh inbox/i));
    await waitFor(() => expect(listPostedDlvs).toHaveBeenCalled());
    fireEvent.click(await screen.findByText(/^Claim$/i));
    await waitFor(() =>
      expect(screen.getByText(/state: error/i)).toBeInTheDocument(),
    );
    // Error message appears in both the row's detail and the global
    // status box; getAllByText asserts at least one match without
    // tripping the "found multiple elements" guard.
    expect(screen.getAllByText(/vault not found/i).length).toBeGreaterThan(0);
  });

  test('Refresh failure surfaces error verbatim', async () => {
    (listPostedDlvs as jest.Mock).mockResolvedValue({
      success: false,
      error: 'storage timeout',
    });
    render(<DevPostedInboxScreen />);
    fireEvent.click(screen.getByText(/Refresh inbox/i));
    await waitFor(() =>
      expect(screen.getByText(/Refresh failed: storage timeout/i)).toBeInTheDocument(),
    );
  });
});
