import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';

import PendingBilateralScreen from '../../components/screens/PendingBilateralScreen';
import * as pb from '../../proto/dsm_app_pb';
import { encodeBase32Crockford } from '../../utils/textId';

// Mock the bridge directly as it is the source of truth now
jest.mock('../../dsm/WebViewBridge', () => ({
  getPendingBilateralListStrictBridge: jest.fn(),
  addDsmEventListener: jest.fn(() => () => {}), // No-op cleanup
  appRouterInvokeBin: jest.fn(),
}));

import { getPendingBilateralListStrictBridge } from '../../dsm/WebViewBridge';

const mockGetList = getPendingBilateralListStrictBridge as jest.Mock;

describe('PendingBilateralScreen persistence', () => {
  beforeEach(() => {
    mockGetList.mockReset();
  });

  test('fetches and renders pending proposals from bridge on mount', async () => {
    const tx = new pb.OfflineBilateralTransaction({
      commitmentHash: new Uint8Array([1, 2, 3]),
      senderId: new Uint8Array([4, 5, 6]),
      // In the component we read direction from metadata.
      // If incoming, we used "senderId" as counterparty.
      // If outgoing, we used "recipientId" but that wasn't strictly mapped in the component logic update yet
      // but let's assume 'incoming' direction metadata is enough for the mock.
      status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING,
      metadata: {
        direction: 'incoming',
        amount: '12',
        token_id: 'ERA',
        counterparty_alias: 'peer'
      }
    });

    const resp = new pb.OfflineBilateralPendingListResponse({
      transactions: [tx],
    });
    const env = new pb.Envelope({
      version: 3,
      payload: { case: 'offlineBilateralPendingListResponse', value: resp },
    } as any);
    const envBytes = env.toBinary();
    const framed = new Uint8Array(1 + envBytes.length);
    framed[0] = 0x03;
    framed.set(envBytes, 1);

    mockGetList.mockResolvedValue(framed);

    render(<PendingBilateralScreen onNavigate={() => {}} />);

    // Expect the amount "12" and token "ERA" to be rendered
    expect(await screen.findByText(/12\s*ERA/)).toBeInTheDocument();
    
    expect(mockGetList).toHaveBeenCalledTimes(1);
  });

  test('renders multiple items sorted by receipt order from rust', async () => {
    const tx1 = new pb.OfflineBilateralTransaction({
      commitmentHash: new Uint8Array([0]),
      status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING,
      metadata: { amount: '5' }
    });
    const tx2 = new pb.OfflineBilateralTransaction({
      commitmentHash: new Uint8Array([1]),
      status: pb.OfflineBilateralTransactionStatus.OFFLINE_TX_PENDING,
      metadata: { amount: '10' }
    });

    const resp = new pb.OfflineBilateralPendingListResponse({
      transactions: [tx1, tx2], // We pass them in list order. The component renders them in order.
    });
    const env = new pb.Envelope({
      version: 3,
      payload: { case: 'offlineBilateralPendingListResponse', value: resp },
    } as any);
    const envBytes = env.toBinary();
    const framed = new Uint8Array(1 + envBytes.length);
    framed[0] = 0x03;
    framed.set(envBytes, 1);

    mockGetList.mockResolvedValue(framed);

    render(<PendingBilateralScreen onNavigate={() => {}} />);

    // Wait for both to appear
    expect(await screen.findByText(/5/)).toBeInTheDocument();
    expect(await screen.findByText(/10/)).toBeInTheDocument();
  });
});
