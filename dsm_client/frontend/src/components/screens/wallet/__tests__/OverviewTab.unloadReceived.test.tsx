// SPDX-License-Identifier: Apache-2.0
//! The one action that moves what was received offline into the balance (owner,
//! 2026-11-07: "One tap, all ready"). The wallet asks Rust through the ingress
//! and shows Rust's own sentence. The bridge answers from Rust's own record
//! (ingress.rs, unload_received_answers_through_the_ingress_as_the_wallet_records_it),
//! taken on a device that received nothing: Rust moves nothing and says so.

import React from 'react';
import { join } from 'path';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import OverviewTab from '../OverviewTab';
import { unloadReceived } from '../../../../dsm/offlineCash';
import { answerFromRustRecord, type Arrival } from '../../../../tests/helpers/rustIngressRecord';
import { walletStore } from '../../../../stores/walletStore';

const RECORD = join(__dirname, 'fixtures/unload_received.ingress.bin');
const SENTENCE = 'No money received offline is waiting.';

describe('moving what was received offline to the balance', () => {
  let arrivals: Arrival[];
  beforeEach(() => {
    arrivals = answerFromRustRecord(RECORD);
  });

  it("asks wallet.unloadReceived and answers Rust's counts and sentence", async () => {
    await expect(unloadReceived()).resolves.toEqual({ moved: 0, waiting: 0, message: SENTENCE });
    expect(arrivals.map((a) => a.carried)).toEqual(['wallet.unloadReceived']);
  });

  it("the overview's button asks Rust, reads the wallet again and shows Rust's sentence", async () => {
    const reads: string[] = [];
    const stay = (): void => undefined;
    render(
      <OverviewTab
        balances={[]}
        balancesLoading={walletStore.getSnapshot().isLoading}
        pendingOffline={{ receipts: [{ ticker: 'ERA', displayAmount: '0.07', payer: 'Alice' }], error: null }}
        onReceivedMoved={async () => {
          reads.push('read');
        }}
        transactions={[]}
        genesisB32=""
        deviceB32=""
        onSwitchToSend={stay}
        onSwitchToHistory={stay}
      />,
    );
    fireEvent.click(screen.getByTestId('unload-received'));
    await waitFor(() => expect(screen.getByTestId('unload-received-notice')).toHaveTextContent(SENTENCE));
    expect(screen.getByTestId('unload-received-notice')).toHaveAttribute('role', 'status');
    expect(reads).toEqual(['read']);
    expect(screen.getByTestId('unload-received')).toBeEnabled();
  });
});
