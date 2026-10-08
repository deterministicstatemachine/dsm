// SPDX-License-Identifier: Apache-2.0
// SoFi's Escrow tab sends what the user entered and shows what Rust answers.
// These tests drive the real tab over the bridge, answered from Rust's own
// record of a funded device on the network's nodes (ingress.rs,
// escrow_answers_through_the_ingress_as_the_wallet_records_it): a stake of
// 5 ERA locked on one outcome this device decides and is paid by, the
// outcome decided, and the stake released.

import React from 'react';
import { join } from 'path';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { answerFromRustRecord } from '../../../tests/helpers/rustIngressRecord';
import type { Arrival } from '../../../tests/helpers/rustIngressRecord';
import EscrowTab from '../sofi/EscrowTab';

const RECORD = join(__dirname, 'fixtures/escrow.ingress.bin');
const carried = (arrivals: Arrival[]): string[] => arrivals.map((a) => a.carried);

/** ERA's policy commit, the anchor the wallet's balances carry for it. */
const ERA = 'NNG176RZ6ACTWCDPRNYHXZK2DCZ72SPA9Q6XWGRGQ9JGKZYTESG0';
/** What the record's lock entered. */
const AGREEMENT = 'terms v1: order 1042';
const OUTCOME = 'delivered';

describe('EscrowTab', () => {
  let arrivals: Arrival[];
  beforeEach(() => {
    arrivals = answerFromRustRecord(RECORD);
  });

  it('locks a stake, decides its outcome and releases it, showing what Rust answers at each step', async () => {
    // The balances refresh after a stake moves; nothing else here moves.
    const moved: string[] = [];
    render(<EscrowTab tokenOptions={[{ value: ERA, ticker: 'ERA' }]} onMoved={async () => { moved.push('refresh'); }} />);
    expect(await screen.findByText('No escrow vaults yet.')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Stake'), { target: { value: '5' } });
    fireEvent.click(screen.getByRole('button', { name: 'Stake token' }));
    const list = await screen.findByRole('listbox', { name: 'Stake token' });
    fireEvent.click(within(list).getByRole('option', { name: /ERA/ }));
    fireEvent.change(screen.getByLabelText('Agreement, exactly as every party has it'), { target: { value: AGREEMENT } });
    fireEvent.change(screen.getByLabelText('Outcome 1'), { target: { value: OUTCOME } });
    fireEvent.click(await screen.findByLabelText('Outcome 1 decided by This device'));
    fireEvent.change(screen.getByLabelText('Pays'), { target: { value: screen.getByRole('option', { name: 'This device' }).getAttribute('value') } });

    fireEvent.click(screen.getByRole('button', { name: 'Lock stake' }));
    expect(await screen.findByText('Escrow vault locked')).toBeInTheDocument();
    // Rust renders the stake: 5 ERA at ERA's decimals.
    const vault = await screen.findByRole('region', { name: /^Escrow vault / });
    expect(within(vault).getByText('5.00 ERA')).toBeInTheDocument();
    expect(within(vault).getByText('you decide')).toBeInTheDocument();
    expect(within(vault).getByText('pays you')).toBeInTheDocument();

    fireEvent.click(within(vault).getByRole('button', { name: `Decide ${OUTCOME}` }));
    expect(await within(vault).findByText(`Final: ${OUTCOME}`)).toBeInTheDocument();

    fireEvent.click(within(vault).getByRole('button', { name: 'Release' }));
    expect(await screen.findByText(/^Released at position \d+$/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('Released · ERA')).toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Release' })).not.toBeInTheDocument();
    expect(moved).toEqual(['refresh', 'refresh']);

    // Every step reached Rust, in the order the record holds; nothing was decided here.
    expect(carried(arrivals)).toEqual([
      'escrow.party',
      'escrow.vaults',
      'escrow.lock',
      'escrow.vaults',
      'escrow.adjudicate',
      'escrow.vaults',
      'escrow.release',
      'escrow.vaults',
    ]);
  });
});
