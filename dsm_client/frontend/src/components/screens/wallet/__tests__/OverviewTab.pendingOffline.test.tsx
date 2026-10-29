// SPDX-License-Identifier: Apache-2.0
//! Payments received offline and held pending are shown apart from the
//! balances, each with its token, its amount and its payer, under "Pending
//! settlement" (owner ruling, 2026-10-28). The balance rows are what
//! balance.list answered, which does not include them. The rows here are
//! built from the answers Rust gives, through the wallet's own mappings.

import React from 'react';
import { render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import OverviewTab from '../OverviewTab';
import * as pb from '../../../../proto/dsm_app_pb';
import { balanceView } from '../../../../dsm/wallet';
import { pendingOfflineView } from '../../../../dsm/pendingOffline';
import type { PendingOfflineState } from '../hooks/usePendingOffline';
import type { TokenBalanceView } from '../../../../dsm/types';
import { walletStore } from '../../../../stores/walletStore';

/** A created token's row, as balance.list answers it. */
const wild = balanceView(
  new pb.BalanceGetResponse({
    tokenId: 'WILD',
    symbol: 'WILD',
    tokenName: 'WILD',
    available: 1_000n,
    displayAmount: '10.00',
    decimals: 2,
    genesisSupplyDisplay: '1000000',
    permissions: new pb.TokenPolicyPermissions(),
    holding: pb.BalanceHolding.CURRENCY,
  }),
);

/** Two payments from Alice held pending, as wallet.pendingOffline answers them. */
const held = pendingOfflineView(
  new pb.PendingOfflineValueResponse({
    receipts: [
      new pb.PendingOfflineReceiptView({ ticker: 'WILD', decimals: 2, baseUnits: 700n, displayAmount: '7.00', payer: 'Alice' }),
      new pb.PendingOfflineReceiptView({ ticker: 'WILD', decimals: 2, baseUnits: 300n, displayAmount: '3.00', payer: 'Alice' }),
    ],
  }),
);

/** The tab showing `answered` as balance.list answered it, loading as the wallet store says it is. */
function renderTab(pendingOffline: PendingOfflineState, answered: TokenBalanceView[]) {
  const stay = (): void => undefined;
  return render(
    <OverviewTab
      balances={answered}
      balancesLoading={walletStore.getSnapshot().isLoading}
      pendingOffline={pendingOffline}
      transactions={[]}
      genesisB32=""
      deviceB32=""
      onSwitchToSend={stay}
      onSwitchToHistory={stay}
    />,
  );
}

it('shows each payment held pending apart from the balance, which it is not in', () => {
  renderTab({ receipts: held, error: null }, [wild]);
  const pending = screen.getByTestId('pending-offline');
  expect(within(pending).getByText('Pending settlement')).toBeInTheDocument();
  const rows = within(pending).getAllByTestId('pending-offline-receipt');
  expect(rows.map((r) => r.textContent)).toEqual(['WILD from Alice7.00', 'WILD from Alice3.00']);

  const balances = screen.getByRole('region', { name: 'Your balances' });
  expect(within(balances).getByText('10.00')).toBeInTheDocument();
  expect(within(balances).queryByText('7.00')).not.toBeInTheDocument();
  expect(within(balances).queryByText('3.00')).not.toBeInTheDocument();
});

it('shows no pending section when nothing is held pending', () => {
  renderTab({ receipts: [], error: null }, [wild]);
  expect(screen.queryByTestId('pending-offline')).not.toBeInTheDocument();
});

it('says so when the pending payments could not be read', () => {
  renderTab({ receipts: [], error: 'the receipts held pending are unreadable' }, [wild]);
  expect(within(screen.getByTestId('pending-offline')).getByRole('alert')).toHaveTextContent(
    'Pending payments could not be read: the receipts held pending are unreadable',
  );
});
