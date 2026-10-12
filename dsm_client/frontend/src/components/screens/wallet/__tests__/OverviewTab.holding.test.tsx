// SPDX-License-Identifier: Apache-2.0
//! The balances card lists currencies and state objects apart: a creature the
//! game issued (a token whose whole supply is one) is not a balance among the
//! coins. The switch beside "Your Balances" flips between the two. The rows
//! are built from the rows Rust answers, through the wallet's own mapping.

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import OverviewTab from '../OverviewTab';
import * as pb from '../../../../proto/dsm_app_pb';
import { balanceView } from '../../../../dsm/wallet';
import type { TokenBalanceView } from '../../../../dsm/types';

/** A created token's row, as balance.list answers it. */
function row(ticker: string, supply: string, held: bigint, holding: pb.BalanceHolding): TokenBalanceView {
  return balanceView(
    new pb.BalanceGetResponse({
      tokenId: ticker,
      symbol: ticker,
      tokenName: ticker,
      available: held,
      displayAmount: held.toString(),
      genesisSupplyDisplay: supply,
      permissions: new pb.TokenPolicyPermissions(),
      holding,
    }),
  );
}

const coin = row('WILD', '1000000', 10n, pb.BalanceHolding.CURRENCY);
const creature = row('MOS0001', '1', 1n, pb.BalanceHolding.STATE_OBJECT);

function renderTab(balances: TokenBalanceView[]) {
  const stay = (): void => undefined;
  return render(
    <OverviewTab
      balances={balances}
      balancesLoading={balances.length < 0}
      transactions={[]}
      genesisB32=""
      deviceB32=""
      onSwitchToSend={stay}
      onSwitchToHistory={stay}
    />,
  );
}

it('lists currencies first, and state objects only behind the switch', () => {
  renderTab([coin, creature]);
  expect(screen.getByText('WILD')).toBeInTheDocument();
  expect(screen.queryByText('MOS0001')).not.toBeInTheDocument();

  const toggle = screen.getByRole('switch', { name: 'Show state objects' });
  expect(toggle).not.toBeChecked();
  fireEvent.click(toggle);
  expect(toggle).toBeChecked();
  expect(screen.getByText('MOS0001')).toBeInTheDocument();
  expect(screen.queryByText('WILD')).not.toBeInTheDocument();
});

it('says so when the wallet holds no state object', () => {
  renderTab([coin]);
  fireEvent.click(screen.getByRole('switch', { name: 'Show state objects' }));
  expect(screen.getByText('No state objects yet.')).toBeInTheDocument();
});
