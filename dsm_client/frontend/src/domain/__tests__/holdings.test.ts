// SPDX-License-Identifier: Apache-2.0
// A wallet's home does not list a token the protocol defines, other than its
// main currency, that it holds nothing of (owner, 2026-11-22). The rows are
// built from the rows Rust answers, through the wallet's own mapping.

import * as pb from '../../proto/dsm_app_pb';
import { balanceView } from '../../dsm/wallet';
import { homeListed } from '../holdings';
import type { TokenBalanceView } from '../../dsm/types';

/** A row as balance.list answers it: `defined` is Rust's word that the protocol defines the token. */
function row(ticker: string, held: bigint, defined: 'protocol' | 'created'): TokenBalanceView {
  return balanceView(
    new pb.BalanceGetResponse({
      tokenId: ticker,
      symbol: ticker,
      tokenName: ticker,
      available: held,
      displayAmount: held.toString(),
      genesisSupplyDisplay: '1000000',
      permissions: new pb.TokenPolicyPermissions(),
      holding: pb.BalanceHolding.CURRENCY,
      protocolDefined: defined === 'protocol',
    }),
  );
}

const tickers = (rows: TokenBalanceView[]) => rows.map((b) => b.tokenId);

describe('what a wallet home lists', () => {
  it('leaves out a second protocol token held at nothing, and lists it once some is held', () => {
    expect(tickers(homeListed([row('ERA', 50n, 'protocol'), row('dBTC', 0n, 'protocol'), row('WILD', 3n, 'created')])))
      .toEqual(['ERA', 'WILD']);
    expect(tickers(homeListed([row('ERA', 50n, 'protocol'), row('dBTC', 7n, 'protocol')])))
      .toEqual(['ERA', 'dBTC']);
  });

  it('lists the main currency at zero, and a created token at zero', () => {
    expect(tickers(homeListed([row('ERA', 0n, 'protocol'), row('dBTC', 0n, 'protocol'), row('STEEL', 0n, 'created')])))
      .toEqual(['ERA', 'STEEL']);
  });

  it('counts an offline allocation as something held', () => {
    const loaded: TokenBalanceView = { ...row('dBTC', 0n, 'protocol'), offline: { baseUnits: 4n, displayAmount: '4' } };
    const empty: TokenBalanceView = { ...row('dBTC', 0n, 'protocol'), offline: { baseUnits: 0n, displayAmount: '0' } };
    expect(tickers(homeListed([row('ERA', 1n, 'protocol'), loaded]))).toEqual(['ERA', 'dBTC']);
    expect(tickers(homeListed([row('ERA', 1n, 'protocol'), empty]))).toEqual(['ERA']);
  });

  // Rust reports the balance net of what is committed in flight (`locked`): a
  // token whose whole holding is in flight is still the wallet's.
  it('counts what is locked in flight as something held', () => {
    const inFlight = balanceView(
      new pb.BalanceGetResponse({
        tokenId: 'dBTC', symbol: 'dBTC', tokenName: 'dBTC', available: 0n, locked: 9n, displayAmount: '0',
        holding: pb.BalanceHolding.CURRENCY, protocolDefined: 'dBTC'.length > 0,
      }),
    );
    expect(inFlight.lockedBaseUnits).toBe(9n);
    expect(tickers(homeListed([row('ERA', 1n, 'protocol'), inFlight]))).toEqual(['ERA', 'dBTC']);
  });

  // The appliance has not stated the allocation yet: the row would show the
  // balance, zero, so it is not listed until an allocation with something in
  // it is stated.
  it('does not list a token at zero for an offline allocation not yet stated', () => {
    const unknown = row('dBTC', 0n, 'protocol');
    expect(unknown.offline).toBeUndefined();
    expect(tickers(homeListed([row('ERA', 1n, 'protocol'), unknown]))).toEqual(['ERA']);
  });

  it('goes by what Rust says the protocol defines, not by a ticker', () => {
    // A token someone created and named dBTC is theirs to list at zero.
    expect(tickers(homeListed([row('ERA', 1n, 'protocol'), row('dBTC', 0n, 'created')])))
      .toEqual(['ERA', 'dBTC']);
  });
});
