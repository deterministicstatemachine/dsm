// SPDX-License-Identifier: Apache-2.0
// What a wallet's home lists of the balances Rust answers.

import type { TokenBalanceView } from '../dsm/types';

/**
 * The balances a wallet's home lists (owner, 2026-11-22): everything Rust
 * listed, except a token the protocol defines, other than the wallet's main
 * currency, that the wallet holds nothing of. Rust lists every token the
 * protocol defines whether or not the wallet has ever held it, so one held at
 * nothing was a row for a token the wallet does not own.
 *
 * The main currency (the first currency the protocol defines) is listed at
 * zero: it is what the wallet pays its own way in. A token the wallet created
 * or added is listed at zero too: adding it is what lets the wallet receive
 * it. Which tokens the protocol defines is Rust's word (`protocolDefined`),
 * never a ticker's.
 *
 * What the wallet holds is its balance, what Rust reports locked in flight
 * (the balance is net of it), and its offline allocation. An allocation the
 * appliance has not stated yet lists nothing by itself: the row shows the
 * balance, so listing it for an unknown allocation would show a token at
 * zero, which is what this leaves out. The row is listed once the appliance
 * states an allocation with something in it.
 */
export function homeListed(balances: TokenBalanceView[]): TokenBalanceView[] {
  const mainAt = balances.findIndex((b) => b.protocolDefined && b.holding !== 'object');
  return balances.filter((b, at) => !b.protocolDefined
    || at === mainAt
    || b.baseUnits > 0n
    || (b.lockedBaseUnits !== undefined && b.lockedBaseUnits > 0n)
    || (b.offline !== undefined && b.offline.baseUnits > 0n));
}
