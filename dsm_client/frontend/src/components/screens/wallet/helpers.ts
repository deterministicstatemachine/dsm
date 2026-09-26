// SPDX-License-Identifier: Apache-2.0
// Shared helpers and types for the wallet screen components.
import type { DomainTransaction, DomainTxType } from '../../../domain/types';

/** The badge a history row's type shows. */
export function txTypeLabel(txType: DomainTxType): string {
  switch (txType) {
    case 'faucet': return 'FAUCET';
    case 'bilateral_offline': return 'OFFLINE';
    case 'online': return 'ONLINE';
    case 'dbtc_mint': return 'dBTC MINT';
    case 'dbtc_burn': return 'dBTC BURN';
  }
}

/** The long name a history row's type shows when expanded. */
export function txTypeDetail(txType: DomainTxType): string {
  switch (txType) {
    case 'faucet': return 'ERA faucet claim';
    case 'bilateral_offline': return 'Bilateral Offline (BLE)';
    case 'online': return 'Online';
    case 'dbtc_mint': return 'BTC \u2192 dBTC Deposit';
    case 'dbtc_burn': return 'dBTC \u2192 BTC Withdrawal';
  }
}

/// The rendered magnitude of a transaction.
///
/// Rust renders the signed form; a transaction row shows the sign separately
/// as an arrow and a colour, so drop the leading '-'. That is a presentational
/// split of a finished string, not a second conversion.
export function formatTxAmount(tx: DomainTransaction): string {
  return tx.displayAmount.startsWith('-') ? tx.displayAmount.slice(1) : tx.displayAmount;
}
