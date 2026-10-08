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
    case 'token_create': return 'TOKEN';
    case 'vault_create': return 'VAULT';
    case 'sofi_setup': return 'SETUP';
    case 'sofi_trade': return 'TRADE';
    case 'sofi_close': return 'CLOSE';
    case 'escrow_lock': return 'LOCK';
    case 'escrow_release': return 'RELEASE';
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
    case 'token_create': return 'Token created';
    case 'vault_create': return 'Liquidity vault created';
    case 'sofi_setup': return 'Set up with a liquidity vault';
    case 'sofi_trade': return 'Trade';
    case 'sofi_close': return 'Liquidity vault closed';
    case 'escrow_lock': return 'Stake locked in an escrow vault';
    case 'escrow_release': return 'Escrow vault released';
  }
}

/** What a token or SoFi event's row names as its subject. */
export function eventSubjectLabel(txType: DomainTxType): string {
  return txType === 'token_create' ? 'Token' : 'Vault';
}

/// The rendered magnitude of a transaction.
///
/// Rust renders the signed form; a transaction row shows the sign separately
/// as an arrow and a colour, so drop the leading '-'. That is a presentational
/// split of a finished string, not a second conversion.
export function formatTxAmount(tx: DomainTransaction): string {
  return tx.displayAmount.startsWith('-') ? tx.displayAmount.slice(1) : tx.displayAmount;
}
