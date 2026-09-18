// SPDX-License-Identifier: Apache-2.0
// Plain-language labels for the Bitcoin tab. The wire carries protocol words
// (limbo, claimable, wif); the screen shows what they mean to the person
// holding the phone. The raw word stays available under the Advanced fold.

const DEPOSIT_STATUS_LABEL: Record<string, string> = {
  initiated: 'Starting',
  awaiting_confirmation: 'Confirming',
  awaiting_confirmations: 'Confirming',
  claimable: 'Ready',
  completed: 'Done',
  expired: 'Expired',
  timed_out: 'Expired',
  timeout: 'Expired',
  refunded: 'Refunded',
};

export function depositStatusLabel(status: string): string {
  return DEPOSIT_STATUS_LABEL[status] ?? status.replace(/_/g, ' ');
}

/** Nothing more will happen to this deposit; it belongs in the history fold. */
export function isSettledDeposit(status: string): boolean {
  return status === 'completed' || status === 'refunded';
}

/** An expired deposit is the one state that needs the user's hand (refund). */
export function isRefundableDeposit(status: string): boolean {
  return status === 'expired' || status === 'timed_out' || status === 'timeout';
}

const VAULT_STATE_LABEL: Record<string, string> = {
  limbo: 'Pending',
  active: 'Active',
  unlocked: 'Unlocked',
  claimed: 'Spent',
  invalidated: 'Void',
};

export function vaultStateLabel(state: string): string {
  return VAULT_STATE_LABEL[state] ?? state;
}

const IMPORT_KIND_LABEL: Record<string, string> = {
  mnemonic: 'Recovery phrase',
  xpriv: 'Extended key',
  wif: 'Single key',
};

export function importKindLabel(kind: string): string {
  return IMPORT_KIND_LABEL[kind] ?? kind;
}

export function directionLabel(direction: string): string {
  if (direction === 'btc_to_dbtc') return 'BTC → dBTC';
  if (direction === 'dbtc_to_btc') return 'dBTC → BTC';
  return direction;
}
