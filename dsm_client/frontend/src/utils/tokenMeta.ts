// SPDX-License-Identifier: Apache-2.0
// Amount rendering does NOT live here.
//
// This file used to hold a hardcoded decimals table (dBTC and BTC at 8,
// everything else 0) and bigint conversion helpers. The table could not know
// about created or adopted CPTA tokens, so a token declared with 2 decimals
// rendered as whole units everywhere it appeared — the transfer dialog,
// transaction lists, contact history. That is the same defect that displayed a
// balance of 100_000 base units as "100000" rather than "1,000.00", reached by
// a different route.
//
// The token's decimals are registry data and the conversion is protocol
// arithmetic, so both belong to Rust. Every wire message that carries an
// amount now carries its rendered display form beside it
// (BalanceGetResponse.display_amount, TransactionInfo.display_amount), and
// this layer prints that string.

/**
 * Present a display amount that arrived from Rust.
 *
 * The fallback exists only for records written before the field did; it prints
 * base units rather than inventing a scale, because a wrong number is worse
 * than an unscaled one.
 */
export function presentDisplayAmount(
  displayAmount: string | undefined,
  baseUnits: bigint,
): string {
  return displayAmount && displayAmount.length > 0
    ? displayAmount
    : baseUnits.toString();
}

/**
 * Present a signed display amount that arrived from Rust.
 */
export function presentSignedDisplayAmount(
  displayAmount: string | undefined,
  baseUnitsSigned: bigint,
): string {
  if (displayAmount && displayAmount.length > 0) return displayAmount;
  const negative = baseUnitsSigned < 0n;
  const abs = negative ? -baseUnitsSigned : baseUnitsSigned;
  return `${negative ? '-' : ''}${abs.toString()}`;
}
