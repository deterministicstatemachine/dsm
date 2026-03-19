// SPDX-License-Identifier: Apache-2.0
// Single source of truth for token decimal metadata and amount formatting.
// ALL components MUST import from here — do not duplicate this logic elsewhere.

/**
 * Canonical decimal places per token (keyed by uppercased token ID).
 * Tokens not listed here default to 0 (whole-unit tokens like ERA).
 *
 * dBTC: 8 decimals (1 dBTC = 100_000_000 satoshi base units)
 * ERA:  0 decimals (whole units — confirmed design intent)
 */
const TOKEN_DECIMALS: Record<string, number> = {
  DBTC: 8,
  BTC: 8,
};

/**
 * Returns the number of decimal places for a token.
 * Case-insensitive. Unknown/undefined tokens return 0.
 */
export function getTokenDecimals(tokenId: string | undefined): number {
  if (!tokenId) return 0;
  return TOKEN_DECIMALS[tokenId.trim().toUpperCase()] ?? 0;
}

/**
 * Format an absolute (unsigned) bigint base-unit amount as a human-readable decimal string.
 * Uses pure bigint arithmetic — no Number() cast, no precision loss.
 *
 * @param abs     Absolute base-unit magnitude (must be ≥ 0n)
 * @param tokenId Token identifier (determines decimal places)
 */
export function formatTokenAmount(abs: bigint, tokenId: string): string {
  const decimals = getTokenDecimals(tokenId);
  if (decimals === 0) return abs.toString();
  const scale = BigInt(10 ** decimals);
  const whole = abs / scale;
  const frac = abs % scale;
  const fracStr = frac.toString().padStart(decimals, '0').replace(/0+$/, '') || '0';
  return `${whole}.${fracStr}`;
}

/**
 * Format a signed bigint amount (positive = incoming, negative = outgoing).
 * Returns the formatted decimal string including the sign prefix.
 */
export function formatSignedTokenAmount(amount: bigint, tokenId: string): string {
  const isOutgoing = amount < 0n;
  const abs = isOutgoing ? -amount : amount;
  return `${isOutgoing ? '-' : ''}${formatTokenAmount(abs, tokenId)}`;
}
