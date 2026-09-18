// SPDX-License-Identifier: Apache-2.0
// The mark that stands for a token anywhere the wallet names one.
//
// A token gets its spinning coin when it is created, so the coin is the token's
// face: wherever an amount, a balance, a swap leg or a vault side names a
// token, the same coin appears beside it. ERA and dBTC keep their own built-in
// artwork; every other token is drawn from its policy icon, or from its ticker
// when the policy carries no icon.
import React from 'react';
import { TokenCoin } from './TokenCoin';
import { useActiveTheme } from '../hooks/useActiveTheme';
import { themeBtcLogo, themeEraToken } from '../hooks/useThemeAssets';

type Props = {
  /** Ticker or token id, whichever the screen has. */
  ticker?: string;
  /** The token policy's icon field, as Rust carried it, when the screen has it. */
  iconUrl?: string;
  /** Rendered coin side in pixels; CSS decides the displayed size. */
  size?: number;
  className?: string;
  alt?: string;
};

function isBitcoin(name: string): boolean {
  return name === 'btc' || name === 'dbtc';
}

/** A token's coin, sized for a row by default. Renders nothing without a name. */
export function TokenMark({ ticker, iconUrl, size = 48, className = 'sb-coin', alt = '' }: Props): JSX.Element | null {
  const theme = useActiveTheme();
  const name = (ticker ?? '').trim();
  if (name.length === 0) return null;

  const lower = name.toLowerCase();
  const era = themeEraToken(theme);
  if (isBitcoin(lower)) {
    return <img src={themeBtcLogo(theme)} alt={alt} className={className} aria-hidden={alt ? undefined : true} />;
  }
  if (lower === 'era') {
    return <img src={era} alt={alt} className={className} aria-hidden={alt ? undefined : true} />;
  }
  return <TokenCoin iconUrl={iconUrl} ticker={name} size={size} className={className} fallbackSrc={era} alt={alt} />;
}

export default TokenMark;
