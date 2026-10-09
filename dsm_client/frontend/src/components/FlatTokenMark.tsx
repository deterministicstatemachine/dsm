// SPDX-License-Identifier: Apache-2.0
// A token's mark in the Modern skin: still, never a spinning coin. The token's
// own policy icon when its policy carries one, else a round badge with the
// ticker's first letter, in fuchsia or gold (ERA fuchsia, dBTC gold, other
// tokens alternating by ticker so a list is not one colour).

import React from 'react';

type Props = { ticker: string; iconUrl?: string; className?: string; alt?: string };

function tone(lower: string): 'fuchsia' | 'gold' {
  if (lower === 'era') return 'fuchsia';
  if (lower === 'dbtc' || lower === 'btc') return 'gold';
  return lower.length % 2 === 0 ? 'fuchsia' : 'gold';
}

export function FlatTokenMark({ ticker, iconUrl, className, alt }: Props): React.JSX.Element {
  const classes = ['s-token-flat', className].filter((c) => c !== undefined && c.length > 0).join(' ');
  if (iconUrl !== undefined && iconUrl.length > 0) {
    return <img src={iconUrl} alt={alt ?? ticker} className={classes} />;
  }
  const lower = ticker.toLowerCase();
  const letter = lower === 'dbtc' || lower === 'btc' ? '₿' : ticker.slice(0, 1).toUpperCase();
  return (
    <span className={classes} data-tone={tone(lower)} role="img" aria-label={alt !== undefined && alt.length > 0 ? alt : ticker}>
      <span className="s-token-letter">{letter}</span>
    </span>
  );
}
