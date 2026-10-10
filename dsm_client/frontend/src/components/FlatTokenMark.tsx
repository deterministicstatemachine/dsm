// SPDX-License-Identifier: Apache-2.0
// A token's mark in the Modern skin: still, never a spinning coin. A round
// badge in fuchsia or gold (ERA fuchsia, dBTC gold, other tokens alternating
// by ticker so a list is not one colour) holding the token's own artwork:
// the logo shape its policy carries (the same shape the DGen coin is struck
// from), drawn in white; a picture its policy links to; else the ticker's
// first letter.

import React, { useMemo } from 'react';
import { decodeCoinSource, MASK_SIZE } from '../utils/coinArtwork';

type Props = { ticker: string; iconUrl?: string; className?: string; alt?: string };

function tone(lower: string): 'fuchsia' | 'gold' {
  if (lower === 'era') return 'fuchsia';
  if (lower === 'dbtc' || lower === 'btc') return 'gold';
  return lower.length % 2 === 0 ? 'fuchsia' : 'gold';
}

/** The policy's logo shape as a white-on-clear picture; `null` without one, or where pictures cannot be drawn. */
function shapePicture(iconUrl: string | undefined): string | null {
  const mask = decodeCoinSource(iconUrl);
  if (mask === null || typeof document === 'undefined') return null;
  const canvas = document.createElement('canvas');
  canvas.width = MASK_SIZE;
  canvas.height = MASK_SIZE;
  const context = canvas.getContext('2d');
  if (context === null) return null;
  const pixels = context.createImageData(MASK_SIZE, MASK_SIZE);
  for (let i = 0; i < mask.length; i++) {
    pixels.data[i * 4] = 255;
    pixels.data[i * 4 + 1] = 255;
    pixels.data[i * 4 + 2] = 255;
    pixels.data[i * 4 + 3] = mask[i];
  }
  context.putImageData(pixels, 0, 0);
  return canvas.toDataURL('image/png');
}

/** A picture the policy links to (not the logo shape, which is drawn above). */
function linkedPicture(iconUrl: string | undefined): string | null {
  if (iconUrl === undefined) return null;
  return iconUrl.startsWith('data:image/') || iconUrl.startsWith('https://') ? iconUrl : null;
}

export function FlatTokenMark({ ticker, iconUrl, className, alt }: Props): React.JSX.Element {
  const shape = useMemo(() => shapePicture(iconUrl), [iconUrl]);
  const classes = ['s-token-flat', className].filter((c) => c !== undefined && c.length > 0).join(' ');
  const lower = ticker.toLowerCase();
  const label = alt !== undefined && alt.length > 0 ? alt : ticker;
  const linked = shape === null ? linkedPicture(iconUrl) : null;
  if (linked !== null) return <img src={linked} alt={label} className={classes} />;
  const letter = lower === 'dbtc' || lower === 'btc' ? '₿' : ticker.slice(0, 1).toUpperCase();
  return (
    <span className={classes} data-tone={tone(lower)} role="img" aria-label={label}>
      {shape !== null ? <img className="s-token-shape" src={shape} alt="" /> : <span className="s-token-letter">{letter}</span>}
    </span>
  );
}
