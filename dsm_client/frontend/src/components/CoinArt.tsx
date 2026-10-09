// SPDX-License-Identifier: Apache-2.0
// The built-in coin artwork (ERA, dBTC) where a screen draws it directly: the
// spinning GIF on the DGen Game Boy, a still mark in the Modern skin where the
// coin names a token (CoinArt). A coin that only decorates a card (HeroCoin)
// is the Game Boy's alone: the Modern skin leaves it out, disc and all.

import React from 'react';
import { useAppRuntimeStore } from '../runtime/appRuntimeStore';
import { FlatTokenMark } from './FlatTokenMark';

type Props = {
  /** The GIF the DGen Game Boy shows. */
  src: string;
  /** The token the art stands for: ERA or dBTC. */
  ticker: 'ERA' | 'dBTC';
  alt: string;
  className?: string;
  style?: React.CSSProperties;
};

export function CoinArt({ src, ticker, alt, className, style }: Props): React.JSX.Element {
  const runtime = useAppRuntimeStore();
  if (runtime.skin === 'modern') {
    return (
      <span className={className} style={{ display: 'inline-block', flex: '0 0 auto', ...style }}>
        <FlatTokenMark ticker={ticker} alt={alt} className="s-token-fill" />
      </span>
    );
  }
  return <img src={src} alt={alt} className={className} style={style} />;
}

/** A coin on its disc that decorates a card (the faucet, adding a contact): DGen only. */
export function HeroCoin({ src, alt }: { src: string; alt: string }): React.JSX.Element | null {
  const runtime = useAppRuntimeStore();
  if (runtime.skin === 'modern') return null;
  return (
    <span className="sb-coin-tile">
      <img src={src} alt={alt} style={{ width: 48, height: 48, imageRendering: 'pixelated' }} />
    </span>
  );
}
