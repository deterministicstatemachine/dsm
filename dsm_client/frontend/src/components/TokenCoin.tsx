// SPDX-License-Identifier: Apache-2.0
import React, { useEffect, useState } from 'react';
import { coinGifsFor, type CoinGifs } from '../utils/coinArtwork';
import { useActiveTheme } from '../hooks/useActiveTheme';

type Props = {
  /** The token policy's icon field, as Rust carried it. */
  iconUrl?: string;
  ticker: string;
  /** Rendered GIF side in pixels; the element's CSS decides the displayed size. */
  size?: number;
  className?: string;
  alt?: string;
  /** Shown while the coin renders, and if it cannot be drawn. */
  fallbackSrc?: string;
};

/** A token's spinning coin, in the look of the built-in token GIFs, for the active theme. */
export function TokenCoin({ iconUrl, ticker, size = 72, className, alt, fallbackSrc }: Props): JSX.Element | null {
  const theme = useActiveTheme();
  const [gifs, setGifs] = useState<CoinGifs | null>(null);
  const [url, setUrl] = useState('');

  useEffect(() => {
    let live = true;
    // After paint: a first render of a new coin takes a moment; later ones come from the cache.
    const handle = setTimeout(() => {
      if (live) setGifs(coinGifsFor(iconUrl, ticker, size));
    }, 0);
    return () => {
      live = false;
      clearTimeout(handle);
    };
  }, [iconUrl, ticker, size]);

  useEffect(() => {
    // Environments without object URLs (a test DOM) keep the fallback.
    if (!gifs || typeof URL.createObjectURL !== 'function') {
      setUrl('');
      return;
    }
    const next = URL.createObjectURL(new Blob([gifs[theme] as BlobPart], { type: 'image/gif' }));
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [gifs, theme]);

  const src = url || fallbackSrc;
  if (!src) return null;
  return <img src={src} alt={alt ?? ticker} className={className} style={{ flexShrink: 0, imageRendering: 'pixelated' }} />;
}
