// SPDX-License-Identifier: Apache-2.0
// The chameleon on the Game Boy home screen. With nothing waiting he plays his
// loop: he spits a coin and takes it back. With mail waiting — received
// transfers the user has not opened the b0x on, as Rust counts them
// (`inbox.moneyWaiting`, announced by `money.waiting`) — he puts out his
// tongue each time the home screen comes up and holds it out with an envelope
// on it, until the user taps the envelope and is taken to the inbox. Opening
// the inbox reports the mail seen, and he goes back to his loop.

import React, { useEffect, useState } from 'react';
import { bridgeEvents } from '../bridge/bridgeEvents';
import { getMoneyWaiting } from '../dsm/moneyWaiting';
import { mailChameleonOf } from '../hooks/useThemeAssets';
import logger from '../utils/logger';

/** Where he hangs: off the top-left edge of the screen. */
const hangStyle: React.CSSProperties = {
  width: '260px',
  height: 'auto',
  position: 'absolute',
  top: '-23px',
  left: '-3px',
  zIndex: 1000,
};

/**
 * How long the mail animation takes to put the tongue out: it plays frames
 * 8–17 of the loop once, 170 ms each, and stops on the tongue out, so the
 * envelope lands on frame 17, nine frames in.
 */
export const TONGUE_OUT_MS = 9 * 170;

/** Rust's count of received transfers the user has not opened the b0x on. */
function useMailWaiting(): number {
  const [waiting, setWaiting] = useState(0);
  useEffect(() => {
    const gone = new AbortController();
    const read = () => getMoneyWaiting().then(
      (now) => { if (!gone.signal.aborted) setWaiting(now.received.length); },
      (e: unknown) => logger.warn('[home] the mail waiting could not be read', e),
    );
    read();
    const off = bridgeEvents.on('money.waiting', read);
    return () => { gone.abort(); off(); };
  }, []);
  return waiting;
}

/** Each time the home screen comes up the tongue goes out again, from the start. */
let plays = 0;

/** Where the tongue is: the animation loading, on its way out, held out. */
type Reach = 'loading' | 'reaching' | 'holding';

/** An envelope with an exclamation mark, in the screen's two inks, a 20 × 13 pixel grid. */
function Envelope(): React.JSX.Element {
  const ink = { fill: 'var(--text-dark)' };
  const paper = { fill: 'var(--bg)' };
  const flap = [[1, 1], [2, 1], [3, 2], [4, 2], [5, 2], [6, 3], [7, 3], [8, 4], [9, 4], [10, 4], [11, 4], [12, 3], [13, 3], [14, 2], [15, 2], [16, 2], [17, 1], [18, 1]];
  return (
    <svg viewBox="0 0 20 13" width="40" height="26" shapeRendering="crispEdges">
      <rect x="0" y="0" width="20" height="13" style={ink} />
      <rect x="1" y="1" width="18" height="11" style={paper} />
      {flap.map(([x, y]) => <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" style={ink} />)}
      <rect x="9" y="6" width="2" height="3" style={ink} />
      <rect x="9" y="10" width="2" height="1" style={ink} />
    </svg>
  );
}

function MailChameleon({ src, waiting, onError, onOpenInbox }: {
  src: string;
  waiting: number;
  onError: () => void;
  onOpenInbox: () => void;
}): React.JSX.Element {
  const [play] = useState(() => { plays += 1; return plays; });
  const [reach, setReach] = useState<Reach>('loading');

  useEffect(() => {
    if (reach !== 'reaching') return undefined;
    const timer = setTimeout(() => setReach('holding'), TONGUE_OUT_MS);
    return () => clearTimeout(timer);
  }, [reach]);

  const label = waiting === 1 ? '1 new in your inbox — open it' : `${waiting} new in your inbox — open it`;
  return (
    <div className="home-chameleon-mail" style={hangStyle}>
      {/* A fresh `play` each time makes the WebView start the animation over;
          the asset loader serves the file by its path alone. */}
      <img
        src={`${mailChameleonOf(src)}?play=${play}`}
        onLoad={() => setReach((was) => (was === 'loading' ? 'reaching' : was))}
        onError={onError}
        alt="Chameleon holding out your mail"
        style={{ width: '100%', height: 'auto', display: 'block' }}
      />
      {reach === 'holding' && (
        <button type="button" className="home-mail-envelope" aria-label={label} title={label} onClick={onOpenInbox}>
          <Envelope />
        </button>
      )}
    </div>
  );
}

type Props = {
  /** The theme's chameleon loop. */
  src: string;
  onError: () => void;
  /** Takes the user to the b0x inbox. */
  onOpenInbox: () => void;
};

export default function HomeChameleon({ src, onError, onOpenInbox }: Props): React.JSX.Element {
  const waiting = useMailWaiting();
  if (waiting > 0) {
    return <MailChameleon key={src} src={src} waiting={waiting} onError={onError} onOpenInbox={onOpenInbox} />;
  }
  return <img src={src} onError={onError} alt="Chameleon" style={hangStyle} />;
}
