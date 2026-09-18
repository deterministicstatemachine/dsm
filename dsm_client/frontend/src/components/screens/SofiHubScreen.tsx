// SPDX-License-Identifier: Apache-2.0
// SoFi hub — sub-menu reached from the home `SOFI` brick. Keeps the home brick
// set short by tucking the lower-frequency SoFi flows (liquidity, mail) behind
// one extra tap. Each destination is one brick with a plain-language line.

import React, { useCallback } from 'react';
import { ScreenFrame } from '../common/ScreenFrame';

interface Props {
  onNavigate?: (screen: string) => void;
}

type Brick = {
  label: string;
  target: string;
  glyph: string;
  description: string;
};

const BRICKS: Brick[] = [
  {
    label: 'SWAP',
    target: 'swap',
    glyph: '⇄',
    description: 'Trade one token for another at the pool price. You see the exact amount before you confirm.',
  },
  {
    label: 'LIQUIDITY',
    target: 'liquidity',
    glyph: '◎',
    description: 'Put two tokens into a pool and earn a fee on every trade made against it.',
  },
  {
    label: 'MAIL',
    target: 'mail',
    glyph: '✉',
    description: 'Send tokens or a note to someone, even while they are offline. They claim it when they are back.',
  },
];

export default function SofiHubScreen({ onNavigate }: Props): JSX.Element {
  const go = useCallback(
    (target: string) => () => onNavigate?.(target),
    [onNavigate],
  );

  return (
    <ScreenFrame title="SoFi" onBack={() => onNavigate?.('home')}>
      <p className="sb-hint">
        Sovereign finance: pools, trades and mail that settle directly between devices, with no exchange in the middle.
      </p>
      <div className="sb-menu" role="menu" aria-label="SoFi sub-menu">
        {BRICKS.map((brick) => (
          <div
            key={brick.target}
            className="sb-menu__item"
            data-label={brick.label}
            role="menuitem"
            tabIndex={0}
            onClick={go(brick.target)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                go(brick.target)();
              }
            }}
          >
            <span className="sb-menu__glyph" aria-hidden="true">{brick.glyph}</span>
            <span className="sb-menu__text">
              <span className="sb-menu__label">{brick.label}</span>
              <span className="sb-menu__desc">{brick.description}</span>
            </span>
            <span className="sb-menu__chev" aria-hidden="true">{'›'}</span>
          </div>
        ))}
      </div>
    </ScreenFrame>
  );
}
