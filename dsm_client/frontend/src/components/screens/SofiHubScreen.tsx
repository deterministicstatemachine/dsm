// SPDX-License-Identifier: Apache-2.0
// SoFi hub — sub-menu reached from the home `SOFI` brick. Keeps the home brick
// set short by tucking the lower-frequency SoFi flows (liquidity, mail) behind
// one extra tap. Each destination is one brick with a plain-language line.

import React, { useCallback } from 'react';
import { ScreenFrame } from '../common/ScreenFrame';
import { InfoTip } from '../common/InfoTip';

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
    description: 'Trade one token for another',
  },
  {
    label: 'LIQUIDITY',
    target: 'liquidity',
    glyph: '◎',
    description: 'Fund a vault, earn the fees',
  },
  {
    label: 'MAIL',
    target: 'mail',
    glyph: '✉',
    description: 'Send a note to someone offline',
  },
];

export default function SofiHubScreen({ onNavigate }: Props): React.JSX.Element {
  const go = useCallback(
    (target: string) => () => onNavigate?.(target),
    [onNavigate],
  );

  return (
    <ScreenFrame
      title="SoFi"
      onBack={() => onNavigate?.('home')}
      info={(
        <InfoTip title="SoFi">
          <p>Sovereign finance: vaults, trades and mail that settle directly between devices, with no exchange in the middle.</p>
          <p><b>Swap</b> trades one token for another at a vault&apos;s price. You see the exact amount you will get before you confirm; if the vault moves first, the trade is refused and you can quote again.</p>
          <p><b>Liquidity</b> puts two of your tokens into a vault. Every trade against it pays you the vault&apos;s fee, and you can take everything back at any time.</p>
          <p><b>Mail</b> sends a note to someone&apos;s key. They do not need to be online: it waits for them on the storage nodes until they claim it.</p>
        </InfoTip>
      )}
    >
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
