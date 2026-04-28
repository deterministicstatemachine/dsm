// SPDX-License-Identifier: Apache-2.0
// DeFi hub — sub-menu reached from the home `DEFI` brick.  Keeps the
// home brick set short by tucking the lower-frequency DeFi flows
// (liquidity, mail) behind one extra tap.  Visual idiom matches the
// home menu (same `dsm-menu` + `home-brick` CSS classes).

import React, { useCallback } from 'react';

interface Props {
  onNavigate?: (screen: string) => void;
}

type Brick = {
  label: string;
  target: string;
  description: string;
};

const BRICKS: Brick[] = [
  {
    label: 'LIQUIDITY',
    target: 'liquidity',
    description: 'AMM vaults you own — reserves, fees, routing ad status, create new.',
  },
  {
    label: 'MAIL',
    target: 'mail',
    description: 'Posted-DLV inbox + compose to a Kyber public key.',
  },
];

export default function DefiHubScreen({ onNavigate }: Props): JSX.Element {
  const go = useCallback(
    (target: string) => () => onNavigate?.(target),
    [onNavigate],
  );

  return (
    <div className="enhanced-wallet-screen" style={{ position: 'relative' }}>
      <div className="wallet-header">
        <h2>DeFi</h2>
        <div className="header-buttons" style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            onClick={() => onNavigate?.('home')}
            className="cancel-button"
            style={{ fontSize: 11, padding: '4px 10px' }}
          >
            Back
          </button>
        </div>
      </div>

      <div className="dsm-menu" role="menu" aria-label="DeFi sub-menu">
        {BRICKS.map((brick) => (
          <div
            key={brick.target}
            className="dsm-menu-item home-brick"
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
            title={brick.description}
          >
            <span className="brick-label visible">{brick.label}</span>
          </div>
        ))}
      </div>

      <div style={{ marginTop: 12, padding: '0 12px', fontSize: 10, opacity: 0.6 }}>
        {BRICKS.map((brick) => (
          <div key={`hint-${brick.target}`} style={{ marginBottom: 4 }}>
            <strong>{brick.label}</strong> · {brick.description}
          </div>
        ))}
      </div>
    </div>
  );
}
