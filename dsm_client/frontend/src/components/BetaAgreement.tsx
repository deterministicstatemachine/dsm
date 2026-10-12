// SPDX-License-Identifier: Apache-2.0
// The first screen of a phone that has not accepted the beta agreement: what
// this pre-release wallet is and is not, each point ticked on its own, and
// "I agree" once all are. It covers the whole screen and comes before the
// choice of look and everything else. Its look is its own: no skin is chosen
// yet when it shows.

import React, { useState } from 'react';
import { createPortal } from 'react-dom';
import { AGREEMENT_POINTS } from '../domain/betaAgreement';
import { acceptAgreement } from '../runtime/skinPreferences';
import { versionLabel } from '../appVersion';
import '../styles/betaAgreement.css';

export default function BetaAgreement(): React.JSX.Element {
  const [ticked, setTicked] = useState<ReadonlySet<string>>(new Set());
  const [keeping, setKeeping] = useState<'idle' | 'keeping'>('idle');
  const [problem, setProblem] = useState<string | null>(null);
  const all = ticked.size === AGREEMENT_POINTS.length;

  const toggle = (id: string) => {
    const next = new Set(ticked);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setTicked(next);
  };

  const agree = () => {
    if (!all) return;
    setKeeping('keeping');
    acceptAgreement().then(
      () => setProblem(null),
      (e: unknown) => {
        setKeeping('idle');
        setProblem(e instanceof Error ? e.message : String(e));
      },
    );
  };

  return createPortal(
    <div className="ba-page" role="dialog" aria-labelledby="ba-title">
      <div className="ba-inner">
        <p className="ba-version">{versionLabel()}</p>
        <h1 id="ba-title" className="ba-title">Before you start</h1>
        <p className="ba-lead">
          DSM is in beta. Read each point and tick it to show you understand. You can only continue once every point is ticked.
        </p>
        <ul className="ba-points">
          {AGREEMENT_POINTS.map((point) => (
            <li key={point.id}>
              <label className="ba-point">
                <input type="checkbox" checked={ticked.has(point.id)} onChange={() => toggle(point.id)} />
                <span className="ba-box" aria-hidden />
                <span className="ba-text">{point.text}</span>
              </label>
            </li>
          ))}
        </ul>
        <button type="button" className="ba-agree" disabled={!all || keeping === 'keeping'} onClick={agree}>
          {keeping === 'keeping' ? 'Saving…' : 'I understand and agree'}
        </button>
        <p className="ba-count" aria-live="polite">{all ? 'All points ticked.' : `${ticked.size} of ${AGREEMENT_POINTS.length} ticked`}</p>
        {problem !== null ? <p className="ba-problem" role="alert">{problem}</p> : null}
      </div>
    </div>,
    document.body,
  );
}
