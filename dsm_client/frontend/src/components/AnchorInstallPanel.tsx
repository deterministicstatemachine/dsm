// SPDX-License-Identifier: Apache-2.0
// A new anchor is connected. Connecting it did nothing permanent; this offers its try-run, shows what
// the try-run went through and what installing would make permanent, and installs only when told to.
// Rust and the anchor decide everything here; this renders what they report and carries the taps.
import React, { useState } from 'react';
import { Notice } from './common/ScreenFrame';
import { installAnchor, runAnchorTryRun, type AnchorTryRun } from '../dsm/anchor';

type Props = {
  /** Reads the anchor again once it is installed. */
  onInstalled: () => Promise<void>;
};

/** Where the install stands. Only a try-run that passed offers it, and it takes a second tap. */
type Stage = 'idle' | 'trying' | 'tried' | 'confirming' | 'installing';

const reason = (e: unknown) => (e instanceof Error ? e.message : String(e));

export default function AnchorInstallPanel({ onInstalled }: Props) {
  const [run, setRun] = useState<AnchorTryRun | null>(null);
  const [stage, setStage] = useState<Stage>('idle');
  const [error, setError] = useState<string | null>(null);

  const tryIt = () => {
    setStage('trying');
    setError(null);
    runAnchorTryRun()
      .then((report) => {
        setRun(report);
        setStage('tried');
      })
      .catch((e: unknown) => {
        setError(reason(e));
        setStage('idle');
      });
  };

  const install = () => {
    setStage('installing');
    setError(null);
    installAnchor()
      .then(() => onInstalled())
      .catch((e: unknown) => {
        setError(reason(e));
        setStage('tried');
      });
  };

  const working = stage === 'trying' || stage === 'installing';
  return (
    <div className="sb-field" data-testid="anchor-install">
      {run && (
        <ul data-testid="anchor-try-run-steps">
          {run.steps.map((step) => (
            <li key={step.name}>
              {step.passed ? 'OK' : 'FAILED'}: {step.name}
              {step.detail ? ` (${step.detail})` : ''}
            </li>
          ))}
        </ul>
      )}
      {run?.refused && <Notice kind="error">{run.refused}</Notice>}
      {run && run.permanent.length > 0 && (
        <>
          <span className="sb-label">Installing makes these permanent</span>
          <ul data-testid="anchor-permanent">
            {run.permanent.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </>
      )}
      {error && <Notice kind="error">{error}</Notice>}
      <div className="sb-actions" style={{ margin: 0 }}>
        <button type="button" className="sb-btn" disabled={working} onClick={tryIt}>
          {stage === 'trying' ? 'Trying it…' : run ? 'Try it again' : 'Try the install'}
        </button>
        {run?.passed && stage === 'tried' && (
          <button type="button" className="sb-btn" onClick={() => setStage('confirming')}>
            Install…
          </button>
        )}
        {run?.passed && (stage === 'confirming' || stage === 'installing') && (
          <button type="button" className="sb-btn sb-btn--primary" disabled={working} onClick={install}>
            {stage === 'installing' ? 'Installing…' : 'Yes, make it permanent'}
          </button>
        )}
      </div>
    </div>
  );
}
