// SPDX-License-Identifier: Apache-2.0
// A new anchor is connected. Connecting it did nothing permanent; this offers its try-run, shows what
// the try-run went through and what installing would make permanent, and installs only when told to.
// On the trial image the install is a trial, with nothing permanent, and it says so.
// Rust and the anchor decide everything here; this renders what they report and carries the taps.
import React, { useState } from 'react';
import { Notice } from './common/ScreenFrame';
import { installAnchor, runAnchorTryRun, type AnchorStatus, type AnchorTryRun } from '../dsm/anchor';

type Props = {
  /**
   * Takes the anchor as the install reported it. The install's own answer says what a status read
   * afterwards does not: what an earlier trial's account held, when the install closed one.
   */
  onInstalled: (installed: AnchorStatus) => Promise<void>;
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
      .then((installed) => onInstalled(installed))
      .catch((e: unknown) => {
        setError(reason(e));
        setStage('tried');
      });
  };

  const working = stage === 'trying' || stage === 'installing';
  // What a production install alone still needs is shown apart from the steps: the anchor works
  // without it, and Rust offers no install until it is met.
  const unmet = run ? run.steps.filter((step) => step.production && !step.passed) : [];
  const steps = run ? run.steps.filter((step) => !(step.production && !step.passed)) : [];
  return (
    <div className="sb-field" data-testid="anchor-install">
      {run && (
        <ul data-testid="anchor-try-run-steps">
          {steps.map((step) => (
            <li key={step.name}>
              {step.passed ? 'OK' : 'FAILED'}: {step.name}
              {step.detail ? ` (${step.detail})` : ''}
            </li>
          ))}
        </ul>
      )}
      {unmet.length > 0 && (
        <>
          <span className="sb-label">Not ready for a production install</span>
          <ul data-testid="anchor-production-unmet">
            {unmet.map((step) => (
              <li key={step.name}>
                {step.name}
                {step.detail ? ` (${step.detail})` : ''}
              </li>
            ))}
          </ul>
        </>
      )}
      {run?.refused && <Notice kind="error">{run.refused}</Notice>}
      {run && run.permanent.length > 0 && (
        <>
          <span className="sb-label">
            {run.trial ? 'A trial install: what it leaves' : 'Installing makes these permanent'}
          </span>
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
            {run.trial ? 'Trial install…' : 'Install…'}
          </button>
        )}
        {run?.passed && (stage === 'confirming' || stage === 'installing') && (
          <button type="button" className="sb-btn sb-btn--primary" disabled={working} onClick={install}>
            {stage === 'installing' ? 'Installing…' : run.trial ? 'Yes, trial install' : 'Yes, make it permanent'}
          </button>
        )}
      </div>
    </div>
  );
}
