// SPDX-License-Identifier: Apache-2.0
// A board's one-time setup for production, from the phone alone (owner, 2026-11-11: "Not everyone
// has a Mac. It has to be doable from the phone"). The board is plugged in with BOOTSEL held; the
// phone drives its own bootloader. Rust reads the board fresh each time and decides everything: which
// step is next, what else the board takes now, whether it may run, and what it wrote. This renders
// what Rust reports and carries the taps. A step takes the board's chip id typed back, its last four
// characters, so it only ever reaches the board the person is looking at.
import React, { useState } from 'react';
import { Notice } from './common/ScreenFrame';
import * as pb from '../proto/dsm_app_pb';
import { readBoardSetup, stepBoardSetup, type BoardSetup, type BoardSetupStep } from '../dsm/anchor';

type Stage = 'idle' | 'reading' | 'read' | 'confirming' | 'stepping';

const reason = (e: unknown) => (e instanceof Error ? e.message : String(e));

const MARKS: Record<BoardSetupStep['state'], string> = {
  done: 'DONE',
  next: 'NEXT',
  later: 'LATER',
  blocked: 'BLOCKED',
};
const mark = (step: BoardSetupStep) => MARKS[step.state];

/** The button for each action Rust offers besides the next step, and its test id. */
const OFFERS = new Map<pb.AnchorBoardStepKind, { label: string; testId: string }>([
  [pb.AnchorBoardStepKind.PREPARE_CHIP, { label: 'Prepare the chip…', testId: 'anchor-board-prepare' }],
  [pb.AnchorBoardStepKind.TRIAL_IMAGE, { label: 'Start the trial image…', testId: 'anchor-board-trial' }],
  [pb.AnchorBoardStepKind.CHECK_CHANGED_IMAGE, { label: 'Check…', testId: 'anchor-board-check' }],
]);

/** What the person is told before a step or an action runs, ending with the chip's last four to type. */
function confirmText(action: BoardSetupStep, lastFour: string): string {
  const typeBack = `Type the chip's last four characters (${lastFour}) to go on`;
  switch (action.kind) {
    case pb.AnchorBoardStepKind.CHECK_CHANGED_IMAGE:
      return `This loads the image with one byte changed and starts the board: it must come back in BOOTSEL, and the signed image is loaded back. Tap Allow when Android asks again. ${typeBack}`;
    case pb.AnchorBoardStepKind.LOCK_PAGES:
      return `This loads a one-time image that sets the two locks and starts the board; it comes back in BOOTSEL and the signed image is loaded back. Tap Allow when Android asks again. ${action.name} can never be undone. ${typeBack}`;
    case pb.AnchorBoardStepKind.PREPARE_CHIP:
      return `This loads the prepare image and starts the board. On a test part it turns the chip's random-number self-test on, for good, and erases any key the chip made before; then the phone asks the board how it went. Tap Allow when Android asks. ${action.name} can never be undone. ${typeBack}`;
    case pb.AnchorBoardStepKind.TRIAL_IMAGE:
      return `This loads the trial image and starts the board, for its try-run on this very board: nothing is burned. Tap Allow when Android asks. ${typeBack}`;
    default:
      return action.permanent ? `${action.name} can never be undone. ${typeBack}` : typeBack;
  }
}

/** The button that runs the confirmed step or action. */
function goLabel(action: BoardSetupStep): string {
  if (action.kind === pb.AnchorBoardStepKind.PREPARE_CHIP) return 'Prepare it';
  return action.permanent ? 'Burn it' : 'Go on';
}

export default function AnchorBoardSetupPanel() {
  const [board, setBoard] = useState<BoardSetup | null>(null);
  const [stage, setStage] = useState<Stage>('idle');
  const [typed, setTyped] = useState('');
  /** What is being confirmed: the board's next step, or an action Rust offers besides it. */
  const [action, setAction] = useState<BoardSetupStep | null>(null);
  const [error, setError] = useState<string | null>(null);

  const read = () => {
    setStage('reading');
    setError(null);
    setTyped('');
    readBoardSetup()
      .then((reading) => {
        setBoard(reading);
        setStage('read');
      })
      .catch((e: unknown) => {
        setError(reason(e));
        setStage('idle');
      });
  };

  const next = board?.steps.find((step) => step.state === 'next');

  const confirm = (chosen: BoardSetupStep) => {
    setAction(chosen);
    setTyped('');
    setStage('confirming');
  };

  const run = () => {
    if (!board || action === null) return;
    setStage('stepping');
    setError(null);
    stepBoardSetup(action.kind, board.chipId)
      .then((after) => {
        setBoard(after);
        setTyped('');
        setStage('read');
      })
      .catch((e: unknown) => {
        setError(reason(e));
        setStage('read');
      });
  };

  const working = stage === 'reading' || stage === 'stepping';
  const lastFour = board ? board.chipId.slice(-4) : '';
  const confirmed = typed.trim().toUpperCase() === lastFour.toUpperCase() && lastFour.length === 4;
  const offered = board?.connected && stage === 'read' ? board.offered : [];
  return (
    <div className="sb-field" data-testid="anchor-board-setup">
      <span className="sb-label">Production setup, from this phone</span>
      <p>
        Hold the board&apos;s BOOTSEL button while plugging it into this phone, then read it. Each step
        is checked on the board before it runs and read back after.
      </p>
      {board && (
        <>
          {board.chipId && (
            <div className="sb-kv">
              <span className="sb-kv__k">Chip</span>
              <span className="sb-kv__v sb-kv__v--mono" data-testid="anchor-board-chip">{board.chipId}</span>
            </div>
          )}
          {board.release && <p data-testid="anchor-board-release">{board.release}</p>}
          {board.steps.length > 0 && (
            <ul data-testid="anchor-board-steps">
              {board.steps.map((step) => (
                <li key={step.kind}>
                  {mark(step)}: {step.name}
                  {step.permanent ? ' (permanent)' : ''}
                </li>
              ))}
            </ul>
          )}
          {board.found.length > 0 && (
            <ul data-testid="anchor-board-found">
              {board.found.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          )}
          {board.written.length > 0 && (
            <>
              <span className="sb-label">The last step</span>
              <ul data-testid="anchor-board-written">
                {board.written.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          )}
          {board.refused && <Notice kind="error">{board.refused}</Notice>}
          {board.done && <Notice kind="info">Every step is done: install the board from its wallet.</Notice>}
        </>
      )}
      {error && <Notice kind="error">{error}</Notice>}
      {action && stage === 'confirming' && (
        <label className="sb-field">
          <span className="sb-label">{confirmText(action, lastFour)}</span>
          <input
            className="sb-input"
            data-testid="anchor-board-confirm"
            value={typed}
            autoCapitalize="characters"
            onChange={(e) => setTyped(e.target.value)}
          />
        </label>
      )}
      <div className="sb-actions" style={{ margin: 0 }}>
        <button type="button" className="sb-btn" disabled={working} onClick={read}>
          {stage === 'reading' ? 'Reading…' : board ? 'Read again' : 'Read board'}
        </button>
        {next && board?.connected && stage === 'read' && (
          <button type="button" className="sb-btn" onClick={() => confirm(next)}>
            Next step…
          </button>
        )}
        {action && (stage === 'confirming' || stage === 'stepping') && (
          <button
            type="button"
            className="sb-btn sb-btn--primary"
            disabled={working || !confirmed}
            onClick={run}
          >
            {stage === 'stepping' ? 'Working…' : goLabel(action)}
          </button>
        )}
      </div>
      {offered.length > 0 && (
        <div className="sb-actions" style={{ margin: 0 }}>
          {offered.map((offer) => {
            const shown = OFFERS.get(offer.kind);
            return (
              <button
                key={offer.kind}
                type="button"
                className="sb-btn"
                data-testid={shown?.testId}
                title={offer.name}
                onClick={() => confirm(offer)}
              >
                {shown?.label ?? `${offer.name}…`}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
