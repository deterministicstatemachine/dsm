// SPDX-License-Identifier: Apache-2.0
// A board's one-time setup for production, from the phone alone (owner, 2026-11-11: "Not everyone
// has a Mac. It has to be doable from the phone"). The board is plugged in with BOOTSEL held; the
// phone drives its own bootloader. Rust reads the board fresh each time and decides everything: which
// step is next, whether it may run, and what it wrote. This renders what Rust reports and carries the
// taps. A step that burns OTP takes the board's chip id typed back, its last four characters, so it
// only ever reaches the board the person is looking at.
import React, { useState } from 'react';
import { Notice } from './common/ScreenFrame';
import * as pb from '../proto/dsm_app_pb';
import { readBoardSetup, stepBoardSetup, type BoardSetup, type BoardSetupStep } from '../dsm/anchor';

type Stage = 'idle' | 'reading' | 'read' | 'confirming' | 'stepping';

const reason = (e: unknown) => (e instanceof Error ? e.message : String(e));

const mark = (step: BoardSetupStep) => (step.state === 'done' ? 'DONE' : step.state === 'next' ? 'NEXT' : 'LATER');

export default function AnchorBoardSetupPanel() {
  const [board, setBoard] = useState<BoardSetup | null>(null);
  const [stage, setStage] = useState<Stage>('idle');
  const [typed, setTyped] = useState('');
  /** The step being confirmed: the board's next, or the changed-image check before its first boot. */
  const [action, setAction] = useState<pb.AnchorBoardStepKind | null>(null);
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
  // Step 9's check is offered only when the board's next step is its first boot: Rust refuses it at
  // any other time.
  const checkOffered = next?.kind === pb.AnchorBoardStepKind.BOOT;
  const checking = action === pb.AnchorBoardStepKind.CHECK_CHANGED_IMAGE;
  const permanent = !checking && next?.permanent;

  const confirm = (kind: pb.AnchorBoardStepKind) => {
    setAction(kind);
    setTyped('');
    setStage('confirming');
  };

  const run = () => {
    if (!board || action === null) return;
    setStage('stepping');
    setError(null);
    stepBoardSetup(action, board.chipId)
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
              <span className="sb-label">Written and read back</span>
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
      {next && stage === 'confirming' && (
        <label className="sb-field">
          <span className="sb-label">
            {checking
              ? `This loads the image with one byte changed and starts the board: it must come back in BOOTSEL, and the signed image is loaded back. Tap Allow when Android asks again. Type the chip's last four characters (${lastFour}) to go on`
              : permanent
                ? `${next.name} can never be undone. Type the chip's last four characters (${lastFour}) to go on`
                : `Type the chip's last four characters (${lastFour}) to go on`}
          </span>
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
          <button type="button" className="sb-btn" onClick={() => confirm(next.kind)}>
            Next step…
          </button>
        )}
        {next && (stage === 'confirming' || stage === 'stepping') && (
          <button
            type="button"
            className="sb-btn sb-btn--primary"
            disabled={working || !confirmed}
            onClick={run}
          >
            {stage === 'stepping' ? 'Working…' : permanent ? 'Burn it' : 'Go on'}
          </button>
        )}
      </div>
      {checkOffered && board?.connected && stage === 'read' && (
        <div className="sb-actions" style={{ margin: 0 }}>
          <button
            type="button"
            className="sb-btn"
            data-testid="anchor-board-check"
            onClick={() => confirm(pb.AnchorBoardStepKind.CHECK_CHANGED_IMAGE)}
          >
            Check…
          </button>
        </div>
      )}
    </div>
  );
}
