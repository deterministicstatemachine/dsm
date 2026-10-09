// SPDX-License-Identifier: Apache-2.0
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { FxCanvas } from './FxCanvas';
import { isFxEngineReady, loadFxEngine, type FxAnim } from './fxEngine';
import { useBackButton, useConfirmButton } from '../../hooks/useBackButton';
import { TokenMark } from '../TokenMark';

export type FxTone = 'good' | 'bad' | 'neutral';

export interface FxPopupProps {
  anim: FxAnim;
  /** Short heading under the animation, e.g. "Sent". */
  title: string;
  /** One line of context, e.g. "12.5 ERA to alice". */
  caption?: string;
  /** Amount caption drawn inside the confirm/fail scenes. */
  amount?: string;
  /** The token this scene is about; its coin sits beside the heading. */
  coin?: { ticker: string; iconUrl?: string };
  muted?: boolean;
  /** Close on its own a moment after the scene ends (default: not for `bad`). */
  autoClose?: boolean;
  tone?: FxTone;
  okLabel?: string;
  onClose: () => void;
}

/** Hard ceiling for an auto-closing popup, in case the engine never loads. */
const AUTO_CLOSE_MAX_MS = 11_000;
/** How long the final frame lingers before an auto-close. */
const LINGER_MS = 2_400;

/**
 * A small rounded "screen within the screen" that plays one FX scene.
 * Stays inside the StateBoy display; B / Escape / tap outside / OK close it,
 * tapping the picture replays it.
 */
export function FxPopup({
  anim,
  title,
  caption,
  amount,
  coin,
  muted = false,
  autoClose,
  tone = 'good',
  okLabel = 'OK',
  onClose,
}: FxPopupProps) {
  const [seq, setSeq] = useState(0);
  const [ended, setEnded] = useState(false);
  // null while the engine is still arriving: the element upgrades in place, so
  // it is rendered meanwhile. false means it never arrived, and the popup drops
  // to its words rather than showing an empty frame.
  const [engineReady, setEngineReady] = useState<boolean | null>(isFxEngineReady() ? true : null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const shouldAutoClose = autoClose ?? tone !== 'bad';

  const close = useCallback(() => onCloseRef.current(), []);
  useBackButton(true, close);
  useConfirmButton(true, close);

  useEffect(() => {
    dialogRef.current?.focus({ preventScroll: true });
  }, []);

  useEffect(() => {
    let alive = true;
    void loadFxEngine().then((ok) => { if (alive) setEngineReady(ok); });
    return () => { alive = false; };
  }, []);

  // Auto-close: a linger after the last frame, with a ceiling from open.
  useEffect(() => {
    if (!shouldAutoClose) return;
    const timer = setTimeout(close, AUTO_CLOSE_MAX_MS);
    return () => clearTimeout(timer);
  }, [shouldAutoClose, close, seq]);

  useEffect(() => {
    if (!shouldAutoClose || !ended) return;
    const timer = setTimeout(close, LINGER_MS);
    return () => clearTimeout(timer);
  }, [shouldAutoClose, ended, close]);

  const replay = useCallback(() => {
    setEnded(false);
    setSeq((n) => n + 1);
  }, []);

  return (
    <div className="sb-popover-backdrop sb-fx-backdrop" onClick={close} data-testid="fx-popup">
      <div
        ref={dialogRef}
        className={`sb-fx-window sb-fx-window--${tone}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        {engineReady !== false && (
          <div className="sb-fx-screen" onClick={replay} aria-hidden="true">
            <FxCanvas anim={anim} seq={seq} muted={muted} amount={amount} fit="fill" onEnd={() => setEnded(true)} />
            <span className="sb-fx-glass" />
          </div>
        )}
        <div className="sb-fx-foot">
          <div className="sb-fx-text">
            <div className="sb-fx-title" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              {coin ? <TokenMark ticker={coin.ticker} iconUrl={coin.iconUrl} className="sb-coin sb-coin--sm" /> : null}
              {title}
            </div>
            {caption ? <div className="sb-fx-caption">{caption}</div> : null}
          </div>
          {engineReady !== false && (
            <button type="button" className="sb-btn sb-fx-replay" onClick={replay} aria-label="Play again">
              {'\u21bb'}
            </button>
          )}
          <button type="button" className="sb-btn sb-btn--primary sb-fx-ok" onClick={close}>
            {okLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export default FxPopup;
