// SPDX-License-Identifier: Apache-2.0
// InfoTip — a small round "i" that opens an in-screen popup holding the
// explanation a screen used to spell out in a paragraph. The screen keeps its
// room; whoever wants the why taps the i, reads, and closes it (tap outside,
// the ×, OK, or the shell's B button).
import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import { useBackButton } from '../../hooks/useBackButton';

type Props = {
  /** Popup heading. */
  title: string;
  /** Accessible name of the i button; defaults to "About <title>". */
  label?: string;
  className?: string;
  children: React.ReactNode;
};

export function InfoTip({ title, label, className, children }: Props): JSX.Element {
  const [open, setOpen] = useState(false);
  const wasOpenRef = useRef(false);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const titleId = `${useId()}-title`;

  const close = useCallback(() => setOpen(false), []);
  useBackButton(open, close);

  // Focus follows the popup in, and returns to the i on the way out.
  useEffect(() => {
    if (open) {
      wasOpenRef.current = true;
      dialogRef.current?.focus();
    } else if (wasOpenRef.current) {
      wasOpenRef.current = false;
      buttonRef.current?.focus();
    }
  }, [open]);

  return (
    <>
      <button
        ref={buttonRef}
        type="button"
        className={`sb-info${className ? ` ${className}` : ''}`}
        aria-label={label ?? `About ${title}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={(e) => { e.stopPropagation(); setOpen(true); }}
      >
        i
      </button>
      {open && (
        <div className="sb-popover-backdrop" onClick={(e) => { e.stopPropagation(); close(); }}>
          <div
            ref={dialogRef}
            className="sb-popover"
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="sb-popover__head">
              <span className="sb-info sb-info--static" aria-hidden="true">i</span>
              <h3 id={titleId} className="sb-popover__title">{title}</h3>
              <button type="button" className="sb-popover__close" onClick={close} aria-label="Close">{'×'}</button>
            </div>
            <div className="sb-popover__body">{children}</div>
            <button type="button" className="sb-btn sb-btn--primary sb-btn--block sb-popover__ok" onClick={close}>OK</button>
          </div>
        </div>
      )}
    </>
  );
}
