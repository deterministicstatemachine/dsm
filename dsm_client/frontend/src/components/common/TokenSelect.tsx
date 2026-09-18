// SPDX-License-Identifier: Apache-2.0
// A token picker that can show each token's coin.
//
// A native <select> cannot: an <option> renders text and nothing else, on every
// platform. So this is a button plus a listbox, styled like the other inputs,
// with the coin sitting immediately left of each ticker — in the closed button
// and in every row of the open list.
import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import { TokenMark } from '../TokenMark';
import { useBackButton } from '../../hooks/useBackButton';

export type TokenOption = {
  /** What onChange reports: a token id, or an anchor where identity is the anchor. */
  value: string;
  ticker: string;
  iconUrl?: string;
  /** Small trailing text, e.g. an anchor fingerprint. */
  note?: string;
};

type Props = {
  id?: string;
  /** Accessible name for the control. */
  label: string;
  value: string;
  options: TokenOption[];
  onChange: (value: string) => void;
  /** Shown when nothing is selected. */
  placeholder?: string;
  className?: string;
  disabled?: boolean;
};

export function TokenSelect({ id, label, value, options, onChange, placeholder = 'Select…', className, disabled }: Props): JSX.Element {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const listId = `${useId()}-list`;
  const selected = options.find((o) => o.value === value) ?? null;

  const close = useCallback(() => setOpen(false), []);
  useBackButton(open, close);

  // A tap anywhere else puts the list away.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: Event) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', onDown, true);
    return () => document.removeEventListener('pointerdown', onDown, true);
  }, [open]);

  const pick = useCallback((next: string) => {
    onChange(next);
    setOpen(false);
    buttonRef.current?.focus();
  }, [onChange]);

  const onListKeyDown = (e: React.KeyboardEvent) => {
    if (options.length === 0) return;
    const index = options.findIndex((o) => o.value === value);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      e.stopPropagation();
      const step = e.key === 'ArrowDown' ? 1 : -1;
      const next = options[(index + step + options.length) % options.length];
      onChange(next.value);
    }
  };

  return (
    <div className={`sb-tokensel${className ? ` ${className}` : ''}`} ref={rootRef}>
      <button
        ref={buttonRef}
        id={id}
        type="button"
        className="sb-input sb-tokensel__button"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
      >
        {selected ? (
          <>
            <TokenMark ticker={selected.ticker} iconUrl={selected.iconUrl} className="sb-coin sb-coin--sm" />
            <span className="sb-tokensel__ticker">{selected.ticker}</span>
          </>
        ) : (
          <span className="sb-tokensel__ticker sb-tokensel__ticker--empty">{placeholder}</span>
        )}
        <span className="sb-tokensel__caret" aria-hidden="true">{'▾'}</span>
      </button>

      {open && (
        <ul className="sb-tokensel__list" id={listId} role="listbox" aria-label={label} tabIndex={-1} onKeyDown={onListKeyDown}>
          {options.length === 0 ? (
            <li className="sb-tokensel__empty">Nothing to pick</li>
          ) : (
            options.map((o) => (
              <li key={o.value}>
                <button
                  type="button"
                  role="option"
                  aria-selected={o.value === value}
                  className={`sb-tokensel__opt${o.value === value ? ' is-selected' : ''}`}
                  onClick={() => pick(o.value)}
                >
                  <TokenMark ticker={o.ticker} iconUrl={o.iconUrl} className="sb-coin sb-coin--sm" />
                  <span className="sb-tokensel__ticker">{o.ticker}</span>
                  {o.note ? <span className="sb-tokensel__note">{o.note}</span> : null}
                </button>
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  );
}

export default TokenSelect;
