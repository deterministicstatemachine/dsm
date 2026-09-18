// SPDX-License-Identifier: Apache-2.0
// ScreenFrame — the one layout every non-home StateBoy screen shares.
//
// The screen is roughly 280×420 CSS px on a phone, so a screen cannot afford a
// tall header, a five-word tab bar or 20px of padding on each side. The frame
// gives each screen a 40px header (back chevron, title, up to two icon
// actions), an optional segmented tab strip, and one scrolling body. Screens
// put their content in the body and nothing else; styles live in screen.css.
import React from 'react';

type FrameProps = {
  title: string;
  /** Renders a back chevron in the header. B on the shell does the same. */
  onBack?: () => void;
  /** An InfoTip rendered beside the title. */
  info?: React.ReactNode;
  /** Icon buttons for the right side of the header. */
  actions?: React.ReactNode;
  /** A `ScreenTabs` strip, rendered under the header. */
  tabs?: React.ReactNode;
  /** Notices that must stay visible while the body scrolls. */
  banner?: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  headRef?: React.Ref<HTMLDivElement>;
  bodyRef?: React.Ref<HTMLDivElement>;
  children: React.ReactNode;
};

export function ScreenFrame({
  title,
  onBack,
  info,
  actions,
  tabs,
  banner,
  className,
  bodyClassName,
  headRef,
  bodyRef,
  children,
}: FrameProps): JSX.Element {
  return (
    <div className={`sb-screen${className ? ` ${className}` : ''}`}>
      <div className="sb-screen__head" ref={headRef}>
        {onBack ? (
          <button type="button" className="sb-icon-btn" onClick={onBack} aria-label="Back" title="Back">
            {'‹'}
          </button>
        ) : null}
        <h2 className="sb-screen__title">{title}</h2>
        {info}
        {actions ? <div className="sb-screen__actions">{actions}</div> : null}
      </div>
      {tabs}
      {banner}
      <div className={`sb-screen__body${bodyClassName ? ` ${bodyClassName}` : ''}`} ref={bodyRef}>
        {children}
      </div>
    </div>
  );
}

type TabsProps<T extends string> = {
  tabs: ReadonlyArray<{ id: T; label: string }>;
  active: T;
  onChange: (id: T) => void;
  ariaLabel?: string;
};

/** Segmented tab strip. Plain buttons, so keyboard and D-pad handling stay as they are. */
export function ScreenTabs<T extends string>({ tabs, active, onChange, ariaLabel }: TabsProps<T>): JSX.Element {
  return (
    <div className="sb-tabs" aria-label={ariaLabel}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          className={`sb-tabs__tab${tab.id === active ? ' active' : ''}`}
          aria-current={tab.id === active ? 'page' : undefined}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

type DisclosureProps = {
  summary: React.ReactNode;
  defaultOpen?: boolean;
  className?: string;
  children: React.ReactNode;
};

/** Folded by default: what a first-time user does not need to see. */
export function Disclosure({ summary, defaultOpen, className, children }: DisclosureProps): JSX.Element {
  return (
    <details className={`sb-details${className ? ` ${className}` : ''}`} open={defaultOpen}>
      <summary>{summary}</summary>
      <div className="sb-details__body">{children}</div>
    </details>
  );
}

type NoticeProps = {
  kind?: 'info' | 'error' | 'success';
  onClose?: () => void;
  banner?: boolean;
  role?: string;
  children: React.ReactNode;
};

export function Notice({ kind = 'info', onClose, banner, role, children }: NoticeProps): JSX.Element {
  const cls = ['sb-notice'];
  if (kind === 'error') cls.push('sb-notice--error');
  if (kind === 'success') cls.push('sb-notice--success');
  if (banner) cls.push('sb-notice--banner');
  return (
    <div className={cls.join(' ')} role={role ?? (kind === 'error' ? 'alert' : 'status')}>
      <span>{children}</span>
      {onClose ? (
        <button type="button" className="sb-notice__close" onClick={onClose} aria-label="Dismiss">
          {'×'}
        </button>
      ) : null}
    </div>
  );
}

/** Middle-truncate an address or id so both ends stay readable. */
export function middleTruncate(value: string, head = 10, tail = 8): string {
  if (!value) return '—';
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Scroll the nearest scrolling ancestor of `el` back to the top. */
export function scrollToTop(el: HTMLElement | null): void {
  let node: HTMLElement | null = el;
  while (node) {
    if (node.scrollHeight > node.clientHeight && node.scrollTop > 0) {
      node.scrollTop = 0;
    }
    node = node.parentElement;
  }
}
