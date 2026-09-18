// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { FxPopup } from '../FxPopup';

function withShellButton() {
  const b = document.createElement('button');
  b.id = 'button-b';
  b.className = 'button-b';
  document.body.appendChild(b);
  return b;
}

describe('FxPopup', () => {
  afterEach(() => {
    document.getElementById('button-b')?.remove();
  });

  it('plays the scene inside a labelled dialog with its title and caption', () => {
    render(<FxPopup anim="confirm" title="Sent" caption="12.5 ERA to alice" onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog', { name: 'Sent' });
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText('12.5 ERA to alice')).toBeInTheDocument();
    expect(dialog.querySelector('fx-canvas')?.getAttribute('anim')).toBe('confirm');
    expect(document.activeElement).toBe(dialog);
  });

  it('stays inside the screen host rather than covering the whole page', () => {
    const { container } = render(<FxPopup anim="vault" title="Pool created" onClose={() => undefined} />);
    const backdrop = container.querySelector('.sb-fx-backdrop');
    expect(backdrop).toBeInTheDocument();
    // .sb-popover-backdrop is position:absolute within .stateboy-screen-host.
    expect(backdrop).toHaveClass('sb-popover-backdrop');
  });

  it('closes on OK, on the backdrop, and on the shell B button', () => {
    const b = withShellButton();
    const onClose = jest.fn();
    const { container } = render(<FxPopup anim="confirm" title="Sent" onClose={onClose} />);

    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    expect(onClose).toHaveBeenCalledTimes(1);

    fireEvent.click(container.querySelector('.sb-fx-backdrop') as Element);
    expect(onClose).toHaveBeenCalledTimes(2);

    fireEvent.click(b);
    expect(onClose).toHaveBeenCalledTimes(3);

    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(4);
  });

  it('does not close when the dialog itself is tapped; tapping the picture replays it', () => {
    const onClose = jest.fn();
    const { container } = render(<FxPopup anim="pair" title="Paired" onClose={onClose} />);
    fireEvent.click(screen.getByRole('dialog', { name: 'Paired' }));
    expect(onClose).not.toHaveBeenCalled();

    const screenEl = container.querySelector('.sb-fx-screen') as Element;
    const before = container.querySelector('fx-canvas')?.getAttribute('seq');
    fireEvent.click(screenEl);
    expect(container.querySelector('fx-canvas')?.getAttribute('seq')).not.toBe(before);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('auto-closes a good scene once it ends, but leaves a bad one up', () => {
    jest.useFakeTimers();
    try {
      const good = jest.fn();
      const { container, unmount } = render(<FxPopup anim="confirm" title="Sent" onClose={good} />);
      act(() => {
        (container.querySelector('fx-canvas') as Element).dispatchEvent(new CustomEvent('fx-end'));
      });
      expect(good).not.toHaveBeenCalled();
      act(() => { jest.advanceTimersByTime(2500); });
      expect(good).toHaveBeenCalledTimes(1);
      unmount();

      const bad = jest.fn();
      const second = render(<FxPopup anim="fail" title="Not sent" tone="bad" onClose={bad} />);
      act(() => {
        (second.container.querySelector('fx-canvas') as Element).dispatchEvent(new CustomEvent('fx-end'));
      });
      act(() => { jest.advanceTimersByTime(60_000); });
      expect(bad).not.toHaveBeenCalled();
    } finally {
      jest.useRealTimers();
    }
  });

  it('passes the amount caption and mute flag to the engine', () => {
    const { container } = render(
      <FxPopup anim="confirm" title="Sent" amount="-12.5 ERA" muted onClose={() => undefined} />,
    );
    const el = container.querySelector('fx-canvas') as Element;
    expect(el.getAttribute('amount')).toBe('-12.5 ERA');
    expect(el.getAttribute('muted')).toBe('1');
  });
});
