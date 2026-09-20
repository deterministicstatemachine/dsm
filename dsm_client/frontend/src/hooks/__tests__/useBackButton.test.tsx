// SPDX-License-Identifier: Apache-2.0
import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { useBackButton, useConfirmButton } from '../useBackButton';
import { InfoTip } from '../../components/common/InfoTip';

function SubView({ onClose }: { onClose: () => void }) {
  useBackButton(true, onClose);
  return (
    <div>
      <span>Deposit view</span>
      <InfoTip title="Deposit">
        <p>About deposits.</p>
      </InfoTip>
    </div>
  );
}

function Screen() {
  const [open, setOpen] = useState(true);
  return open ? <SubView onClose={() => setOpen(false)} /> : <span>Main view</span>;
}

describe('useBackButton', () => {
  let b: HTMLButtonElement;
  const appBack = jest.fn();
  beforeEach(() => {
    appBack.mockClear();
    b = document.createElement('button');
    b.id = 'button-b';
    b.className = 'button-b';
    document.body.appendChild(b);
    b.addEventListener('click', appBack);
  });
  afterEach(() => {
    b.remove();
  });

  it('B closes the innermost thing first: popup, then sub-view, then reaches the app', () => {
    render(<Screen />);
    fireEvent.click(screen.getByRole('button', { name: 'About Deposit' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    fireEvent.click(b);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByText('Deposit view')).toBeInTheDocument();
    expect(appBack).not.toHaveBeenCalled();

    fireEvent.click(b);
    expect(screen.getByText('Main view')).toBeInTheDocument();
    expect(appBack).not.toHaveBeenCalled();

    fireEvent.click(b);
    expect(appBack).toHaveBeenCalledTimes(1);
  });

  it('A closes the popup instead of reaching the list behind it', () => {
    // The screen underneath binds A the way useDpadNav does: document capture.
    const listSelect = jest.fn((e: Event) => e.stopImmediatePropagation());
    const a = document.createElement('button');
    a.id = 'button-a';
    a.className = 'button-a';
    document.body.appendChild(a);
    document.addEventListener('keydown', listSelect as EventListener, true);
    a.addEventListener('click', listSelect as EventListener, true);
    try {
      render(<Screen />);
      fireEvent.click(screen.getByRole('button', { name: 'About Deposit' }));
      expect(screen.getByRole('dialog')).toBeInTheDocument();

      fireEvent.keyDown(document.body, { key: 'Enter' });
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(listSelect).not.toHaveBeenCalled();
      expect(screen.getByText('Deposit view')).toBeInTheDocument();

      // Closed again: A now belongs to the screen underneath.
      fireEvent.keyDown(document.body, { key: 'Enter' });
      expect(listSelect).toHaveBeenCalledTimes(1);

      fireEvent.click(screen.getByRole('button', { name: 'About Deposit' }));
      fireEvent.click(a);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(listSelect).toHaveBeenCalledTimes(1);
    } finally {
      document.removeEventListener('keydown', listSelect as EventListener, true);
      a.remove();
    }
  });

  it('A presses the popup control that holds focus, and reaches nothing behind it', () => {
    const listSelect = jest.fn((e: Event) => e.stopImmediatePropagation());
    document.addEventListener('keydown', listSelect as EventListener, true);
    const replay = jest.fn();
    const confirm = jest.fn();
    function Popup() {
      useConfirmButton(true, confirm);
      return (
        <div role="dialog" aria-label="Sent" tabIndex={-1}>
          <button type="button" onClick={replay}>Play again</button>
        </div>
      );
    }
    try {
      render(<Popup />);
      const btn = screen.getByRole('button', { name: 'Play again' });
      btn.focus();
      fireEvent.keyDown(btn, { key: 'Enter' });
      expect(replay).toHaveBeenCalledTimes(1);
      expect(confirm).not.toHaveBeenCalled();
      expect(listSelect).not.toHaveBeenCalled();

      screen.getByRole('dialog').focus();
      fireEvent.keyDown(document.body, { key: 'Enter' });
      expect(confirm).toHaveBeenCalledTimes(1);
      expect(listSelect).not.toHaveBeenCalled();
    } finally {
      document.removeEventListener('keydown', listSelect as EventListener, true);
    }
  });

  it('A leaves typing alone while a popup is open', () => {
    const pressed = jest.fn();
    function Typing() {
      useConfirmButton(true, pressed);
      return <input aria-label="amount" />;
    }
    render(<Typing />);
    fireEvent.keyDown(screen.getByLabelText('amount'), { key: 'Enter' });
    expect(pressed).not.toHaveBeenCalled();
    fireEvent.keyDown(document.body, { key: 'Enter' });
    expect(pressed).toHaveBeenCalledTimes(1);
  });

  it('Escape behaves the same as B', () => {
    render(<Screen />);
    fireEvent.click(screen.getByRole('button', { name: 'About Deposit' }));
    fireEvent.keyDown(document.body, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByText('Deposit view')).toBeInTheDocument();
    fireEvent.keyDown(document.body, { key: 'Escape' });
    expect(screen.getByText('Main view')).toBeInTheDocument();
  });
});
