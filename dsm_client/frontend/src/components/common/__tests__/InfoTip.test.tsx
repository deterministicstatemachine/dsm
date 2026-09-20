// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { InfoTip } from '../InfoTip';

function renderTip() {
  // The shell's physical B button lives outside React; give the hook one to bind.
  const b = document.createElement('button');
  b.id = 'button-b';
  b.className = 'button-b';
  document.body.appendChild(b);
  const utils = render(
    <InfoTip title="Swap" label="About swapping">
      <p>Trades one token for another.</p>
    </InfoTip>,
  );
  return { ...utils, b };
}

describe('InfoTip', () => {
  afterEach(() => {
    document.getElementById('button-b')?.remove();
  });

  it('shows only the i until tapped, then a dialog with the text', () => {
    renderTip();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'About swapping' }));
    const dialog = screen.getByRole('dialog', { name: 'Swap' });
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText('Trades one token for another.')).toBeInTheDocument();
    expect(document.activeElement).toBe(dialog);
  });

  it('closes on ×, on OK, on the backdrop, and returns focus to the i', () => {
    renderTip();
    const trigger = screen.getByRole('button', { name: 'About swapping' });

    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(trigger);

    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole('dialog').parentElement!);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('closes on the shell B button and on Escape, without leaving the screen', () => {
    const { b } = renderTip();
    const appBack = jest.fn();
    // The app-level handlers: bubble-phase keydown on document, plain click on #button-b.
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') appBack(); });
    b.addEventListener('click', appBack);

    fireEvent.click(screen.getByRole('button', { name: 'About swapping' }));
    fireEvent.click(b);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(appBack).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'About swapping' }));
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(appBack).not.toHaveBeenCalled();

    // With nothing open, B and Escape reach the app again.
    fireEvent.click(b);
    fireEvent.keyDown(document.body, { key: 'Escape' });
    expect(appBack).toHaveBeenCalledTimes(2);
  });

  it('does not activate a clickable card it sits in', () => {
    const onCard = jest.fn();
    render(
      <div role="button" tabIndex={0} onClick={onCard}>
        <InfoTip title="Vaults">
          <p>About vaults.</p>
        </InfoTip>
      </div>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'About Vaults' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onCard).not.toHaveBeenCalled();
  });
});
