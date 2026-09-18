// SPDX-License-Identifier: Apache-2.0
import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { useBackButton } from '../useBackButton';
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
