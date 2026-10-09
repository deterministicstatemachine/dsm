// SPDX-License-Identifier: Apache-2.0
// The Modern skin has no animations: a cue (sent, not sent, …) is a plain
// pop-up with its words, its amount and OK.

import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { FxPopup } from '../../fx/FxPopup';
import { appRuntimeStore } from '../../../runtime/appRuntimeStore';

describe('a cue in the Modern skin', () => {
  it('is a plain pop-up with no scene, and OK closes it', () => {
    appRuntimeStore.setSkin('modern');
    const closed: string[] = [];
    render(
      <FxPopup anim="confirm" title="Sent" caption="12.5 ERA to alice" amount="-12.5 ERA" tone="bad" onClose={() => closed.push('closed')} />,
    );
    const dialog = screen.getByRole('dialog', { name: 'Sent' });
    expect(dialog).toHaveTextContent('12.5 ERA to alice');
    expect(dialog).toHaveTextContent('-12.5 ERA');
    expect(dialog.querySelector('fx-canvas, canvas, .sb-fx-screen')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Play again' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    expect(closed).toEqual(['closed']);
  });
});
