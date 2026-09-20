// SPDX-License-Identifier: Apache-2.0
// Its own file: the engine loader caches its one attempt per module registry,
// and this test needs that attempt to be the one it controls.
import React from 'react';
import { act, render, screen } from '@testing-library/react';
import { FxPopup } from '../FxPopup';

describe('FxPopup without the engine', () => {
  it('falls back to its words when the engine never arrives', async () => {
    // jsdom does not execute the injected script, so `fx-canvas` never
    // registers and the loader gives up when its timeout elapses.
    jest.useFakeTimers();
    try {
      const { container } = render(
        <FxPopup anim="confirm" title="Sent" caption="12.5 ERA to alice" onClose={() => undefined} />,
      );
      expect(container.querySelector('.sb-fx-screen')).toBeInTheDocument();

      await act(async () => { jest.advanceTimersByTime(8_100); });

      expect(container.querySelector('.sb-fx-screen')).not.toBeInTheDocument();
      expect(screen.getByRole('dialog', { name: 'Sent' })).toBeInTheDocument();
      expect(screen.getByText('12.5 ERA to alice')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'OK' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Play again' })).not.toBeInTheDocument();
    } finally {
      jest.useRealTimers();
    }
  });
});
