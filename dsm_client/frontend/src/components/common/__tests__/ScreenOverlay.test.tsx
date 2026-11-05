// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { render, screen } from '@testing-library/react';
import { ScreenOverlay } from '../ScreenOverlay';

function Screen({ dialog }: { dialog: 'open' | 'shut' }) {
  return (
    <div className="sb-screen">
      <div className="sb-screen__body">
        {dialog === 'open' ? <ScreenOverlay><div role="dialog">asked</div></ScreenOverlay> : null}
      </div>
    </div>
  );
}

describe('ScreenOverlay', () => {
  // MUTATION CONTROL: rendering the children in place turns this red.
  it('puts a dialog opened in the body on the screen, outside the scrolling body', () => {
    const { rerender, container } = render(<Screen dialog="shut" />);
    rerender(<Screen dialog="open" />);
    const dialog = screen.getByRole('dialog');
    expect(dialog.parentElement).toBe(container.querySelector('.sb-screen'));
    expect(dialog.closest('.sb-screen__body')).toBeNull();
  });

  it('puts it on the screen it is told to, as Modern asks for its whole app', () => {
    function App({ sheet }: { sheet: 'open' | 'shut' }) {
      return (
        <div className="s-app">
          <main className="s-body">
            {sheet === 'open' ? <ScreenOverlay on=".s-app"><div role="dialog">asked</div></ScreenOverlay> : null}
          </main>
        </div>
      );
    }
    const { rerender, container } = render(<App sheet="shut" />);
    rerender(<App sheet="open" />);
    const dialog = screen.getByRole('dialog');
    expect(dialog.parentElement).toBe(container.querySelector('.s-app'));
    expect(dialog.closest('.s-body')).toBeNull();
  });

  it('takes the dialog away again when it closes', () => {
    const { rerender } = render(<Screen dialog="shut" />);
    rerender(<Screen dialog="open" />);
    rerender(<Screen dialog="shut" />);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('stays where it is when there is no screen to put it on', () => {
    const { container } = render(<section><ScreenOverlay><div role="dialog">asked</div></ScreenOverlay></section>);
    expect(screen.getByRole('dialog').parentElement).toBe(container.querySelector('section'));
  });
});
