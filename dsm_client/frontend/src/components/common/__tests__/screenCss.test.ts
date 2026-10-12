// SPDX-License-Identifier: Apache-2.0
// The screen stylesheet is mocked away in jsdom, so these rules are checked as
// text. They guard two things the browser would otherwise get wrong quietly.
import fs from 'fs';
import path from 'path';

const css = fs.readFileSync(path.join(__dirname, '../../../styles/screen.css'), 'utf8');

function rule(selector: string): string {
  const start = css.indexOf(`\n${selector} {`);
  expect(start).toBeGreaterThan(-1);
  const end = css.indexOf('\n}', start);
  return css.slice(start, end);
}

describe('screen.css', () => {
  it('starts a popup from prose typography, whatever opened it', () => {
    // An InfoTip lives inside card titles and field labels, which are
    // uppercase, tracked and bold. Its popup is a DOM child of that element.
    const backdrop = rule('.sb-popover-backdrop');
    expect(backdrop).toMatch(/text-transform:\s*none/);
    expect(backdrop).toMatch(/letter-spacing:\s*normal/);
    expect(backdrop).toMatch(/font-weight:\s*400/);
  });

  it('keeps the i glyph a lowercase i', () => {
    expect(rule('.sb-info')).toMatch(/text-transform:\s*none/);
  });

  it("scrolls the frame's body, and only the body", () => {
    // Screens put their content in the body; a card taller than the screen
    // must be reachable by scrolling it, not clipped.
    expect(rule('.sb-screen__body')).toMatch(/overflow-y:\s*auto/);
    expect(rule('.sb-screen')).not.toMatch(/overflow-y:\s*auto/);
  });

  it('inverts the dark card: background and type together', () => {
    // The contrast container carries the popup's look onto the screen. A dark
    // background with the screen's default dark type would be unreadable.
    const dark = rule('.sb-card--dark');
    expect(dark).toMatch(/background:\s*var\(--text-dark\)/);
    expect(dark).toMatch(/color:\s*var\(--bg\)/);
  });

  it("opens an inline token picker's list across its whole row", () => {
    // Beside an amount field the picker's button is a narrow column. Its list
    // is placed against the row, not the button, so it spans the amount field
    // and the button together and a row's ticker is never cut to the column.
    expect(rule('.sb-input-row:has(> .sb-tokensel--inline)')).toMatch(/position:\s*relative/);
    const picker = rule('.sb-input-row > .sb-tokensel--inline');
    expect(picker).toMatch(/position:\s*static/);
    expect(picker).toMatch(/max-width:\s*50%/);
    expect(picker).not.toMatch(/\swidth:/);
    const list = rule('.sb-tokensel__list');
    expect(list).toMatch(/position:\s*absolute/);
    expect(list).toMatch(/left:\s*0/);
    expect(list).toMatch(/right:\s*0/);
  });

  it("gives the token wizard's action two shares of its row", () => {
    // "Publishing token" is 115px of text: in an even split the action's
    // content box is 99px and the label ran into the button's edges.
    expect(rule('.sb-popover.token-wizard .sb-actions > .sb-btn--primary')).toMatch(/flex-grow:\s*2/);
  });

  it('keeps an FX scene inside the screen host', () => {
    // position: absolute against .stateboy-screen-host, never fixed to the page.
    expect(rule('.sb-fx-backdrop')).not.toMatch(/position:\s*fixed/);
    expect(rule('.sb-fx-full')).toMatch(/position:\s*absolute/);
  });
});
