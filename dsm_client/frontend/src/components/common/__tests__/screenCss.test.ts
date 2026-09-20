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

  it('keeps an FX scene inside the screen host', () => {
    // position: absolute against .stateboy-screen-host, never fixed to the page.
    expect(rule('.sb-fx-backdrop')).not.toMatch(/position:\s*fixed/);
    expect(rule('.sb-fx-full')).toMatch(/position:\s*absolute/);
  });
});
