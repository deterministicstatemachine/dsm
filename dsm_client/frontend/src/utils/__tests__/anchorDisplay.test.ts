/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;

import { shortId, prettyAnchor } from '../anchorDisplay';

describe('anchorDisplay (UI-only)', () => {
  test('shortId renders crockford body and checksum', () => {
    const bytes = new Uint8Array(32).map((_, i) => (i * 7) & 0xff);
    const s = shortId(bytes, 12);
    expect(typeof s).toBe('string');
    const parts = s.split('-');
    expect(parts.length).toBe(2);
    expect(parts[0].length).toBe(12);
    expect(parts[1].length).toBe(2);
  });

  test('prettyAnchor groups in 8-char blocks (last group may be shorter)', () => {
    const bytes = new Uint8Array(16).map((_, i) => (i * 13) & 0xff);
    const s = prettyAnchor(bytes);
    // Expect groups separated by spaces; removing spaces should be crockford-only
    const noSpaces = s.replace(/\s+/g, '');
    expect(/^[0-9A-Z]+$/.test(noSpaces)).toBe(true);
    // All groups have length 8 except possibly last
    const groups = s.split(' ');
    expect(groups.slice(0, -1).every(g => g.length === 8)).toBe(true);
    expect(groups[groups.length - 1].length).toBeGreaterThan(0);
  });
});
