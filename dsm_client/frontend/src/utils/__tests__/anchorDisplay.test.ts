/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;

import { shortId } from '../anchorDisplay';

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

});
