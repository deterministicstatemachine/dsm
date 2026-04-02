/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;

import { formatTimeAgo, formatDateTime } from '../time';

describe('formatTimeAgo', () => {
  const nowSec = () => Math.floor(Date.now() / 1000);

  test('returns empty string for 0', () => {
    expect(formatTimeAgo(0)).toBe('');
  });

  test('returns empty string for negative values', () => {
    expect(formatTimeAgo(-1)).toBe('');
    expect(formatTimeAgo(-9999)).toBe('');
  });

  test('returns empty string for NaN/falsy', () => {
    expect(formatTimeAgo(NaN)).toBe('');
    expect(formatTimeAgo(undefined as any)).toBe('');
    expect(formatTimeAgo(null as any)).toBe('');
  });

  test('returns "Just now" for timestamps within the last 60 seconds', () => {
    expect(formatTimeAgo(nowSec())).toBe('Just now');
    expect(formatTimeAgo(nowSec() - 30)).toBe('Just now');
    expect(formatTimeAgo(nowSec() - 59)).toBe('Just now');
  });

  test('returns minutes ago for timestamps within the last hour', () => {
    const result = formatTimeAgo(nowSec() - 120);
    expect(result).toBe('2m ago');

    const result2 = formatTimeAgo(nowSec() - 3540);
    expect(result2).toBe('59m ago');
  });

  test('returns hours ago for timestamps within the last day', () => {
    const result = formatTimeAgo(nowSec() - 7200);
    expect(result).toBe('2h ago');
  });

  test('returns "Yesterday" for timestamps 24-48h ago', () => {
    expect(formatTimeAgo(nowSec() - 86400)).toBe('Yesterday');
    expect(formatTimeAgo(nowSec() - 100000)).toBe('Yesterday');
  });

  test('returns a formatted date for older timestamps', () => {
    const threeDaysAgo = nowSec() - 3 * 86400;
    const result = formatTimeAgo(threeDaysAgo);
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(result).not.toBe('Yesterday');
    expect(result).not.toContain('ago');
  });
});

describe('formatDateTime', () => {
  test('returns "Unknown" for 0', () => {
    expect(formatDateTime(0)).toBe('Unknown');
  });

  test('returns "Unknown" for negative values', () => {
    expect(formatDateTime(-1)).toBe('Unknown');
  });

  test('returns "Unknown" for falsy values', () => {
    expect(formatDateTime(NaN)).toBe('Unknown');
    expect(formatDateTime(undefined as any)).toBe('Unknown');
    expect(formatDateTime(null as any)).toBe('Unknown');
  });

  test('returns a formatted date/time string for valid timestamps', () => {
    const ts = Math.floor(new Date('2024-06-15T12:30:00Z').getTime() / 1000);
    const result = formatDateTime(ts);
    expect(typeof result).toBe('string');
    expect(result).toContain('2024');
    expect(result).toContain('15');
  });
});
