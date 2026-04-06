/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;
declare const beforeEach: any;
declare const afterEach: any;

import { parseDeterministicSafety, emitDeterministicSafetyIfPresent } from '../deterministicSafety';
import { bridgeEvents } from '../../bridge/bridgeEvents';

describe('parseDeterministicSafety', () => {
  test('returns null for null/undefined/empty', () => {
    expect(parseDeterministicSafety(null)).toBeNull();
    expect(parseDeterministicSafety(undefined)).toBeNull();
    expect(parseDeterministicSafety('')).toBeNull();
  });

  test('returns null for non-matching messages', () => {
    expect(parseDeterministicSafety('some random error')).toBeNull();
    expect(parseDeterministicSafety('Deterministic safety')).toBeNull();
    expect(parseDeterministicSafety('Deterministic safety rejection')).toBeNull();
  });

  test('parses a valid deterministic safety rejection message', () => {
    const msg = 'Deterministic safety rejection [OVERFLOW]: value exceeds maximum';
    const result = parseDeterministicSafety(msg);
    expect(result).toEqual({
      classification: 'OVERFLOW',
      message: 'value exceeds maximum',
    });
  });

  test('is case-insensitive', () => {
    const msg = 'deterministic safety rejection [Replay]: duplicate nonce detected';
    const result = parseDeterministicSafety(msg);
    expect(result).toEqual({
      classification: 'Replay',
      message: 'duplicate nonce detected',
    });
  });

  test('handles empty classification gracefully', () => {
    const msg = 'Deterministic safety rejection []: some detail';
    const result = parseDeterministicSafety(msg);
    expect(result).toBeNull();
  });

  test('handles empty detail', () => {
    const msg = 'Deterministic safety rejection [CRITICAL]:';
    const result = parseDeterministicSafety(msg);
    expect(result).toEqual({
      classification: 'CRITICAL',
      message: '',
    });
  });

  test('trims classification and detail', () => {
    const msg = 'Deterministic safety rejection [ BOUNDS ]:  out of range  ';
    const result = parseDeterministicSafety(msg);
    expect(result).toEqual({
      classification: 'BOUNDS',
      message: 'out of range',
    });
  });
});

describe('emitDeterministicSafetyIfPresent', () => {
  let emitSpy: any;

  beforeEach(() => {
    emitSpy = jest.spyOn(bridgeEvents, 'emit').mockImplementation(() => {});
  });

  afterEach(() => {
    emitSpy.mockRestore();
  });

  test('returns false and does not emit for non-matching messages', () => {
    expect(emitDeterministicSafetyIfPresent('random error')).toBe(false);
    expect(emitSpy).not.toHaveBeenCalled();
  });

  test('returns false for null/undefined', () => {
    expect(emitDeterministicSafetyIfPresent(null)).toBe(false);
    expect(emitDeterministicSafetyIfPresent(undefined)).toBe(false);
    expect(emitSpy).not.toHaveBeenCalled();
  });

  test('returns true and emits for valid safety rejection', () => {
    const msg = 'Deterministic safety rejection [DOUBLE_SPEND]: already spent';
    expect(emitDeterministicSafetyIfPresent(msg)).toBe(true);
    expect(emitSpy).toHaveBeenCalledWith('dsm.deterministicSafety', {
      classification: 'DOUBLE_SPEND',
      message: 'already spent',
    });
  });

  test('returns true even if emit throws', () => {
    emitSpy.mockImplementation(() => { throw new Error('fail'); });
    const msg = 'Deterministic safety rejection [ERROR]: something broke';
    expect(emitDeterministicSafetyIfPresent(msg)).toBe(true);
  });
});
