/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;
declare const beforeEach: any;
declare const afterEach: any;

import {
  DETERMINISTIC_SAFETY_SOURCE_TAG,
  deterministicSafetyFromError,
  emitDeterministicSafetyForError,
} from '../deterministicSafety';
import { bridgeEvents } from '../../bridge/bridgeEvents';

const enc = (s: string) => new TextEncoder().encode(s);

describe('deterministicSafetyFromError', () => {
  test('an error Rust did not tag is not a safety refusal, whatever it says', () => {
    expect(deterministicSafetyFromError({
      sourceTag: 10,
      message: 'Deterministic safety rejection [ParentConsumed]: parent already consumed',
      context: enc('classification=ParentConsumed message=parent already consumed'),
    })).toBeNull();
  });

  test('a tagged error yields the class and message Rust put in its context', () => {
    expect(deterministicSafetyFromError({
      sourceTag: DETERMINISTIC_SAFETY_SOURCE_TAG,
      message: 'Deterministic safety rejection [StalePrecommit]: tip moved',
      context: enc('classification=StalePrecommit message=tip moved'),
    })).toEqual({ classification: 'StalePrecommit', message: 'tip moved' });
  });

  test('a tagged error without the context format keeps its message and no class', () => {
    expect(deterministicSafetyFromError({
      sourceTag: DETERMINISTIC_SAFETY_SOURCE_TAG,
      message: 'refused',
      context: new Uint8Array(0),
    })).toEqual({ classification: '', message: 'refused' });
  });
});

describe('emitDeterministicSafetyForError', () => {
  let emitSpy: any;

  beforeEach(() => {
    emitSpy = jest.spyOn(bridgeEvents, 'emit').mockImplementation(() => {});
  });

  afterEach(() => {
    emitSpy.mockRestore();
  });

  test('emits nothing for an untagged error', () => {
    expect(emitDeterministicSafetyForError({ sourceTag: 0, message: 'random error', context: new Uint8Array(0) })).toBe(false);
    expect(emitSpy).not.toHaveBeenCalled();
  });

  test('emits the detail for a tagged error', () => {
    expect(emitDeterministicSafetyForError({
      sourceTag: DETERMINISTIC_SAFETY_SOURCE_TAG,
      message: 'x',
      context: enc('classification=TipMismatch message=expected tip differs'),
    })).toBe(true);
    expect(emitSpy).toHaveBeenCalledWith('dsm.deterministicSafety', {
      classification: 'TipMismatch',
      message: 'expected tip differs',
    });
  });

  test('answers true even if a listener throws', () => {
    emitSpy.mockImplementation(() => { throw new Error('fail'); });
    expect(emitDeterministicSafetyForError({
      sourceTag: DETERMINISTIC_SAFETY_SOURCE_TAG,
      message: 'x',
      context: enc('classification=ParentConsumed message=already consumed'),
    })).toBe(true);
  });
});
