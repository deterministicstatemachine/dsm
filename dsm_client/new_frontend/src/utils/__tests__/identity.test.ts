/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;

import { hasIdentity, checkIdentityState } from '../identity';
import {
  DEFAULT_NATIVE_SESSION,
  type NativeSessionSnapshot,
} from '../../runtime/nativeSessionTypes';
import {
  resetNativeSessionStoreForTest,
  setNativeSessionSnapshotForTest,
} from '../../runtime/nativeSessionStore';

function publishSession(overrides: Partial<NativeSessionSnapshot>): void {
  setNativeSessionSnapshotForTest({
    ...DEFAULT_NATIVE_SESSION,
    received: true,
    ...overrides,
  });
}

describe('identity', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    resetNativeSessionStoreForTest();
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  test('hasIdentity returns true when native session reports ready identity', async () => {
    publishSession({
      phase: 'wallet_ready',
      identity_status: 'ready',
      env_config_status: 'ready',
    });
    const ok = await hasIdentity();
    expect(ok).toBe(true);
  });

  test('hasIdentity returns false when native session reports missing identity', async () => {
    publishSession({
      phase: 'needs_genesis',
      identity_status: 'missing',
      env_config_status: 'ready',
    });
    const ok = await hasIdentity();
    expect(ok).toBe(false);
  });

  test('checkIdentityState returns RUNTIME_NOT_READY before native session arrives', async () => {
    const state = await checkIdentityState();
    expect(state).toBe('RUNTIME_NOT_READY');
  });

  test('checkIdentityState returns READY when native session reports ready identity', async () => {
    publishSession({
      phase: 'wallet_ready',
      identity_status: 'ready',
      env_config_status: 'ready',
    });
    const state = await checkIdentityState();
    expect(state).toBe('READY');
  });

  test('checkIdentityState returns NO_IDENTITY when native session reports missing identity', async () => {
    publishSession({
      phase: 'needs_genesis',
      identity_status: 'missing',
      env_config_status: 'ready',
    });
    const state = await checkIdentityState();
    expect(state).toBe('NO_IDENTITY');
  });

  test('checkIdentityState returns RUNTIME_NOT_READY while env config is still loading', async () => {
    publishSession({
      phase: 'runtime_loading',
      identity_status: 'runtime_not_ready',
      env_config_status: 'loading',
    });
    const state = await checkIdentityState();
    expect(state).toBe('RUNTIME_NOT_READY');
  });
});
