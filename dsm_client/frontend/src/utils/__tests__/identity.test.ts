/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// The native session reaches the store the way Rust's does: as a
// `session.state` event on the bus. The store used to carry setters that
// existed only for tests.

import { DEFAULT_NATIVE_SESSION, type NativeSessionSnapshot } from '../../runtime/nativeSessionTypes';

type IdentityModule = typeof import('../identity');
type BusModule = typeof import('../../bridge/bridgeEvents');

describe('identity', () => {
  let identity: IdentityModule;
  let bus: BusModule;
  let warnSpy: jest.SpyInstance;

  // A fresh store per test: the session is module state, and "not received"
  // is the state before any event, which nothing can bring back.
  beforeEach(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.isolateModules(() => {
      bus = require('../../bridge/bridgeEvents');
      identity = require('../identity');
    });
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  function publishSession(overrides: Partial<NativeSessionSnapshot>): void {
    bus.bridgeEvents.emit('session.state', { ...DEFAULT_NATIVE_SESSION, ...overrides } as any);
  }

  test('hasIdentity returns true when native session reports ready identity', async () => {
    publishSession({
      phase: 'wallet_ready',
      identity_status: 'ready',
      env_config_status: 'ready',
    });
    expect(await identity.hasIdentity()).toBe(true);
  });

  test('hasIdentity returns false when native session reports missing identity', async () => {
    publishSession({
      phase: 'needs_genesis',
      identity_status: 'missing',
      env_config_status: 'ready',
    });
    expect(await identity.hasIdentity()).toBe(false);
  });

  test('checkIdentityState returns RUNTIME_NOT_READY before native session arrives', async () => {
    expect(await identity.checkIdentityState()).toBe('RUNTIME_NOT_READY');
  });

  test('checkIdentityState returns READY when native session reports ready identity', async () => {
    publishSession({
      phase: 'wallet_ready',
      identity_status: 'ready',
      env_config_status: 'ready',
    });
    expect(await identity.checkIdentityState()).toBe('READY');
  });

  test('checkIdentityState returns NO_IDENTITY when native session reports missing identity', async () => {
    publishSession({
      phase: 'needs_genesis',
      identity_status: 'missing',
      env_config_status: 'ready',
    });
    expect(await identity.checkIdentityState()).toBe('NO_IDENTITY');
  });

  test('checkIdentityState returns RUNTIME_NOT_READY while env config is still loading', async () => {
    publishSession({
      phase: 'runtime_loading',
      identity_status: 'runtime_not_ready',
      env_config_status: 'loading',
    });
    expect(await identity.checkIdentityState()).toBe('RUNTIME_NOT_READY');
  });
});
