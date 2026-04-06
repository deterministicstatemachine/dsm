/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;
declare const beforeEach: any;
declare const afterEach: any;

import { isAndroidWebView, hasDsmBridge, testBridgeConnectivity } from '../deviceTesting';

describe('isAndroidWebView', () => {
  const originalUA = navigator.userAgent;

  afterEach(() => {
    Object.defineProperty(navigator, 'userAgent', {
      value: originalUA,
      configurable: true,
    });
  });

  test('returns false when userAgent does not contain Android', () => {
    Object.defineProperty(navigator, 'userAgent', {
      value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X)',
      configurable: true,
    });
    expect(isAndroidWebView()).toBe(false);
  });

  test('returns true when userAgent contains Android', () => {
    Object.defineProperty(navigator, 'userAgent', {
      value: 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36',
      configurable: true,
    });
    expect(isAndroidWebView()).toBe(true);
  });
});

describe('hasDsmBridge', () => {
  afterEach(() => {
    delete (window as any).DsmBridge;
  });

  test('returns false when DsmBridge is not on window', () => {
    delete (window as any).DsmBridge;
    expect(hasDsmBridge()).toBe(false);
  });

  test('returns true when DsmBridge is present', () => {
    (window as any).DsmBridge = { hasIdentityDirect: () => true };
    expect(hasDsmBridge()).toBe(true);
  });
});

describe('testBridgeConnectivity', () => {
  afterEach(() => {
    delete (window as any).DsmBridge;
  });

  test('resolves false when no DsmBridge', async () => {
    delete (window as any).DsmBridge;
    await expect(testBridgeConnectivity()).resolves.toBe(false);
  });

  test('resolves true when bridge has hasIdentityDirect returning boolean', async () => {
    (window as any).DsmBridge = {
      hasIdentityDirect: () => false,
    };
    await expect(testBridgeConnectivity()).resolves.toBe(true);
  });

  test('resolves false when bridge lacks hasIdentityDirect', async () => {
    (window as any).DsmBridge = {};
    await expect(testBridgeConnectivity()).resolves.toBe(false);
  });

  test('resolves false when hasIdentityDirect returns non-boolean', async () => {
    (window as any).DsmBridge = {
      hasIdentityDirect: () => 'yes',
    };
    await expect(testBridgeConnectivity()).resolves.toBe(false);
  });

  test('resolves false when bridge throws', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    (window as any).DsmBridge = {
      hasIdentityDirect: () => { throw new Error('broken'); },
    };
    await expect(testBridgeConnectivity()).resolves.toBe(false);
  });
});
