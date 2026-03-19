/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0
// eslint-env jest
declare const describe: any;
declare const test: any;
declare const expect: any;

import logger from '../logger';

describe('logger', () => {
  test('safe log functions exist and are callable', () => {
    const msgs: any[] = [];
    const orig = { debug: console.debug, info: console.info, warn: console.warn, error: console.error };
    // @ts-ignore
    console.debug = (...a: any[]) => { msgs.push(['d', ...a].join(' ')); };
    // @ts-ignore
    console.info = (...a: any[]) => { msgs.push(['i', ...a].join(' ')); };
    // @ts-ignore
    console.warn = (...a: any[]) => { msgs.push(['w', ...a].join(' ')); };
    // @ts-ignore
    console.error = (...a: any[]) => { msgs.push(['e', ...a].join(' ')); };
    try {
      logger.debug('hello');
      logger.info('world');
      logger.warn('!');
      logger.error('x');
      expect(msgs.length).toBeGreaterThan(0);
    } finally {
      console.debug = orig.debug;
      console.info = orig.info;
      console.warn = orig.warn;
      console.error = orig.error;
    }
  });
});
