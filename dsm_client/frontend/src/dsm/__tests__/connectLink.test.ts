// SPDX-License-Identifier: Apache-2.0
// A link's connect code reaches the Apps screen through the native event
// bridge: held once, taken once, and the wallet is on the Apps screen. The
// link comes with the app Android recorded as having opened it (audit
// 2026-10-15, item 4), or with none when Android named none.

import { emit } from '../EventBridge';
import { onConnectLink, readConnectLink, takeConnectLink } from '../connectLink';
import { navigationStore } from '../../runtime/navigationStore';

const CODE = 'dsm:connect/v1:18B6GX3ME1SKMBSF64S3EBHG5RR2WC9T70T38CRJ40WMGA1EMH21E2GTB2G51ME8C';

function payload(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

describe('a connect link', () => {
  it('is held for the Apps screen, once, with the app that opened it, and opens the screen', () => {
    const heard: string[] = [];
    const stop = onConnectLink(() => heard.push('link'));
    emit('connect.link', payload(`com.example.game\n${CODE}`));
    stop();
    expect(heard).toEqual(['link']);
    expect(navigationStore.getSnapshot().currentScreen).toBe('apps');
    expect(takeConnectLink()).toEqual({ code: CODE, sender: 'com.example.game' });
    expect(takeConnectLink()).toBeNull();
  });

  it('names no sender when Android named none', () => {
    expect(readConnectLink(payload(`\n${CODE}`))).toEqual({ code: CODE, sender: null });
  });

  it('keeps a newline inside the link as part of the link', () => {
    expect(readConnectLink(payload(`com.example.game\n${CODE}\nmore`))).toEqual({
      code: `${CODE}\nmore`,
      sender: 'com.example.game',
    });
  });

  it('is not taken when the payload has no sender line or no link', () => {
    const heard: string[] = [];
    const stop = onConnectLink(() => heard.push('link'));
    emit('connect.link', payload(CODE));
    emit('connect.link', payload('com.example.game\n'));
    stop();
    expect(heard).toEqual([]);
    expect(takeConnectLink()).toBeNull();
    expect(() => readConnectLink(payload(CODE))).toThrow(/no sender line/);
  });
});
