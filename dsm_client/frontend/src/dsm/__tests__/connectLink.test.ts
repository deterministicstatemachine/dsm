// SPDX-License-Identifier: Apache-2.0
// A link's connect code reaches the Apps screen through the native event
// bridge: held once, taken once, and the wallet is on the Apps screen.

import { emit } from '../EventBridge';
import { onConnectLink, takeConnectLink } from '../connectLink';
import { navigationStore } from '../../runtime/navigationStore';

const CODE = 'dsm:connect/v1:18B6GX3ME1SKMBSF64S3EBHG5RR2WC9T70T38CRJ40WMGA1EMH21E2GTB2G51ME8C';

describe('a connect link', () => {
  it('is held for the Apps screen, once, and opens it', () => {
    const heard: string[] = [];
    const stop = onConnectLink(() => heard.push('link'));
    emit('connect.link', new TextEncoder().encode(CODE));
    stop();
    expect(heard).toEqual(['link']);
    expect(navigationStore.getSnapshot().currentScreen).toBe('apps');
    expect(takeConnectLink()).toBe(CODE);
    expect(takeConnectLink()).toBeNull();
  });
});
