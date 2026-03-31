// SPDX-License-Identifier: Apache-2.0
/// <reference types="jest" />

describe('getNetworkId (single source)', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.dontMock('../../dsm_network_config.json');
  });
  it('reads client.mode when present', () => {
    jest.doMock('../../dsm_network_config.json', () => ({ client: { mode: 'jsonnet' } }), { virtual: true });
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { getNetworkId } = require('./network');
    expect(getNetworkId()).toBe('jsonnet');
  });

  it('reads _generated.environment when client.mode missing', () => {
    jest.doMock('../../dsm_network_config.json', () => ({ _generated: { environment: 'genv' } }), { virtual: true });
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { getNetworkId } = require('./network');
    expect(getNetworkId()).toBe('genv');
  });

  it('throws when neither field exists', () => {
    jest.doMock('../../dsm_network_config.json', () => ({}), { virtual: true });
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { getNetworkId } = require('./network');
    expect(() => getNetworkId()).toThrow(/networkId missing/);
  });
});