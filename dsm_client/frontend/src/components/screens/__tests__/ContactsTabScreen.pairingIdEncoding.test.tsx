import React from 'react';
import { act, render } from '@testing-library/react';

import ContactsTabScreen from '../ContactsTabScreen';
import { encodeBase32Crockford32 } from '../../../utils/textId';

jest.mock('../../../utils/identity', () => ({
  hasIdentity: jest.fn().mockResolvedValue(false),
}));

jest.mock('../../../hooks/useTransactions', () => ({
  useTransactions: () => ({
    transactions: [],
    refresh: jest.fn(),
  }),
}));

declare const describe: any;
declare const it: any;
declare const expect: any;

// Mock ContactsContext to provide exactly what ContactsTabScreen uses.
jest.mock('../../../contexts/ContactsContext', () => {
  return {
    useContacts: () => {
      // A deterministic 32-byte device id (base32 string).
      const device_id = new Uint8Array(32);
      for (let i = 0; i < device_id.length; i++) device_id[i] = i & 0xff;
      const deviceIdB32 = encodeBase32Crockford32(device_id);

      return {
        contacts: [
          {
            alias: 'peer',
            deviceId: deviceIdB32,
            genesisHash: encodeBase32Crockford32(new Uint8Array(32)),
            bleAddress: 'AA:BB:CC:DD:EE:FF',
          },
        ],
        refreshContacts: async () => {},
        isLoading: false,
      };
    },
  };
});

// Mock the Rust-driven pairing bridge calls
jest.mock('../../../dsm/WebViewBridge', () => ({
  startPairingAll: jest.fn().mockResolvedValue(undefined),
  stopPairingAll: jest.fn().mockResolvedValue(undefined),
}));

describe('ContactsTabScreen BLE pairing', () => {
  it('does not call startPairingAll when all contacts are already paired', async () => {
    const { startPairingAll } = require('../../../dsm/WebViewBridge');

    (globalThis as any).window = (globalThis as any).window || {};
    (globalThis as any).window.DsmBridge = {
      __callBin: async () => new Uint8Array(0),
    };
    (globalThis as any).requestAnimationFrame = () => 0;

    // Sanity check encoder remains stable (used for UI/display).
    const expectedB32 = encodeBase32Crockford32(new Uint8Array(Array.from({ length: 32 }, (_, i) => i & 0xff)));
    expect(expectedB32).toMatch(/^[0-9A-Z]+$/);

    await act(async () => {
      render(<ContactsTabScreen />);
      await Promise.resolve();
    });

    // Contact already has bleAddress, so startPairingAll should NOT be called.
    expect(startPairingAll).not.toHaveBeenCalled();
  });
});
