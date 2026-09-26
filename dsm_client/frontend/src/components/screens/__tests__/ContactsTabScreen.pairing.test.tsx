// SPDX-License-Identifier: MIT OR Apache-2.0
//! When pairing runs is Rust's: while the app is in the foreground with
//! Bluetooth on and permitted, until no contact is left unpaired. The screen
//! used to start the pairing loop when it saw an unpaired contact, and stop it
//! when it unmounted.

/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { act, render } from '@testing-library/react';

import * as pb from '../../../proto/dsm_app_pb';
import ContactsTabScreen from '../ContactsTabScreen';

jest.mock('../../../utils/identity', () => ({
  hasIdentity: jest.fn().mockResolvedValue(false),
}));

jest.mock('../../../hooks/useTransactions', () => ({
  useTransactions: () => ({ transactions: [], refresh: jest.fn() }),
}));

const mockContacts: any[] = [];
jest.mock('../../../contexts/ContactsContext', () => ({
  useContacts: () => ({ contacts: mockContacts, refreshContacts: async () => {}, isLoading: false }),
}));

test('the contacts screen asks for nothing but reads, with a contact unpaired and as it unmounts', async () => {
  mockContacts.push(
    { alias: 'paired', deviceId: 'PA1RED', genesisHash: 'GENES1S', signingPublicKey: 'KEY1', genesisVerifiedOnline: true, bleAddress: 'AA:BB:CC:DD:EE:FF' },
    { alias: 'unpaired', deviceId: 'UNPA1RED', genesisHash: 'GENES2S', signingPublicKey: 'KEY2', genesisVerifiedOnline: true },
  );
  (globalThis as any).requestAnimationFrame = () => 0;
  const bridge = (window as any).DsmBridge;
  const answer = bridge.sendMessageBin;
  const requests: string[] = [];
  bridge.sendMessageBin = (bytes: Uint8Array) => {
    const req = pb.BridgeRpcRequest.fromBinary(bytes);
    let what = req.method;
    if (req.method === 'nativeBoundaryIngress' && req.payload.case === 'bytes') {
      what += `:${String(pb.IngressRequest.fromBinary(req.payload.value.data).operation.case)}`;
    }
    requests.push(what);
    return answer(bytes);
  };
  try {
    let rendered: ReturnType<typeof render> | undefined;
    await act(async () => {
      rendered = render(<ContactsTabScreen />);
      await Promise.resolve();
    });
    await act(async () => {
      rendered!.unmount();
      // Whatever the unmount started has reached the port by now.
      await new Promise((r) => setTimeout(r, 20));
    });
  } finally {
    bridge.sendMessageBin = answer;
  }
  expect(requests.filter((r) => r !== 'nativeBoundaryIngress:routerQuery')).toEqual([]);
});
