// SPDX-License-Identifier: MIT OR Apache-2.0
// Whether the radio advertises is native policy: it follows the device's
// identity. The contacts provider used to set the advertised identity and
// start advertising when the identity became ready and when a contact's BLE
// address was learned.

/* eslint-disable @typescript-eslint/no-explicit-any */
import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import * as pb from '../../proto/dsm_app_pb';
import { ContactsProvider } from '../ContactsContext';
import { dsmClient } from '../../services/dsmClient';
import { bridgeEvents } from '../../bridge/bridgeEvents';

test('identity readiness and a learned BLE address reach the contact list, not the radio', async () => {
  const peer = {
    alias: 'Peer',
    deviceId: new Uint8Array(32).fill(0x0a),
    genesisHash: new Uint8Array(32).fill(0x0b),
    publicKey: new Uint8Array(64).fill(0x0c),
    genesisVerifiedOnline: true,
    bleAddress: 'AA:BB:CC:DD:EE:FF',
  };
  (dsmClient.getContacts as any) = jest.fn().mockResolvedValue({ contacts: [peer] });
  const bridge = (window as any).DsmBridge;
  const answer = bridge.sendMessageBin;
  const methods: string[] = [];
  bridge.sendMessageBin = (bytes: Uint8Array) => {
    methods.push(pb.BridgeRpcRequest.fromBinary(bytes).method);
    return answer(bytes);
  };
  try {
    render(<ContactsProvider><div /></ContactsProvider>);
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    const before = (dsmClient.getContacts as jest.Mock).mock.calls.length;

    await act(async () => {
      bridgeEvents.emit('identity.ready', undefined);
    });
    // The provider answers readiness by reading the list Rust holds.
    await waitFor(() => expect((dsmClient.getContacts as jest.Mock).mock.calls.length).toBeGreaterThan(before));

    await act(async () => {
      bridgeEvents.emit('contact.bleMapped', { address: peer.bleAddress });
    });
    // Whatever either event started has reached the port by now.
    await act(async () => { await new Promise((r) => setTimeout(r, 200)); });
  } finally {
    bridge.sendMessageBin = answer;
  }
  expect(methods).not.toContain('nativeHostRequest');
  expect(methods).not.toContain('setBleIdentityForAdvertising');
});
