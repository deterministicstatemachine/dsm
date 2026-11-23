// SPDX-License-Identifier: Apache-2.0
// The Apps screen reads the connected applications and the requests waiting
// for the player on opening, and again when Rust says they changed
// (`connect.changed`, from the native event path), and on no timer. It used
// to read both every three seconds for as long as it was open.

import React from 'react';
import { act, render } from '@testing-library/react';
import * as pb from '../../../proto/dsm_app_pb';
import AppsScreen from '../AppsScreen';
import { initializeEventBridge } from '../../../dsm/EventBridge';
import { installScriptedPhone, removeScriptedPhone, settle, type Answer } from '../../../tests/helpers/scriptedPhone';

afterEach(removeScriptedPhone);

function reply(value: pb.ConnectReplyV1['reply']): Answer {
  return { case: 'connectReply', value: new pb.ConnectReplyV1({ reply: value }) };
}

test('the Apps screen reads on opening and on connect.changed, not on a clock', async () => {
  let reads = 0;
  installScriptedPhone({
    'connect.list': () => {
      reads += 1;
      return reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [] }) });
    },
    'connect.connectedBy': reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [] }) }),
    'connect.pending': reply({ case: 'pending', value: new pb.ConnectPendingListV1({ pending: [] }) }),
  });
  const { unmount } = render(<AppsScreen />);
  await act(settle);
  expect(reads).toBe(1);

  await act(async () => { await new Promise((r) => setTimeout(r, 4_000)); });
  expect(reads).toBe(1);

  // As the native host delivers a Rust event to the page.
  initializeEventBridge();
  act(() => {
    window.dispatchEvent(new CustomEvent('dsm-event-bin', {
      detail: { topic: 'connect.changed', payload: new Uint8Array(0) },
    }));
  });
  await act(settle);
  expect(reads).toBe(2);
  unmount();
}, 15_000);
