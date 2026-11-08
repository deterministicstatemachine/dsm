// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, items 3 and 4: a connect code a link brought is shown as
// coming from outside the wallet, with the app Android recorded as having
// opened the link, beside the name the offer gives itself; and the approval
// holds the confirm guard (other apps' overlay windows hidden) while it is up.

import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../proto/dsm_app_pb';
import AppsScreen from '../AppsScreen';
import { emit } from '../../../dsm/EventBridge';
import { installScriptedPhone, removeScriptedPhone, settle, type Answer } from '../../../tests/helpers/scriptedPhone';

const CODE = 'dsm:connect/v1:18B6GX3ME1SKMBSF64S3EBHG5RR2WC9T70T38CRJ40WMGA1EMH21E2GTB2G51ME8C';
const CONFIRM = 2;

function reply(value: pb.ConnectReplyV1['reply']): Answer {
  return { case: 'connectReply', value: new pb.ConnectReplyV1({ reply: value }) };
}

function phoneWithAnOffer() {
  return installScriptedPhone({
    'connect.list': reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [] }) }),
    'connect.pending': reply({ case: 'pending', value: new pb.ConnectPendingListV1({ pending: [] }) }),
    'connect.preview': reply({
      case: 'preview',
      value: new pb.ConnectPreviewV1({
        offerDigest: new Uint8Array(32).fill(7),
        displayName: 'DSM Wallet Official',
        appDeviceId: new Uint8Array(32).fill(9),
        endpoint: 'https://game.example',
        scopeLines: ['Pay up to 10 ERA'],
      }),
    }),
  });
}

afterEach(removeScriptedPhone);

describe('a connect offer', () => {
  it('that a link brought says it came from outside the wallet, and from which app', async () => {
    const phone = phoneWithAnOffer();
    const { unmount } = render(<AppsScreen />);
    await act(settle);

    act(() => emit('connect.link', new TextEncoder().encode(`com.example.lookalike\n${CODE}`)));
    expect(screen.getByText(/A link from outside the wallet handed over a connect code, opened by com\.example\.lookalike/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'READ' }));
    await act(settle);
    const offer = screen.getByTestId('connect-offer');
    expect(offer).toHaveTextContent('DSM Wallet Official asks to connect. That is the name it gives itself.');
    expect(screen.getByTestId('connect-offer-origin')).toHaveTextContent(
      'This code came from outside the wallet: a link opened by com.example.lookalike.',
    );
    expect(phone.guards).toEqual([CONFIRM]);

    fireEvent.click(screen.getByRole('button', { name: 'CANCEL' }));
    await act(settle);
    expect(phone.guards).toEqual([CONFIRM, 0]);
    unmount();
  });

  it('that a link brought with no app named says Android named none', async () => {
    phoneWithAnOffer();
    render(<AppsScreen />);
    await act(settle);
    act(() => emit('connect.link', new TextEncoder().encode(`\n${CODE}`)));
    fireEvent.click(screen.getByRole('button', { name: 'READ' }));
    await act(settle);
    expect(screen.getByTestId('connect-offer-origin')).toHaveTextContent('a link opened by an app Android did not name');
  });

  it('that the player pasted carries no link origin', async () => {
    phoneWithAnOffer();
    render(<AppsScreen />);
    await act(settle);
    fireEvent.change(screen.getByLabelText('Connect an app'), { target: { value: CODE } });
    fireEvent.click(screen.getByRole('button', { name: 'READ' }));
    await act(settle);
    expect(screen.getByTestId('connect-offer')).toBeInTheDocument();
    expect(screen.queryByTestId('connect-offer-origin')).toBeNull();
  });
});

// SA-157: what an application chose is shown without bidirectional controls.
describe('a request waiting for the player', () => {
  it('shows the application its name and summary with no bidi override', async () => {
    const RLO = '\u202E';
    installScriptedPhone({
      'connect.list': reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [] }) }),
      'connect.pending': reply({
        case: 'pending',
        value: new pb.ConnectPendingListV1({
          pending: [
            new pb.ConnectPendingV1({
              sessionId: new Uint8Array(32).fill(3),
              seq: 4n,
              displayName: `Arena${RLO}`,
              summary: `Pay 1 ERA, memo ${RLO}0001 ARE 0`,
              reason: `over the grant${RLO}`,
            }),
          ],
        }),
      }),
    });
    render(<AppsScreen />);
    await act(settle);
    fireEvent.click(screen.getByRole('button', { name: /^Waiting/ }));
    await act(settle);
    const card = screen.getByText('Arena').closest('section');
    expect(card).not.toBeNull();
    expect(card).not.toHaveTextContent(RLO);
    expect(card).toHaveTextContent('Arena: Pay 1 ERA, memo 0001 ARE 0');
  });
});
