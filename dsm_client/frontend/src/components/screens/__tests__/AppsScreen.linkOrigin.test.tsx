// SPDX-License-Identifier: Apache-2.0
// Audit 2026-10-15, items 3 and 4: a connect code a link brought is shown as
// coming from outside the wallet, with the app the phone recorded as having
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
    'connect.connectedBy': reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [] }) }),
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
    await act(settle);
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

  it('that a link brought with no app named says the phone named none', async () => {
    phoneWithAnOffer();
    render(<AppsScreen />);
    await act(settle);
    act(() => emit('connect.link', new TextEncoder().encode(`\n${CODE}`)));
    await act(settle);
    fireEvent.click(screen.getByRole('button', { name: 'READ' }));
    await act(settle);
    expect(screen.getByTestId('connect-offer-origin')).toHaveTextContent('a link opened by an app your phone did not name');
  });

  // Found on the iOS Simulator, 2026-11-08: iOS cannot step back to the app
  // that sent the link (no return address is bound to the session yet), and
  // the connect stood while the page reported it as failed.
  it('that a link brought, once approved, says it connected whether or not the wallet stepped back', async () => {
    for (const [stepped, said] of [
      [1, 'Connected to DSM Wallet Official.'],
      [0, 'Connected to DSM Wallet Official. Go back to the app that sent you here.'],
    ] as const) {
      const phone = installScriptedPhone(
        {
          'connect.list': reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [] }) }),
          'connect.connectedBy': reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [] }) }),
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
          'connect.approve': reply({
            case: 'session',
            value: new pb.ConnectSessionV1({ sessionId: new Uint8Array(32).fill(5), displayName: 'DSM Wallet Official' }),
          }),
        },
        { returnToConnectCaller: new Uint8Array([stepped]) },
      );
      const { unmount } = render(<AppsScreen />);
      await act(settle);
      act(() => emit('connect.link', new TextEncoder().encode(`\n${CODE}`)));
      await act(settle);
      fireEvent.click(screen.getByRole('button', { name: 'READ' }));
      await act(settle);
      fireEvent.click(screen.getByRole('button', { name: 'APPROVE' }));
      await act(settle);
      expect(screen.getByText(said)).toBeInTheDocument();
      expect(screen.queryByText(/Connecting failed/)).toBeNull();
      expect(phone.guards).toContain(CONFIRM);
      unmount();
      removeScriptedPhone();
    }
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

// Owner, 2026-11-19: an app the wallet is connected to sends the player to the
// wallet to approve what it asks for, and the wallet goes back to it by itself.
describe('a link carrying the code of a connected application', () => {
  const ARENA = new Uint8Array(32).fill(5);
  const OTHER = new Uint8Array(32).fill(6);
  const arena = new pb.ConnectSessionV1({
    sessionId: ARENA,
    displayName: 'Arena',
    status: pb.ConnectSessionStatus.CONNECTED,
  });
  const asked = (sessionId: Uint8Array<ArrayBuffer>, seq: bigint, displayName: string, summary: string) =>
    new pb.ConnectPendingV1({ sessionId, seq, displayName, summary, reason: 'the grant covers no payment' });

  /** A phone connected to Arena, with `waiting` held for the player; what it was asked, in order. */
  function phoneConnectedToArena(waiting: pb.ConnectPendingV1[], stepped: number) {
    const calls: string[] = [];
    let held = waiting;
    const heard = (route: string, answer: () => ReturnType<typeof reply>) => () => {
      calls.push(route);
      return answer();
    };
    const phone = installScriptedPhone(
      {
        'connect.list': reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [arena] }) }),
        'connect.connectedBy': heard('connect.connectedBy', () => reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [arena] }) })),
        'connect.sync': heard('connect.sync', () => reply({ case: 'sessions', value: new pb.ConnectSessionsV1({ sessions: [arena] }) })),
        'connect.preview': heard('connect.preview', () => reply({ case: 'preview', value: new pb.ConnectPreviewV1({}) })),
        'connect.pending': () => reply({ case: 'pending', value: new pb.ConnectPendingListV1({ pending: held }) }),
        'connect.respond': () => {
          calls.push(`connect.respond ${held[0].seq.toString()}`);
          held = held.slice(1);
          return reply({
            case: 'decided',
            value: new pb.ConnectDecidedV1({ session: arena, outcome: pb.ConnectOutcome.CARRIED_OUT, line: 'Paid 1,200 DBUCKS to Arena.' }),
          });
        },
      },
      { returnToConnectCaller: new Uint8Array([stepped]) },
    );
    return { phone, calls };
  }

  it('opens what that application has waiting, fetching nothing the link names', async () => {
    const { phone, calls } = phoneConnectedToArena([asked(ARENA, 7n, 'Arena', 'Pay 1,200 DBUCKS')], 1);
    render(<AppsScreen />);
    await act(settle);
    act(() => emit('connect.link', new TextEncoder().encode(`com.example.arena\n${CODE}`)));
    await act(settle);

    expect(screen.getByText(/com\.example\.arena opened the wallet for Arena, which is connected/)).toBeInTheDocument();
    expect(screen.getByText(/Pay 1,200 DBUCKS/).closest('section')).toHaveTextContent('Arena: Pay 1,200 DBUCKS');
    expect(screen.getByRole('button', { name: 'APPROVE' })).toBeInTheDocument();
    // No connect offer is read or shown, and the code is not left in the field.
    expect(screen.queryByTestId('connect-offer')).toBeNull();
    expect(screen.queryByLabelText('Connect an app')).toBeNull();
    expect(calls).toEqual(['connect.connectedBy', 'connect.sync']);
    expect(phone.guards).toContain(CONFIRM);
  });

  it('steps back to the app once its request is decided, or says so where the phone cannot', async () => {
    for (const [stepped, said] of [
      [1, 'Paid 1,200 DBUCKS to Arena.'],
      [0, 'Paid 1,200 DBUCKS to Arena. Go back to the app that sent you here.'],
    ] as const) {
      const { calls } = phoneConnectedToArena([asked(ARENA, 7n, 'Arena', 'Pay 1,200 DBUCKS')], stepped);
      const { unmount } = render(<AppsScreen />);
      await act(settle);
      act(() => emit('connect.link', new TextEncoder().encode(`com.example.arena\n${CODE}`)));
      await act(settle);
      fireEvent.click(screen.getByRole('button', { name: 'APPROVE' }));
      await act(settle);
      expect(screen.getByText(said)).toBeInTheDocument();
      expect(calls).toEqual(['connect.connectedBy', 'connect.sync', 'connect.respond 7']);
      unmount();
      removeScriptedPhone();
    }
  });

  it('stays while another of its requests waits, and steps back after the last', async () => {
    // A phone that cannot step back says so only once the wallet asked it to.
    const { calls } = phoneConnectedToArena(
      [asked(ARENA, 7n, 'Arena', 'Pay 1,200 DBUCKS'), asked(ARENA, 8n, 'Arena', 'Pay 300 DBUCKS')],
      0,
    );
    render(<AppsScreen />);
    await act(settle);
    act(() => emit('connect.link', new TextEncoder().encode(`\n${CODE}`)));
    await act(settle);
    expect(screen.getByText(/An app your phone did not name opened the wallet for Arena/)).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole('button', { name: 'DECLINE' })[0]);
    await act(settle);
    expect(screen.getByText('Paid 1,200 DBUCKS to Arena.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'DECLINE' }));
    await act(settle);
    expect(screen.getByText('Paid 1,200 DBUCKS to Arena. Go back to the app that sent you here.')).toBeInTheDocument();
    expect(calls).toEqual(['connect.connectedBy', 'connect.sync', 'connect.respond 7', 'connect.respond 8']);
  });

  it('does not step back after a request of another application', async () => {
    const { calls } = phoneConnectedToArena([asked(OTHER, 2n, 'Bazaar', 'Pay 5 ERA')], 0);
    render(<AppsScreen />);
    await act(settle);
    act(() => emit('connect.link', new TextEncoder().encode(`\n${CODE}`)));
    await act(settle);
    fireEvent.click(screen.getByRole('button', { name: 'APPROVE' }));
    await act(settle);
    expect(screen.getByText('Paid 1,200 DBUCKS to Arena.')).toBeInTheDocument();
    expect(screen.queryByText(/Go back to the app that sent you here/)).toBeNull();
    expect(calls).toEqual(['connect.connectedBy', 'connect.sync', 'connect.respond 2']);
  });

  it('a request the player opened the wallet for themselves does not step back', async () => {
    const { calls } = phoneConnectedToArena([asked(ARENA, 7n, 'Arena', 'Pay 1,200 DBUCKS')], 0);
    render(<AppsScreen />);
    await act(settle);
    fireEvent.click(screen.getByRole('button', { name: /^Waiting/ }));
    await act(settle);
    fireEvent.click(screen.getByRole('button', { name: 'APPROVE' }));
    await act(settle);
    expect(screen.getByText('Paid 1,200 DBUCKS to Arena.')).toBeInTheDocument();
    expect(screen.queryByText(/Go back to the app that sent you here/)).toBeNull();
    expect(calls).toEqual(['connect.respond 7']);
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
