// SPDX-License-Identifier: Apache-2.0
// Offline on the Modern send page shows the two things an offline send needs besides Bluetooth:
// the appliance, read through Rust the moment Offline is chosen, and the funding that moves a
// token into cash in hand. The real bridge code runs over a host that answers each route as the
// SDK does, and counts what it was asked; the page renders what came back.

import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../../proto/dsm_app_pb';
import ModernSend from '../ModernSend';
import { WalletContext } from '../../../contexts/WalletContext';
import { ContactsContext } from '../../../contexts/ContactsContext';
import type { TokenBalanceView } from '../../../dsm/types';

type BridgeAnswer = (bytes: Uint8Array) => Uint8Array;

function answerOf(payload: pb.Envelope['payload']): Uint8Array {
  const bytes = new pb.Envelope({ version: 3, payload }).toBinary();
  const framed = new Uint8Array(1 + bytes.length);
  framed[0] = 0x03;
  framed.set(bytes, 1);
  const ingress = new pb.IngressResponse({ result: { case: 'okBytes', value: framed } });
  const wrap = (globalThis as unknown as { createDsmBridgeSuccessResponse: BridgeAnswer })
    .createDsmBridgeSuccessResponse;
  return wrap(ingress.toBinary());
}

function routeOf(reqBytes: Uint8Array): { route: string; body: Uint8Array } {
  const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
  if (req.payload.case !== 'bytes') throw new Error(`a ${req.payload.case} payload`);
  const ingress = pb.IngressRequest.fromBinary(req.payload.value.data);
  if (ingress.operation.case === 'routerInvoke') return { route: ingress.operation.value.method, body: ingress.operation.value.args };
  if (ingress.operation.case === 'routerQuery') return { route: ingress.operation.value.method, body: ingress.operation.value.args };
  throw new Error(`an operation of ${ingress.operation.case}`);
}

/** A host with an installed anchor attached, answering status and the load as the SDK does. */
function hostWith(anchor: 'attached' | 'none') {
  const asked: string[] = [];
  const loaded: string[] = [];
  const status = new pb.AnchorStatusResponse({
    status: anchor === 'attached' ? 'trial anchor connected (counter u=0)' : 'no anchor appliance connected',
  });
  status.anchorConnected = anchor === 'attached';
  Object.assign(window, {
    DsmBridge: {
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const { route, body } = routeOf(reqBytes);
        asked.push(route);
        if (route === 'anchor.status') return answerOf({ case: 'anchorStatusResponse', value: status });
        if (route === 'wallet.loadOffline') {
          const arg = pb.ArgPack.fromBinary(body);
          const req = pb.OfflineCashRequest.fromBinary(arg.body);
          loaded.push(`${req.tokenId}:${req.amount}`);
          const res = new pb.OfflineCashResponse({
            message: 'loaded 5.00 ERA — offline allocation now 5.00, online 95.00',
            onlineDisplay: '95.00',
            allocationDisplay: '5.00',
          });
          res.success = req.amount === '5';
          return answerOf({ case: 'offlineCashResponse', value: res });
        }
        throw new Error(`a route this host does not answer: ${route}`);
      },
    },
  });
  return { asked, loaded };
}

function era(offline?: TokenBalanceView['offline']): TokenBalanceView {
  return {
    tokenId: 'ERA', symbol: 'ERA', tokenName: 'ERA', baseUnits: 10000n, displayAmount: '100.00', decimals: 2,
    protocolDefined: 'ERA'.length === 3, holding: 'currency', offline,
  };
}

function renderSend(balances: TokenBalanceView[]) {
  const refreshed: string[] = [];
  const loading = 'loaded';
  const wallet = {
    genesisHash: 'G', deviceId: 'ME', balances, transactions: [], isInitialized: loading === 'loaded', isLoading: loading !== 'loaded', error: null,
    refreshAll: async () => { refreshed.push('all'); }, refreshBalances: async () => undefined, refreshTransactions: async () => undefined,
    setError: () => undefined,
  };
  const contacts = {
    contacts: [], isLoading: loading !== 'loaded', error: null,
    refreshContacts: async () => undefined,
    addContact: async () => { throw new Error('not in this test'); },
    unpairContact: async () => undefined,
    setError: () => undefined,
  };
  render(
    <WalletContext.Provider value={wallet as never}>
      <ContactsContext.Provider value={contacts as never}>
        <ModernSend to={null} />
      </ContactsContext.Provider>
    </WalletContext.Provider>,
  );
  return { refreshed };
}

describe('offline on the Modern send page', () => {
  it('online mode shows the online amount and never reads the appliance', () => {
    const host = hostWith('attached');
    renderSend([era()]);
    expect(screen.getByText('100.00')).toBeInTheDocument();
    expect(screen.queryByLabelText('Appliance')).not.toBeInTheDocument();
    expect(host.asked).toEqual([]);
  });

  it('choosing Offline reads the appliance, shows cash in hand, and loads through Rust', async () => {
    const host = hostWith('attached');
    const { refreshed } = renderSend([era({ baseUnits: 500n, displayAmount: '5.00' })]);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    });
    await waitFor(() => expect(host.asked).toContain('anchor.status'));
    expect(screen.getByTestId('appliance-state')).toHaveTextContent('trial anchor connected (counter u=0)');
    expect(screen.getByText('Cash in hand', { selector: '.s-balance-label' })).toBeInTheDocument();
    expect(screen.getByText('5.00', { selector: '.s-balance-amount' })).toBeInTheDocument();
    expect(screen.getByTestId('offline-allocation')).toHaveTextContent('5.00 ERA');
    // A connected appliance means the balances can name their allocations: the wallet is read again.
    expect(refreshed.length).toBeGreaterThan(0);

    fireEvent.change(screen.getByLabelText('Amount', { selector: '#s-offline-amount' }), { target: { value: '5' } });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Load' }));
    });
    await waitFor(() => expect(host.loaded).toEqual(['ERA:5']));
    expect(await screen.findByRole('status')).toHaveTextContent('loaded 5.00 ERA');
  });

  it('with no appliance the allocation is unknown, not zero, and says so', async () => {
    const host = hostWith('none');
    renderSend([era()]);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Offline' }));
    });
    await waitFor(() => expect(host.asked).toContain('anchor.status'));
    expect(screen.getByTestId('appliance-state')).toHaveTextContent('no anchor appliance connected');
    expect(screen.getByTestId('send-offline-unknown')).toBeInTheDocument();
    expect(screen.getByTestId('offline-allocation')).toHaveTextContent('Unknown until the appliance connects');
    expect(screen.getByRole('button', { name: 'Connect' })).toBeInTheDocument();
  });
});
