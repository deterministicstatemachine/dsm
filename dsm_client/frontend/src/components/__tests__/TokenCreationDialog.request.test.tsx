// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The wizard sends Rust the token it will create, its genesis supply, its
// burn flag and its threshold, with every step's check. The bridge answers
// from Rust's own record of those checks (ingress.rs,
// token_check_answers_through_the_ingress_as_the_wizard_records_it), and it
// answers only a request byte for byte the one Rust recorded. Nothing in the
// dialog is replaced here.

import React from 'react';
import { join } from 'path';
import { fireEvent, render, screen, within } from '@testing-library/react';
import * as pb from '../../proto/dsm_app_pb';
import { TokenCreationDialog } from '../TokenCreationDialog';
import { answerFromRustRecord, readRustRecord } from '../../tests/helpers/rustIngressRecord';

const RECORD = join(__dirname, 'fixtures/token_check.ingress.bin');

/** The token.check request Rust recorded for `ticker`. */
function recordedCheck(ticker: string): pb.TokenCreateRequest {
  for (const { request } of readRustRecord(RECORD)) {
    const op = pb.IngressRequest.fromBinary(request).operation;
    if ((op.case === 'routerQuery' || op.case === 'routerInvoke') && op.value.method === 'token.check') {
      const r = pb.TokenCreateRequest.fromBinary(pb.ArgPack.fromBinary(op.value.args).body);
      if (r.ticker === ticker) return r;
    }
  }
  throw new Error(`the record holds no token.check of ${ticker}`);
}

describe('TokenCreationDialog request', () => {
  it('checks the genesis supply, burn flag and threshold it will create, byte for byte as Rust recorded them', async () => {
    const arrivals = answerFromRustRecord(RECORD);
    render(<TokenCreationDialog onClose={() => undefined} />);
    fireEvent.change(screen.getByLabelText(/Ticker/i), { target: { value: 'ART' } });
    fireEvent.change(screen.getByLabelText(/Display Name/i), { target: { value: 'Artwork' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue/i }));

    // The rules step opens only on Rust's answer, and Rust's record answers
    // only the check it recorded: the dialog sent exactly that request.
    expect(await screen.findByLabelText('Total Supply')).toBeInTheDocument();
    expect(arrivals).toContainEqual({ method: 'nativeBoundaryIngress', carried: 'token.check' });

    // That request carries the token as it will be created, and the rules
    // step shows the same genesis supply and burn flag.
    const sent = recordedCheck('ART');
    expect(sent.genesisSupplyEntered).not.toBe('');
    expect(sent.threshold).toBe(1);
    expect(screen.getByLabelText('Total Supply')).toHaveValue(sent.genesisSupplyEntered);
    expect(sent.burnEnabled).toBeFalsy();
    const burn = within(screen.getByRole('group', { name: 'Burn' }));
    expect(burn.getByRole('button', { name: 'Off' })).toHaveClass('active');
    expect(burn.getByRole('button', { name: 'On' })).not.toHaveClass('active');
  });
});
