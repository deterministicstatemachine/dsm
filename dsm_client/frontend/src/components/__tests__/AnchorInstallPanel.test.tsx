// SPDX-License-Identifier: Apache-2.0
//! Connecting a new anchor does nothing permanent. The install is offered only after a try-run has
//! passed, says what it makes permanent, and takes a second tap. On the trial image it is a trial
//! install, and says so. The real bridge code runs here over a host that answers each route as the
//! SDK does, and counts what it was asked.

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../proto/dsm_app_pb';
import { AppliancePopover } from '../screens/wallet/AppliancePopover';
import { getAnchorStatus } from '../../dsm/anchor';

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

function routeOf(reqBytes: Uint8Array): string {
  const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
  if (req.payload.case !== 'bytes') throw new Error(`a ${req.payload.case} payload`);
  const ingress = pb.IngressRequest.fromBinary(req.payload.value.data);
  if (ingress.operation.case === 'routerInvoke') return ingress.operation.value.method;
  if (ingress.operation.case === 'routerQuery') return ingress.operation.value.method;
  throw new Error(`an operation of ${ingress.operation.case}`);
}

const PERMANENT = 'This anchor is bound to this wallet.';
const TRIAL = 'Nothing on the chip or the board is permanent.';

function hostWith(tryRun: pb.AnchorTryRunResponse, awaiting: 'new anchor' | 'nothing new') {
  const asked: string[] = [];
  const installed = new pb.AnchorStatusResponse({ status: 'anchor connected (counter u=0)' });
  installed.anchorConnected = awaiting === 'new anchor';
  const status = new pb.AnchorStatusResponse({
    status: 'a new anchor is connected. Nothing about it is permanent yet.',
  });
  status.awaitingInstall = awaiting === 'new anchor';
  Object.assign(window, {
    DsmBridge: {
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const route = routeOf(reqBytes);
        asked.push(route);
        if (route === 'anchor.status') return answerOf({ case: 'anchorStatusResponse', value: status });
        if (route === 'anchor.tryRun') return answerOf({ case: 'anchorTryRunResponse', value: tryRun });
        if (route === 'anchor.install') return answerOf({ case: 'anchorStatusResponse', value: installed });
        throw new Error(`a route this host does not answer: ${route}`);
      },
    },
  });
  return asked;
}

function report(stepPassed: 'passed' | 'failed'): pb.AnchorTryRunResponse {
  const step = new pb.AnchorTryRunStep({ name: 'the chip signs' });
  step.passed = stepPassed === 'passed';
  const run = new pb.AnchorTryRunResponse({ steps: [step], permanent: [PERMANENT] });
  run.passed = stepPassed === 'passed';
  return run;
}

type StepOf = {
  name: string;
  outcome: 'passed' | 'failed';
  requirement: 'works' | 'production';
  detail: string;
};

/** A run of these steps, as the anchor answers it: an install for good passes only when every step
 *  did, and a trial install passes over what a production install alone needs. */
function reportOf(steps: StepOf[], install: 'for good' | 'trial'): pb.AnchorTryRunResponse {
  const run = new pb.AnchorTryRunResponse({
    steps: steps.map((s) => {
      const step = new pb.AnchorTryRunStep({ name: s.name, detail: s.detail });
      step.passed = s.outcome === 'passed';
      step.production = s.requirement === 'production';
      return step;
    }),
    permanent: [install === 'trial' ? TRIAL : PERMANENT],
  });
  run.trial = install === 'trial';
  run.passed = steps.every((s) => s.outcome === 'passed' || (run.trial && s.requirement === 'production'));
  return run;
}

/** The anchor works, and a production install still waits for a tested PTRNG. */
const PTRNG_UNTESTED: StepOf[] = [
  { name: 'the chip signs', outcome: 'passed', requirement: 'works', detail: '' },
  {
    name: 'the chip tests its PTRNG at start-up',
    outcome: 'failed',
    requirement: 'production',
    detail: 'it does not',
  },
];

async function popover(onConnect: () => Promise<void>) {
  const status = await getAnchorStatus();
  const onClose = () => undefined;
  return render(
    <AppliancePopover read={{ kind: 'read', status }} busy={status.connected} onConnect={onConnect} onClose={onClose} />,
  );
}

const nothing = async () => undefined;

describe('the install of a new anchor', () => {
  it('is not offered when no new anchor is connected', async () => {
    hostWith(report('passed'), 'nothing new');
    await popover(nothing);
    expect(screen.queryByTestId('anchor-install')).toBeNull();
  });

  it('happens only after a passing try-run and a second tap, and reads the anchor again', async () => {
    const asked = hostWith(report('passed'), 'new anchor');
    const reads: string[] = [];
    await popover(async () => {
      reads.push('read again');
    });
    expect(asked).toEqual(['anchor.status']);

    fireEvent.click(screen.getByRole('button', { name: 'Try the install' }));
    expect(await screen.findByText(PERMANENT)).toBeInTheDocument();
    expect(screen.getByText(/the chip signs/)).toBeInTheDocument();
    expect(asked).not.toContain('anchor.install');

    fireEvent.click(screen.getByRole('button', { name: 'Install…' }));
    expect(asked).not.toContain('anchor.install');
    fireEvent.click(screen.getByRole('button', { name: 'Yes, make it permanent' }));
    await waitFor(() => expect(reads).toEqual(['read again']));
    expect(asked.filter((route) => route === 'anchor.install')).toHaveLength(1);
  });

  it('shows what a production install still needs apart from the steps, and offers no install', async () => {
    hostWith(reportOf(PTRNG_UNTESTED, 'for good'), 'new anchor');
    await popover(nothing);
    fireEvent.click(screen.getByRole('button', { name: 'Try the install' }));
    const unmet = await screen.findByTestId('anchor-production-unmet');
    expect(unmet).toHaveTextContent('the chip tests its PTRNG at start-up (it does not)');
    expect(screen.getByText('Not ready for a production install')).toBeInTheDocument();
    expect(screen.getByTestId('anchor-try-run-steps')).toHaveTextContent('OK: the chip signs');
    expect(screen.getByTestId('anchor-try-run-steps')).not.toHaveTextContent('PTRNG');
    expect(screen.queryByText(/FAILED/)).toBeNull();
    expect(screen.queryByRole('button', { name: 'Install…' })).toBeNull();
  });

  it('on the trial image is a trial install over what production still needs, and says so', async () => {
    const asked = hostWith(reportOf(PTRNG_UNTESTED, 'trial'), 'new anchor');
    await popover(nothing);
    fireEvent.click(screen.getByRole('button', { name: 'Try the install' }));
    expect(await screen.findByText(TRIAL)).toBeInTheDocument();
    expect(screen.getByText('A trial install: what it leaves')).toBeInTheDocument();
    expect(screen.queryByText('Installing makes these permanent')).toBeNull();
    expect(screen.getByTestId('anchor-production-unmet')).toHaveTextContent('PTRNG');

    fireEvent.click(screen.getByRole('button', { name: 'Trial install…' }));
    expect(asked).not.toContain('anchor.install');
    fireEvent.click(screen.getByRole('button', { name: 'Yes, trial install' }));
    await waitFor(() => expect(asked.filter((route) => route === 'anchor.install')).toHaveLength(1));
  });

  it('is never offered after a try-run that failed', async () => {
    hostWith(report('failed'), 'new anchor');
    await popover(nothing);
    fireEvent.click(screen.getByRole('button', { name: 'Try the install' }));
    expect(await screen.findByText(/FAILED/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Install…' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Try it again' })).toBeEnabled();
  });
});
