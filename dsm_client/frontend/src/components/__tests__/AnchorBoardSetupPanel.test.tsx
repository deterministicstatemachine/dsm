// SPDX-License-Identifier: Apache-2.0
//! A board's one-time setup from the phone: the panel shows what Rust read off the board, offers only
//! the step Rust names next, and sends it only once the chip's last four characters are typed back,
//! with the chip id the board read named. The real bridge code runs here over a host that answers each
//! route as the SDK does, and keeps what it was asked.

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import * as pb from '../../proto/dsm_app_pb';
import AnchorBoardSetupPanel from '../AnchorBoardSetupPanel';

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

type Asked = { route: string; step?: pb.AnchorBoardStepRequest };

function askedOf(reqBytes: Uint8Array): Asked {
  const req = pb.BridgeRpcRequest.fromBinary(reqBytes);
  if (req.payload.case !== 'bytes') throw new Error(`a ${req.payload.case} payload`);
  const ingress = pb.IngressRequest.fromBinary(req.payload.value.data);
  if (ingress.operation.case === 'routerQuery') return { route: ingress.operation.value.method };
  if (ingress.operation.case === 'routerInvoke') {
    const args = pb.ArgPack.fromBinary(ingress.operation.value.args);
    return { route: ingress.operation.value.method, step: pb.AnchorBoardStepRequest.fromBinary(args.body) };
  }
  throw new Error(`an operation of ${ingress.operation.case}`);
}

const CHIP = '430ED6D919933C8E';
const K = pb.AnchorBoardStepKind;
const S = pb.AnchorBoardStepState;

const NAMES = new Map<pb.AnchorBoardStepKind, string>([
  [K.LOAD_IMAGE, 'Load the signed image into flash'],
  [K.SEAL_SECRET, "Write the board's secret and lock its page"],
  [K.WRITE_DIGEST, 'Burn the firmware digest'],
  [K.LOCK_DIGEST, 'Lock the digest page'],
  [K.WRITE_BOOT_KEY, "Burn the boot key's hash"],
  [K.LOCKDOWN, 'Lock down: secure boot on, debug off'],
  [K.BOOT, 'Start the signed image once'],
  [K.LOCK_BOOT_PAGES, 'Lock the boot pages'],
]);

function nameOf(kind: pb.AnchorBoardStepKind): string {
  const name = NAMES.get(kind);
  if (name === undefined) throw new Error(`no name for step ${kind}`);
  return name;
}

function boardWith(next: pb.AnchorBoardStepKind, written: string[]): pb.AnchorBoardResponse {
  const order = [K.LOAD_IMAGE, K.SEAL_SECRET, K.WRITE_DIGEST, K.LOCK_DIGEST, K.WRITE_BOOT_KEY, K.LOCKDOWN, K.BOOT, K.LOCK_BOOT_PAGES];
  const at = order.indexOf(next);
  const board = new pb.AnchorBoardResponse({
    chipId: CHIP,
    release: 'the production release this app carries: a signed image of 254840 bytes',
    steps: order.map(
      (kind, i) =>
        new pb.AnchorBoardStep({
          kind,
          state: i < at || kind === K.SEAL_SECRET ? S.DONE : i === at ? S.NEXT : S.LATER,
          name: nameOf(kind),
        }),
    ),
    found: ['boot configuration page lock already holds 0x40404'],
    written,
  });
  board.boardConnected = board.chipId.length === 16;
  board.steps.forEach((step) => {
    step.permanent = step.kind !== K.LOAD_IMAGE;
  });
  return board;
}

function hostAnswering(read: pb.AnchorBoardResponse, afterStep: pb.AnchorBoardResponse): Asked[] {
  const asked: Asked[] = [];
  Object.assign(window, {
    DsmBridge: {
      sendMessageBin: async (reqBytes: Uint8Array) => {
        const what = askedOf(reqBytes);
        asked.push(what);
        if (what.route === 'anchor.board.read') return answerOf({ case: 'anchorBoardResponse', value: read });
        if (what.route === 'anchor.board.step') return answerOf({ case: 'anchorBoardResponse', value: afterStep });
        throw new Error(`a route this host does not answer: ${what.route}`);
      },
    },
  });
  return asked;
}

describe('a board set up from the phone', () => {
  it('reads the board and shows its chip, its steps and what the check found', async () => {
    hostAnswering(boardWith(K.LOAD_IMAGE, []), boardWith(K.WRITE_DIGEST, []));
    render(<AnchorBoardSetupPanel />);
    fireEvent.click(screen.getByText('Read board'));
    await waitFor(() => expect(screen.getByTestId('anchor-board-chip')).toHaveTextContent(CHIP));
    const steps = screen.getByTestId('anchor-board-steps');
    expect(steps).toHaveTextContent('NEXT: Load the signed image into flash');
    expect(steps).toHaveTextContent("DONE: Write the board's secret and lock its page");
    expect(steps).toHaveTextContent('LATER: Burn the firmware digest');
    expect(screen.getByTestId('anchor-board-found')).toHaveTextContent('0x40404');
  });

  it('sends the step only once the chip is typed back, with the chip the board named', async () => {
    const asked = hostAnswering(
      boardWith(K.LOAD_IMAGE, []),
      boardWith(K.WRITE_DIGEST, ['flash: the signed image, 254840 bytes, read back whole']),
    );
    render(<AnchorBoardSetupPanel />);
    fireEvent.click(screen.getByText('Read board'));
    await waitFor(() => screen.getByText('Next step…'));
    fireEvent.click(screen.getByText('Next step…'));
    const go = screen.getByText('Go on');
    expect(go).toBeDisabled();
    fireEvent.change(screen.getByTestId('anchor-board-confirm'), { target: { value: '6f81' } });
    expect(go).toBeDisabled();
    fireEvent.change(screen.getByTestId('anchor-board-confirm'), { target: { value: '3c8e' } });
    expect(go).toBeEnabled();
    fireEvent.click(go);
    await waitFor(() => expect(screen.getByTestId('anchor-board-written')).toHaveTextContent('read back whole'));
    const sent = asked.filter((a) => a.route === 'anchor.board.step');
    expect(sent).toHaveLength(1);
    expect(sent[0].step?.step).toBe(K.LOAD_IMAGE);
    expect(sent[0].step?.chipId).toBe(CHIP);
  });

  it('names a permanent step as one that can never be undone', async () => {
    hostAnswering(boardWith(K.WRITE_DIGEST, []), boardWith(K.LOCK_DIGEST, []));
    render(<AnchorBoardSetupPanel />);
    fireEvent.click(screen.getByText('Read board'));
    await waitFor(() => screen.getByText('Next step…'));
    fireEvent.click(screen.getByText('Next step…'));
    expect(screen.getByText(/Burn the firmware digest can never be undone/)).toBeInTheDocument();
    expect(screen.getByText('Burn it')).toBeDisabled();
  });

  it('offers the changed-image check only before the first boot, and sends it once typed back', async () => {
    const asked = hostAnswering(
      boardWith(K.BOOT, []),
      boardWith(K.BOOT, ['a changed image was refused: the board found no image it may run and came back in BOOTSEL']),
    );
    render(<AnchorBoardSetupPanel />);
    fireEvent.click(screen.getByText('Read board'));
    await waitFor(() => screen.getByTestId('anchor-board-check'));
    fireEvent.click(screen.getByTestId('anchor-board-check'));
    expect(screen.getByText(/must come back in BOOTSEL/)).toBeInTheDocument();
    const go = screen.getByText('Go on');
    expect(go).toBeDisabled();
    fireEvent.change(screen.getByTestId('anchor-board-confirm'), { target: { value: '3C8E' } });
    fireEvent.click(go);
    await waitFor(() => expect(screen.getByTestId('anchor-board-written')).toHaveTextContent('was refused'));
    const sent = asked.filter((a) => a.route === 'anchor.board.step');
    expect(sent).toHaveLength(1);
    expect(sent[0].step?.step).toBe(K.CHECK_CHANGED_IMAGE);
  });

  it('does not offer the check while the board is not at its first boot', async () => {
    hostAnswering(boardWith(K.WRITE_DIGEST, []), boardWith(K.WRITE_DIGEST, []));
    render(<AnchorBoardSetupPanel />);
    fireEvent.click(screen.getByText('Read board'));
    await waitFor(() => screen.getByText('Next step…'));
    expect(screen.queryByTestId('anchor-board-check')).not.toBeInTheDocument();
  });
});
