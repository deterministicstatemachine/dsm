// SPDX-License-Identifier: MIT OR Apache-2.0

import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin, routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { bytesToBase32CrockfordPrefix } from '../utils/textId';
import logger from '../utils/logger';

/**
 * Read-only offline-bearer anchor status for the diagnostics panel (Stage 4 Slice 3, signal c).
 * Pure render data derived from the `anchor.status` route — no protocol logic lives here.
 */
export interface AnchorStatus {
  /** Appliance attached and OP_STATUS read OK. */
  connected: boolean;
  /** Enrolled anchor identity (Crockford base32 prefix); '' when disconnected. */
  anchorIdB32: string;
  /** Resident Ed25519 chip pubkey (σ^chip) prefix; '' when disconnected. */
  pkChipB32: string;
  /** Live counter floor u_i. */
  anchorCounter: bigint;
  /** Current offline frontier h_i (base32 prefix). */
  frontierRootB32: string;
  /** Counter floor at enrollment. */
  enrolledCounter: bigint;
  /** Human-readable status line supplied by Rust. */
  statusText: string;
  /** A new anchor is connected and never installed: nothing about it is permanent yet. */
  awaitingInstall: boolean;
}

/** One thing a try-run went through, as Rust reported it. */
export interface AnchorTryRunStep {
  name: string;
  passed: boolean;
  detail: string;
  /** A production install's requirement alone: the anchor works without it. An install for good waits for it; a trial install does not. */
  production: boolean;
}

/** An install gone through on the anchor with its permanent parts substituted. */
export interface AnchorTryRun {
  passed: boolean;
  steps: AnchorTryRunStep[];
  /** The install would be a trial: nothing on the anchor is permanent, and its next boot ends it. */
  trial: boolean;
  /** What installing makes permanent, shown before it is asked for. */
  permanent: string[];
  /** Why it could not run at all. */
  refused: string;
}

const NO_ARGS = () => new Uint8Array(new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) }).toBinary());

/**
 * Go through an install on the connected anchor with its permanent parts substituted (`anchor.tryRun`).
 * Binds nothing. A whole payment on the real chip: expect a minute or more.
 */
export async function runAnchorTryRun(): Promise<AnchorTryRun> {
  const env = decodeFramedEnvelopeV3(await routerQueryBin('anchor.tryRun', NO_ARGS()));
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'the try-run failed');
  }
  if (env.payload.case !== 'anchorTryRunResponse') {
    throw new Error(`runAnchorTryRun: unexpected payload ${env.payload.case}`);
  }
  const resp = env.payload.value;
  return {
    passed: resp.passed,
    steps: resp.steps.map((step) => ({
      name: step.name,
      passed: step.passed,
      detail: step.detail,
      production: step.production,
    })),
    trial: resp.trial,
    permanent: [...resp.permanent],
    refused: resp.refused,
  };
}

/** Install the connected anchor for this wallet (`anchor.install`): for good, or a trial on the trial image. */
export async function installAnchor(): Promise<AnchorStatus> {
  const env = decodeFramedEnvelopeV3(await routerInvokeBin('anchor.install', NO_ARGS()));
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || 'the install failed');
  }
  if (env.payload.case !== 'anchorStatusResponse') {
    throw new Error(`installAnchor: unexpected payload ${env.payload.case}`);
  }
  return statusOf(env.payload.value);
}

/** Base32-encode a 32-byte field for display, treating an all-zero/empty field as "not present". */
function b32OrEmpty(bytes: Uint8Array | undefined, prefixLen: number): string {
  if (!bytes || bytes.length === 0 || bytes.every((x) => x === 0)) return '';
  return bytesToBase32CrockfordPrefix(bytes, prefixLen);
}

function statusOf(resp: pb.AnchorStatusResponse): AnchorStatus {
  return {
    connected: resp.anchorConnected,
    anchorIdB32: b32OrEmpty(resp.anchorId, 12),
    pkChipB32: b32OrEmpty(resp.pkChip, 12),
    anchorCounter: resp.anchorCounter,
    frontierRootB32: b32OrEmpty(resp.frontierRoot, 12),
    enrolledCounter: resp.enrolledCounter,
    statusText: resp.status,
    awaitingInstall: resp.awaitingInstall,
  };
}

/**
 * Query the sender's anchor appliance status (`anchor.status` route). Read-only diagnostics: the
 * Rust handler never mutates device or appliance state. A disconnected appliance returns a
 * `connected=false` snapshot rather than throwing — that is an expected, renderable state.
 */
export async function getAnchorStatus(): Promise<AnchorStatus> {
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(0) });
  const resBytes = await routerQueryBin('anchor.status', new Uint8Array(arg.toBinary()));
  if (!resBytes || resBytes.length === 0) {
    throw new Error('getAnchorStatus: empty response from bridge');
  }

  const env = decodeFramedEnvelopeV3(resBytes);
  if (env.payload.case === 'error') {
    throw new Error(`getAnchorStatus: ${env.payload.value.message || 'unknown error'}`);
  }
  if (env.payload.case !== 'anchorStatusResponse') {
    throw new Error(`getAnchorStatus: unexpected payload ${env.payload.case}`);
  }

  const resp = env.payload.value;
  if (!resp) {
    throw new Error('getAnchorStatus: anchorStatusResponse payload is null');
  }

  logger.debug('[DSM:getAnchorStatus] snapshot', {
    connected: resp.anchorConnected,
    counter: String(resp.anchorCounter),
  });

  return statusOf(resp);
}

/** One step of a board's one-time setup for production, as Rust reports it. */
export interface BoardSetupStep {
  kind: pb.AnchorBoardStepKind;
  /** `blocked`: the board's bootloader cannot write what is left, and `refused` says why. */
  state: 'done' | 'next' | 'later' | 'blocked';
  /** It burns OTP: it can never be undone. */
  permanent: boolean;
  name: string;
}

/**
 * A board in BOOTSEL as its own bootloader shows it, read fresh, and where its setup stands. The
 * phone drives the board's bootloader itself: nothing but the phone is needed (owner, 2026-11-11).
 */
export interface BoardSetup {
  connected: boolean;
  /** The board's RP2350 chip id, as its bootloader names itself. */
  chipId: string;
  /** The production release this app carries, or why it carries none. */
  release: string;
  steps: BoardSetupStep[];
  /** Why the setup cannot go on, or why the last step stopped. */
  refused: string;
  /** What the read-only check found beyond blank. */
  found: string[];
  /** The last step's rows, each confirmed by its read-back. */
  written: string[];
  /** Every step is done: the board goes on to its install. */
  done: boolean;
}

const stateOf = (state: pb.AnchorBoardStepState): BoardSetupStep['state'] => {
  switch (state) {
    case pb.AnchorBoardStepState.DONE:
      return 'done';
    case pb.AnchorBoardStepState.NEXT:
      return 'next';
    case pb.AnchorBoardStepState.LATER:
      return 'later';
    case pb.AnchorBoardStepState.BLOCKED:
      return 'blocked';
    default:
      throw new Error(`a board step state this app does not know: ${state}`);
  }
};

function boardSetupOf(bytes: Uint8Array, route: string): BoardSetup {
  const env = decodeFramedEnvelopeV3(bytes);
  if (env.payload.case === 'error') {
    throw new Error(env.payload.value.message || `${route} failed`);
  }
  if (env.payload.case !== 'anchorBoardResponse') {
    throw new Error(`${route}: unexpected payload ${env.payload.case}`);
  }
  const resp = env.payload.value;
  return {
    connected: resp.boardConnected,
    chipId: resp.chipId,
    release: resp.release,
    steps: resp.steps.map((step) => ({
      kind: step.kind,
      state: stateOf(step.state),
      permanent: step.permanent,
      name: step.name,
    })),
    refused: resp.refused,
    found: [...resp.found],
    written: [...resp.written],
    done: resp.done,
  };
}

/** Read the board in BOOTSEL and where its setup stands (`anchor.board.read`). Writes nothing. */
export async function readBoardSetup(): Promise<BoardSetup> {
  return boardSetupOf(await routerQueryBin('anchor.board.read', NO_ARGS()), 'anchor.board.read');
}

/**
 * Run the board's next step (`anchor.board.step`) on the board whose chip id is given: Rust runs it
 * only if it is that board's next step, and only on that board.
 */
export async function stepBoardSetup(kind: pb.AnchorBoardStepKind, chipId: string): Promise<BoardSetup> {
  const request = new pb.AnchorBoardStepRequest({ step: kind, chipId });
  const arg = new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(request.toBinary()) });
  return boardSetupOf(await routerInvokeBin('anchor.board.step', new Uint8Array(arg.toBinary())), 'anchor.board.step');
}
