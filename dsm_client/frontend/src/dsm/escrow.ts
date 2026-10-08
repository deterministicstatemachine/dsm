// SPDX-License-Identifier: MIT OR Apache-2.0

// Escrow vaults (SoFi §19.9, Amendment S21): the wallet reaches them only
// through these routes. A stake of one token is locked in a vault whose terms
// list outcomes, each naming who decides it and who it pays. Rust supplies
// every party's genesis and signing key, puts the terms in their canonical
// order, and answers what the vault's verdict cell holds; the app sends what
// the user entered and shows what Rust answers.
import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { emitWalletRefresh } from './events';
import { positionResult, type PositionResult } from './sofi';

/** The bytes in a buffer of their own, as the proto messages hold them. */
const own = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);

async function call(method: string, req: { toBinary(): Uint8Array }) {
  const argPack = new pb.ArgPack({
    codec: pb.Codec.PROTO,
    body: new Uint8Array(req.toBinary()),
  });
  const env = decodeFramedEnvelopeV3(
    await routerInvokeBin(method, new Uint8Array(argPack.toBinary())),
  );
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  return env.payload;
}

/** This device as an escrow party. */
export interface EscrowParty {
  genesis: Uint8Array;
  deviceId: Uint8Array;
}

export async function party(): Promise<EscrowParty> {
  const payload = await call('escrow.party', new pb.EscrowPartyRequest());
  if (payload.case !== 'escrowPartyResponse') {
    throw new Error(`Expected escrowPartyResponse, got ${payload.case}`);
  }
  return { genesis: payload.value.genesis, deviceId: payload.value.deviceId };
}

/** One outcome as the user names it: who decides it and who it pays, by device id. */
export interface EscrowLockOutcome {
  outcome: Uint8Array;
  decidedBy: Uint8Array[];
  pays: Uint8Array;
}

export interface EscrowLocked {
  vaultId: Uint8Array;
  /** K_verdict: every vault bound to the same agreement and outcomes shares it. */
  verdictCell: Uint8Array;
  externalCommitment: Uint8Array;
  position: bigint;
}

/**
 * Lock a stake. `external` is the agreement as the parties have it, of which
 * the vault keeps only the hash; `amountEntered` is in token units, as typed.
 * With a linked vault, the stake is locked only once that vault is active on
 * the same verdict cell.
 */
export async function lock(args: {
  external: Uint8Array;
  token: Uint8Array;
  amountEntered: string;
  outcomes: EscrowLockOutcome[];
  linkedVaultId?: Uint8Array;
}): Promise<EscrowLocked> {
  const payload = await call('escrow.lock', new pb.EscrowLockRequest({
    external: own(args.external),
    tokenPolicyCommit: own(args.token),
    amountEntered: args.amountEntered,
    outcomes: args.outcomes.map((o) => new pb.EscrowLockOutcomeV1({
      outcome: own(o.outcome),
      decidedBy: o.decidedBy.map(own),
      pays: own(o.pays),
    })),
    counterpartVaultId: args.linkedVaultId === undefined ? undefined : own(args.linkedVaultId),
  }));
  if (payload.case !== 'escrowCreatedResponse') {
    throw new Error(`Expected escrowCreatedResponse, got ${payload.case}`);
  }
  emitWalletRefresh({ source: 'escrow.lock' });
  const r = payload.value;
  return {
    vaultId: r.vaultId,
    verdictCell: r.verdictCell,
    externalCommitment: r.externalCommitment,
    position: r.position,
  };
}

export type EscrowStatus = 'active' | 'released';

/** One outcome of a vault's terms, and what it means for this device. */
export interface EscrowOutcome {
  outcome: Uint8Array;
  recipientDeviceId: Uint8Array;
  decidedByThisDevice: boolean;
  paysThisDevice: boolean;
}

export interface EscrowVault {
  vaultId: Uint8Array;
  ownerDeviceId: Uint8Array;
  verdictCell: Uint8Array;
  tokenSymbol: string;
  amountDisplay: string;
  status: EscrowStatus;
  outcomes: EscrowOutcome[];
}

function statusOf(status: pb.SofiVaultStatus): EscrowStatus {
  switch (status) {
    case pb.SofiVaultStatus.ACTIVE: return 'active';
    case pb.SofiVaultStatus.RETIRED: return 'released';
    default: throw new Error(`an escrow vault in status ${status}`);
  }
}

function vaultsOf(payload: Awaited<ReturnType<typeof call>>): EscrowVault[] {
  if (payload.case !== 'escrowVaultsResponse') {
    throw new Error(`Expected escrowVaultsResponse, got ${payload.case}`);
  }
  return payload.value.vaults.map((v) => ({
    vaultId: v.vaultId,
    ownerDeviceId: v.ownerDeviceId,
    verdictCell: v.verdictCell,
    tokenSymbol: v.tokenSymbol,
    amountDisplay: v.amountDisplay,
    status: statusOf(v.status),
    outcomes: v.outcomes.map((o) => ({
      outcome: o.outcome,
      recipientDeviceId: o.recipientDeviceId,
      decidedByThisDevice: o.decidedByThisDevice,
      paysThisDevice: o.paysThisDevice,
    })),
  }));
}

/** The escrow vaults this device locked. */
export async function vaults(): Promise<EscrowVault[]> {
  return vaultsOf(await call('escrow.vaults', new pb.EscrowVaultsRequest()));
}

/** The escrow vaults bound to a verdict cell, whoever locked them. */
export async function locked(verdictCell: Uint8Array): Promise<EscrowVault[]> {
  return vaultsOf(await call('escrow.locked', new pb.EscrowLockedRequest({ verdictCell: own(verdictCell) })));
}

export type VerdictState = 'none' | 'leaderHeld' | 'preserved' | 'final';

export interface EscrowVerdict {
  verdictCell: Uint8Array;
  state: VerdictState;
  /** The outcome the cell holds; empty with no verdict. */
  outcome: Uint8Array;
  /** Why each value ahead of the verdict counts as nothing. */
  passedOver: string[];
}

function verdictOf(payload: Awaited<ReturnType<typeof call>>): EscrowVerdict {
  if (payload.case !== 'escrowVerdictResponse') {
    throw new Error(`Expected escrowVerdictResponse, got ${payload.case}`);
  }
  const r = payload.value;
  const state: VerdictState = (() => {
    switch (r.state) {
      case pb.EscrowVerdictState.NONE: return 'none';
      case pb.EscrowVerdictState.LEADER_HELD: return 'leaderHeld';
      case pb.EscrowVerdictState.PRESERVED: return 'preserved';
      case pb.EscrowVerdictState.FINAL: return 'final';
      default: throw new Error(`a verdict in state ${r.state}`);
    }
  })();
  return { verdictCell: r.verdictCell, state, outcome: r.outcome, passedOver: r.passedOver };
}

/** What the vault's verdict cell holds. */
export async function verdict(vaultId: Uint8Array): Promise<EscrowVerdict> {
  return verdictOf(await call('escrow.verdict', new pb.EscrowVerdictRequest({ vaultId: own(vaultId) })));
}

/** Put this device's signature for `outcome` where the outcome's other signers find it. */
export async function sign(vaultId: Uint8Array, outcome: Uint8Array): Promise<void> {
  const payload = await call('escrow.sign', new pb.EscrowOutcomeRequest({ vaultId: own(vaultId), outcome: own(outcome) }));
  if (payload.case !== 'escrowSignedResponse') {
    throw new Error(`Expected escrowSignedResponse, got ${payload.case}`);
  }
}

/** Assemble the verdict for `outcome` from its signers' signatures and write it to the cell. */
export async function decide(vaultId: Uint8Array, outcome: Uint8Array): Promise<EscrowVerdict> {
  return verdictOf(await call('escrow.adjudicate', new pb.EscrowOutcomeRequest({ vaultId: own(vaultId), outcome: own(outcome) })));
}

/** Release the whole stake to this device, once the verdict is final on an outcome that pays it. */
export async function release(vaultId: Uint8Array): Promise<PositionResult> {
  const result = positionResult(await call('escrow.release', new pb.EscrowReleaseRequest({ vaultId: own(vaultId) })));
  emitWalletRefresh({ source: 'escrow.release' });
  return result;
}
