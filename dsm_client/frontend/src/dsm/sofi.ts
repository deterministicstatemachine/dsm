// SPDX-License-Identifier: MIT OR Apache-2.0

/* eslint-disable @typescript-eslint/no-explicit-any */
// SoFi routes (SoFi §27): the app reaches SoFi only through these. Each call
// sends the user's intent; Rust assembles, Core decides.
import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';
import { emitWalletRefresh } from './events';

type Bytes32 = Uint8Array;

async function call(method: string, req: { toBinary(): Uint8Array }) {
  const argPack = new pb.ArgPack({
    codec: pb.Codec.PROTO as any,
    body: new Uint8Array(req.toBinary()),
  });
  const env = decodeFramedEnvelopeV3(
    await routerInvokeBin(method, new Uint8Array(argPack.toBinary())),
  );
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  return env.payload;
}

/** Where a trade, route, close or resolve left the device's position. */
export type PositionState = 'realized' | 'void' | 'invalid' | 'retriesExhausted';

export interface PositionResult {
  position: bigint;
  state: PositionState;
}

function positionResult(payload: any): PositionResult {
  if (payload.case !== 'sofiPositionResponse') {
    throw new Error(`Expected sofiPositionResponse, got ${payload.case}`);
  }
  const r = payload.value;
  const state: PositionState =
    r.state === pb.SofiPositionState.REALIZED
      ? 'realized'
      : r.state === pb.SofiPositionState.VOID
        ? 'void'
        : r.state === pb.SofiPositionState.INVALID
          ? 'invalid'
          : r.state === pb.SofiPositionState.RETRIES_EXHAUSTED
            ? 'retriesExhausted'
            : (() => {
                throw new Error(`unknown SoFi position state ${r.state}`);
              })();
  if (state === 'realized' || state === 'void') {
    emitWalletRefresh({ source: 'sofi', tokenId: '', anchorBase32: '' });
  }
  return { position: r.position, state };
}

/** sofi.createVault (§28): the pair (ordered), both reserves, and the fee. */
export async function createVault(args: {
  tokenA: Bytes32;
  tokenB: Bytes32;
  reserveA: bigint;
  reserveB: bigint;
  feeBps: number;
}): Promise<{ vaultId: Bytes32; position: bigint }> {
  const payload = await call(
    'sofi.createVault',
    new pb.SofiCreateVaultRequest({
      tokenAPolicyCommit: args.tokenA,
      tokenBPolicyCommit: args.tokenB,
      reserveA: args.reserveA,
      reserveB: args.reserveB,
      feeBps: args.feeBps,
    } as any),
  );
  if (payload.case !== 'sofiVaultCreatedResponse') {
    throw new Error(`Expected sofiVaultCreatedResponse, got ${payload.case}`);
  }
  emitWalletRefresh({ source: 'sofi.createVault', tokenId: '', anchorBase32: '' });
  return { vaultId: payload.value.vaultId, position: payload.value.position };
}

/** sofi.setup (§29): set up with a vault once, before trading against it. */
export async function setup(vaultId: Bytes32): Promise<{ setupRef: Bytes32; position: bigint }> {
  const payload = await call('sofi.setup', new pb.SofiSetupRequest({ vaultId } as any));
  if (payload.case !== 'sofiSetupResponse') {
    throw new Error(`Expected sofiSetupResponse, got ${payload.case}`);
  }
  return { setupRef: payload.value.setupRef, position: payload.value.position };
}

export interface Hop {
  vaultId: Bytes32;
  parentRoot: Bytes32;
  tokenIn: Bytes32;
  tokenOut: Bytes32;
  amountIn: bigint;
  amountOut: bigint;
}

/** sofi.findRoute (§30): a proposed hop list. It carries no authority. */
export async function findRoute(args: {
  tokenIn: Bytes32;
  tokenOut: Bytes32;
  amountIn: bigint;
}): Promise<Hop[]> {
  const payload = await call(
    'sofi.findRoute',
    new pb.SofiFindRouteRequest({
      tokenInPolicyCommit: args.tokenIn,
      tokenOutPolicyCommit: args.tokenOut,
      amountIn: args.amountIn,
    } as any),
  );
  if (payload.case !== 'sofiFindRouteResponse') {
    throw new Error(`Expected sofiFindRouteResponse, got ${payload.case}`);
  }
  return payload.value.hops.map((h: any) => ({
    vaultId: h.vaultId,
    parentRoot: h.parentRoot,
    tokenIn: h.tokenInPolicyCommit,
    tokenOut: h.tokenOutPolicyCommit,
    amountIn: h.amountIn,
    amountOut: h.amountOut,
  }));
}

/** sofi.trade (§31): one hop against one vault. */
export async function trade(args: {
  vaultId: Bytes32;
  tokenIn: Bytes32;
  amountIn: bigint;
  minAmountOut: bigint;
}): Promise<PositionResult> {
  return positionResult(
    await call(
      'sofi.trade',
      new pb.SofiTradeRequest({
        vaultId: args.vaultId,
        tokenInPolicyCommit: args.tokenIn,
        amountIn: args.amountIn,
        minAmountOut: args.minAmountOut,
      } as any),
    ),
  );
}

/** sofi.route (§31): a multihop route through distinct vaults, all or none. */
export async function route(args: {
  vaultIds: Bytes32[];
  tokenIn: Bytes32;
  amountIn: bigint;
  minAmountOut: bigint;
}): Promise<PositionResult> {
  return positionResult(
    await call(
      'sofi.route',
      new pb.SofiRouteRequest({
        vaultIds: args.vaultIds,
        tokenInPolicyCommit: args.tokenIn,
        amountIn: args.amountIn,
        minAmountOut: args.minAmountOut,
      } as any),
    ),
  );
}

/** sofi.close (§32): the owner closes its own vault. */
export async function close(vaultId: Bytes32): Promise<PositionResult> {
  return positionResult(await call('sofi.close', new pb.SofiCloseRequest({ vaultId } as any)));
}

/** sofi.resolve (§27): resolve and advance this device's pending position. */
export async function resolve(): Promise<PositionResult> {
  return positionResult(await call('sofi.resolve', new pb.SofiResolveRequest({} as any)));
}

/** sofi.relay (§33): complete someone's registered fulfillment. */
export async function relay(args: {
  traderGenesis: Bytes32;
  traderDeviceId: Bytes32;
  position: bigint;
}): Promise<{ cellsWritten: number }> {
  const payload = await call(
    'sofi.relay',
    new pb.SofiRelayRequest({
      traderGenesis: args.traderGenesis,
      traderDeviceId: args.traderDeviceId,
      position: args.position,
    } as any),
  );
  if (payload.case !== 'sofiRelayResponse') {
    throw new Error(`Expected sofiRelayResponse, got ${payload.case}`);
  }
  return { cellsWritten: payload.value.cellsWritten };
}
