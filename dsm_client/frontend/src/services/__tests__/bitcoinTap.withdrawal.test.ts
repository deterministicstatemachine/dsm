// SPDX-License-Identifier: MIT OR Apache-2.0

import {
  ArgPack,
  BitcoinWithdrawalExecuteRequest,
  BitcoinWithdrawalExecuteResponse,
  BitcoinWithdrawalPlanRequest,
  BitcoinWithdrawalPlanResponse,
  BridgeRpcRequest,
  Envelope,
  IngressRequest,
  IngressResponse,
} from '../../proto/dsm_app_pb';

describe('bitcoinTap withdrawal planner service', () => {
  it('reviewWithdrawalPlan sends the planner request through nativeBoundaryIngress', async () => {
    let capturedReqBytes: Uint8Array | null = null;

    const plannerResponse = new BitcoinWithdrawalPlanResponse({
      planId: 'withdraw-1',
      planClass: 'single_full_sweep',
      requestedNetSats: 250_000n as any,
      plannedNetSats: 250_000n as any,
      totalGrossExitSats: 251_000n as any,
      totalFeeSats: 1_000n as any,
      shortfallSats: 0n as any,
      policyCommit: Uint8Array.from([9, 10, 11, 12]),
    });
    const env = new Envelope({
      version: 3,
      payload: {
        case: 'bitcoinWithdrawalPlanResponse',
        value: plannerResponse,
      },
    } as any);
    const envBytes = env.toBinary();
    const framedEnv = new Uint8Array(1 + envBytes.length);
    framedEnv[0] = 0x03;
    framedEnv.set(envBytes, 1);

    (global as any).window.DsmBridge = {
      sendMessageBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
        capturedReqBytes = new Uint8Array(reqBytes);
        return (global as any).createDsmBridgeSuccessResponse(
          new IngressResponse({
            result: { case: 'okBytes', value: framedEnv },
          }).toBinary(),
        );
      },
    };

    const { reviewWithdrawalPlan } = await import('../bitcoinTap');
    const result = await reviewWithdrawalPlan(250_000n, 'tb1qreviewdest');

    expect(capturedReqBytes).not.toBeNull();
    const bridgeReq = BridgeRpcRequest.fromBinary(capturedReqBytes!);
    expect(bridgeReq.method).toBe('nativeBoundaryIngress');
    // Both are oneofs: narrow on the case rather than reaching through the union.
    if (bridgeReq.payload.case !== 'bytes') throw new Error('expected a bytes payload');
    const ingressRequest = IngressRequest.fromBinary(bridgeReq.payload.value.data);
    const op = ingressRequest.operation;
    expect(op.case).toBe('routerQuery');
    if (op.case !== 'routerQuery') throw new Error('expected a routerQuery operation');
    expect(op.value.method).toBe('bitcoin.withdraw.plan');

    const argPack = ArgPack.fromBinary(op.value.args);
    const req = BitcoinWithdrawalPlanRequest.fromBinary(argPack.body as Uint8Array);
    expect(req.requestedNetSats).toBe(250_000n);
    expect(req.destinationAddress).toBe('tb1qreviewdest');
    expect(Array.from(result.policyCommit)).toEqual([9, 10, 11, 12]);
  });

  it('executeWithdrawalPlan sends plan_id and destination only', async () => {
    let capturedReqBytes: Uint8Array | null = null;

    const executeResponse = new BitcoinWithdrawalExecuteResponse({
      planId: 'withdraw-1',
      planClass: 'single_full_sweep',
      status: 'committed',
      message: 'Broadcast 1 withdrawal leg(s). Final burn will complete after confirmation depth is reached.',
      requestedNetSats: 250_000n as any,
      plannedNetSats: 250_000n as any,
      totalGrossExitSats: 251_000n as any,
      totalFeeSats: 1_000n as any,
      shortfallSats: 0n as any,
    });
    const env = new Envelope({
      version: 3,
      payload: {
        case: 'bitcoinWithdrawalExecuteResponse',
        value: executeResponse,
      },
    } as any);
    const envBytes = env.toBinary();
    const framedEnv = new Uint8Array(1 + envBytes.length);
    framedEnv[0] = 0x03;
    framedEnv.set(envBytes, 1);

    (global as any).window.DsmBridge = {
      sendMessageBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
        capturedReqBytes = new Uint8Array(reqBytes);
        return (global as any).createDsmBridgeSuccessResponse(
          new IngressResponse({
            result: { case: 'okBytes', value: framedEnv },
          }).toBinary(),
        );
      },
    };

    const { executeWithdrawalPlan } = await import('../bitcoinTap');
    const result = await executeWithdrawalPlan(
      'withdraw-1',
      'tb1qexecutedest',
    );

    expect(capturedReqBytes).not.toBeNull();
    const bridgeReq = BridgeRpcRequest.fromBinary(capturedReqBytes!);
    expect(bridgeReq.method).toBe('nativeBoundaryIngress');
    // Both are oneofs: narrow on the case rather than reaching through the union.
    if (bridgeReq.payload.case !== 'bytes') throw new Error('expected a bytes payload');
    const ingressRequest = IngressRequest.fromBinary(bridgeReq.payload.value.data);
    const op = ingressRequest.operation;
    expect(op.case).toBe('routerInvoke');
    if (op.case !== 'routerInvoke') throw new Error('expected a routerInvoke operation');
    expect(op.value.method).toBe('bitcoin.withdraw.execute');

    const argPack = ArgPack.fromBinary(op.value.args);
    const req = BitcoinWithdrawalExecuteRequest.fromBinary(argPack.body as Uint8Array);
    expect(req.planId).toBe('withdraw-1');
    expect(req.destinationAddress).toBe('tb1qexecutedest');
    expect(result.status).toBe('committed');
    expect(result.planId).toBe('withdraw-1');
  });
});
