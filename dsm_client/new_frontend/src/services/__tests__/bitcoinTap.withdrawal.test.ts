import {
  ArgPack,
  AppRouterPayload,
  BitcoinWithdrawalExecuteRequest,
  BitcoinWithdrawalExecuteResponse,
  BitcoinWithdrawalPlanRequest,
  BitcoinWithdrawalPlanResponse,
  BridgeRpcRequest,
  Envelope,
} from '../../proto/dsm_app_pb';

function routerResponseBytes(framedEnv: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + framedEnv.length);
  out.set(framedEnv, 8);
  return out;
}

describe('bitcoinTap withdrawal planner service', () => {
  it('reviewWithdrawalPlan sends the planner request through appRouterQuery', async () => {
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
      __callBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
        capturedReqBytes = new Uint8Array(reqBytes);
        return (global as any).createDsmBridgeSuccessResponse(routerResponseBytes(framedEnv));
      },
    };

    const { reviewWithdrawalPlan } = await import('../bitcoinTap');
    const result = await reviewWithdrawalPlan(250_000n, 'tb1qreviewdest');

    expect(capturedReqBytes).not.toBeNull();
    const bridgeReq = BridgeRpcRequest.fromBinary(capturedReqBytes!);
    expect(bridgeReq.method).toBe('appRouterQuery');

    const routerPayload = bridgeReq.payload;
    expect(routerPayload.case).toBe('appRouter');
    const appRouter = routerPayload.value as AppRouterPayload;
    expect(appRouter.methodName).toBe('bitcoin.withdraw.plan');

    const argPack = ArgPack.fromBinary(appRouter.args);
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
      status: 'completed',
      message: 'Executed 1 withdrawal leg(s)',
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
      __callBin: async (reqBytes: Uint8Array): Promise<Uint8Array> => {
        capturedReqBytes = new Uint8Array(reqBytes);
        return (global as any).createDsmBridgeSuccessResponse(routerResponseBytes(framedEnv));
      },
    };

    const { executeWithdrawalPlan } = await import('../bitcoinTap');
    const result = await executeWithdrawalPlan(
      'withdraw-1',
      'tb1qexecutedest',
    );

    expect(capturedReqBytes).not.toBeNull();
    const bridgeReq = BridgeRpcRequest.fromBinary(capturedReqBytes!);
    expect(bridgeReq.method).toBe('appRouterInvoke');

    const routerPayload = bridgeReq.payload;
    expect(routerPayload.case).toBe('appRouter');
    const appRouter = routerPayload.value as AppRouterPayload;
    expect(appRouter.methodName).toBe('bitcoin.withdraw.execute');

    const argPack = ArgPack.fromBinary(appRouter.args);
    const req = BitcoinWithdrawalExecuteRequest.fromBinary(argPack.body as Uint8Array);
    expect(req.planId).toBe('withdraw-1');
    expect(req.destinationAddress).toBe('tb1qexecutedest');
    expect(result.status).toBe('completed');
    expect(result.planId).toBe('withdraw-1');
  });
});
