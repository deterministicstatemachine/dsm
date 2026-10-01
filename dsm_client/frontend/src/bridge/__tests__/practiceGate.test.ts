// SPDX-License-Identifier: Apache-2.0
//! While the tour's practice wallet stands in, the bridge lets only reads reach
//! native code, whatever module makes the call. Practice mode used to patch the
//! dsmClient object and nothing else, so a screen that imported a write
//! directly (token creation, burn, forget, every SoFi action, the lock, NFC)
//! reached the real wallet during the tour. These tests drive such direct
//! imports. Reads are answered from Rust's own record of the ingress, and every
//! request that reaches the bridge is logged, so "blocked" means the bridge
//! never saw it.

import { join } from 'path';
import * as pb from '../../proto/dsm_app_pb';
import { answerFromRustRecord } from '../../tests/helpers/rustIngressRecord';
import type { Arrival } from '../../tests/helpers/rustIngressRecord';
import { enterPracticeSandbox, inPracticeSandbox, leavePracticeSandbox, PRACTICE_BLOCKED_MESSAGE } from '../practiceGate';
import { burnToken } from '../../dsm/policies';
import * as sofi from '../../dsm/sofi';
import { walletAmount } from '../../dsm/amount';
import { callBin, setPreference } from '../../dsm/WebViewBridge';
import { startNativeQrScan, writeNfcTagPayloadHost } from '../../dsm/NativeHostBridge';
import { dsmClient } from '../../services/dsmClient';
import { practiceMode } from '../../components/tour/practiceMode';

const RECORD = join(__dirname, '../../components/tour/__tests__/fixtures/wallet_amount.ingress.bin');
const carried = (arrivals: Arrival[]): string[] => arrivals.map((a) => a.carried);
const client = dsmClient as unknown as Record<string, (...args: any[]) => Promise<any>>;

const VAULT = new Uint8Array(32).fill(0x51);
const TOKEN_IN = new Uint8Array(32).fill(0x52);
const TOKEN_OUT = new Uint8Array(32).fill(0x53);

describe('the practice sandbox at the bridge', () => {
  let arrivals: Arrival[];
  beforeEach(() => {
    arrivals = answerFromRustRecord(RECORD);
    enterPracticeSandbox();
  });
  afterEach(() => leavePracticeSandbox());

  it('blocks a write a screen imports directly, past dsmClient, before it reaches native code', async () => {
    const burned = await burnToken({ tokenId: 'ERA', amount: '1' });
    expect(burned).toEqual(expect.objectContaining({ message: expect.stringContaining(PRACTICE_BLOCKED_MESSAGE) }));
    await expect(
      sofi.trade({ vaultId: VAULT, tokenIn: TOKEN_IN, tokenOut: TOKEN_OUT, amountIn: '1', minAmountOut: '1' }),
    ).rejects.toThrow(PRACTICE_BLOCKED_MESSAGE);
    await expect(sofi.resolve()).rejects.toThrow(PRACTICE_BLOCKED_MESSAGE);
    expect(arrivals).toEqual([]);
  });

  it('blocks a raw frame that carries a write to the ingress', async () => {
    const frame = new pb.IngressRequest({
      operation: { case: 'routerInvoke', value: new pb.RouterInvokeOp({ method: 'token.create' }) },
    });
    await expect(callBin('nativeBoundaryIngress', frame.toBinary())).rejects.toThrow(PRACTICE_BLOCKED_MESSAGE);
    expect(arrivals).toEqual([]);
  });

  it('lets a read through, and Rust answers it', async () => {
    await expect(walletAmount({ tokenId: 'ERA' }, { entered: '1000' })).resolves.toEqual({
      baseUnits: 100000n,
      displayAmount: '1000.00',
      decimals: 2,
    });
    expect(carried(arrivals)).toEqual(['wallet.amount']);
  });

  it('keeps the preferences that change how the app looks and sounds, and no others', async () => {
    await setPreference('ui_theme', 'dark');
    await setPreference('lock_enabled', '1');
    await setPreference('diagnostics_consent', '1');
    expect(carried(arrivals)).toEqual(['ui_theme']);
  });

  it('lets the camera open for a contact code, and blocks a write to an NFC ring', async () => {
    await expect(startNativeQrScan()).rejects.toThrow(/no recorded answer/);
    await expect(writeNfcTagPayloadHost(new Uint8Array([7]))).rejects.toThrow(PRACTICE_BLOCKED_MESSAGE);
    expect(carried(arrivals)).toEqual(['HOST_CONTROL_QR_START_SCAN']);
  });
});

describe('outside practice', () => {
  it('the same writes reach native code', async () => {
    const arrivals = answerFromRustRecord(RECORD);
    await burnToken({ tokenId: 'ERA', amount: '1' });
    await expect(sofi.resolve()).rejects.toThrow(/no recorded answer/);
    await setPreference('lock_enabled', '1');
    expect(carried(arrivals)).toEqual(['token.burn', 'sofi.resolve', 'lock_enabled']);
  });
});

describe('practice mode puts the bridge in its sandbox', () => {
  let arrivals: Arrival[];
  beforeEach(() => {
    arrivals = answerFromRustRecord(RECORD);
    practiceMode.enter();
  });
  afterEach(() => practiceMode.leave());

  it('blocks a dsmClient write that practice does not answer', async () => {
    const burned = await client.burnToken({ tokenId: 'ERA', amount: '1' });
    expect(burned).toEqual(expect.objectContaining({ message: expect.stringContaining(PRACTICE_BLOCKED_MESSAGE) }));
    await expect(client.forgetToken('PLAY')).rejects.toThrow(PRACTICE_BLOCKED_MESSAGE);
    expect(arrivals).toEqual([]);
  });

  it('answers a write it simulates with only Rust reads crossing the bridge', async () => {
    const sent = await client.sendOnlineTransferSmart('alice', '25', undefined, 'ERA');
    expect(sent).toEqual(expect.objectContaining({ newBalance: 97500n }));
    expect(new Set(carried(arrivals))).toEqual(new Set(['wallet.amount']));
  });

  it('takes the bridge out of its sandbox when it leaves', () => {
    expect(inPracticeSandbox()).toBeTruthy();
    practiceMode.leave();
    expect(inPracticeSandbox()).toBeFalsy();
  });
});
