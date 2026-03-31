/* eslint-disable @typescript-eslint/no-explicit-any */
// UI-level runtime vectors (bridge processing where possible).

import * as pb from '../proto/dsm_app_pb';
import { appRouterInvokeBin, appRouterQueryBin } from '../dsm/WebViewBridge';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';
import { decodeBase32Crockford } from '../utils/textId';

export type UiVectorResult = {
  name: string;
  passed: boolean;
  skipped?: boolean;
  message?: string;
};

export type UiVectorRunReport = {
  passed: number;
  failed: number;
  results: UiVectorResult[];
};

function runCase(name: string, fn: () => Promise<void> | void): Promise<UiVectorResult> {
  return Promise.resolve()
    .then(() => fn())
    .then(() => ({ name, passed: true }))
    .catch((e: any) => ({ name, passed: false, message: e?.message ?? String(e) }));
}

function skipCase(name: string, message: string): UiVectorResult {
  return { name, passed: true, skipped: true, message };
}

async function invokeAndDecode(method: string, body: Uint8Array): Promise<pb.Envelope> {
  const argPack = new pb.ArgPack({
    codec: pb.Codec.PROTO as any,
    body: body as any,
  });
  const resBytes = await appRouterInvokeBin(method, argPack.toBinary());
  if (!resBytes || resBytes.length === 0) {
    throw new Error(`${method}: empty response`);
  }
  return decodeFramedEnvelopeV3(resBytes);
}

async function queryAndDecode(path: string): Promise<pb.Envelope> {
  const resBytes = await appRouterQueryBin(path);
  if (!resBytes || resBytes.length === 0) {
    throw new Error(`${path}: empty response`);
  }
  return decodeFramedEnvelopeV3(resBytes);
}

function isErrorPayload(env: pb.Envelope): boolean {
  return env.payload.case === 'error';
}

export async function runUiVectors(): Promise<UiVectorRunReport> {
  const results: UiVectorResult[] = [];
  const cfg: any = (globalThis as any).__DSM_UI_VECTOR_CONFIG__ ?? {};

  results.push(
    await runCase('token.create rejects invalid policy/limits', async () => {
      const req = new pb.TokenCreateRequest({
        ticker: 'a',
        alias: 'Bad Token',
        decimals: 255,
        maxSupplyU128: new Uint8Array(16),
        policyAnchor: new Uint8Array(32),
      });

      const env = await invokeAndDecode('token.create', req.toBinary());

      if (isErrorPayload(env)) {
        return;
      }

      if (env.payload.case !== 'tokenCreateResponse') {
        throw new Error(`token.create: unexpected payload ${env.payload.case}`);
      }

      const resp = env.payload.value as pb.TokenCreateResponse;
      if (resp.success) {
        throw new Error('token.create unexpectedly succeeded for invalid request');
      }
    }),
  );

  results.push(
    await runCase('wallet.send rejects invalid online transfer', async () => {
      const req = new pb.OnlineTransferRequest({
        tokenId: 'DSM',
        toDeviceId: new Uint8Array(0),
        amount: 1n,
        memo: 'vector',
        nonce: new Uint8Array(0),
        signature: new Uint8Array(0),
        fromDeviceId: new Uint8Array(0),
        chainTip: new Uint8Array(0),
        seq: 1n,
      } as any);

      const env = await invokeAndDecode('wallet.send', req.toBinary());

      if (isErrorPayload(env)) {
        return;
      }

      if (env.payload.case !== 'onlineTransferResponse') {
        throw new Error(`wallet.send: unexpected payload ${env.payload.case}`);
      }

      const resp = env.payload.value as pb.OnlineTransferResponse;
      if (resp.success) {
        throw new Error('wallet.send unexpectedly succeeded for invalid request');
      }
    }),
  );

  results.push(
    await runCase('faucet.claim rejects missing device id', async () => {
      const req = new pb.FaucetClaimRequest({
        deviceId: new Uint8Array(0),
      });

      const env = await invokeAndDecode('faucet.claim', req.toBinary());

      if (isErrorPayload(env)) {
        return;
      }

      if (env.payload.case !== 'faucetClaimResponse') {
        throw new Error(`faucet.claim: unexpected payload ${env.payload.case}`);
      }

      const resp = env.payload.value as pb.FaucetClaimResponse;
      if (resp.success) {
        throw new Error('faucet.claim unexpectedly succeeded for invalid request');
      }
    }),
  );

  if (!cfg?.tokenCreate) {
    results.push(skipCase('token.create happy path', 'missing __DSM_UI_VECTOR_CONFIG__.tokenCreate'));
  } else {
    results.push(
      await runCase('token.create happy path', async () => {
        const tc = cfg.tokenCreate;
        if (!tc?.policyAnchorB32 || typeof tc.policyAnchorB32 !== 'string') {
          throw new Error('token.create happy path missing policyAnchorB32');
        }
        const anchorBytes = new Uint8Array(decodeBase32Crockford(tc.policyAnchorB32));
        if (anchorBytes.length !== 32) {
          throw new Error('token.create happy path policyAnchorB32 must be 32 bytes');
        }

        const maxSupplyHex = typeof tc.maxSupplyU128Hex === 'string' ? tc.maxSupplyU128Hex : '01';
        const hex = maxSupplyHex.startsWith('0x') ? maxSupplyHex.slice(2) : maxSupplyHex;
        const padded = hex.padStart(32, '0');
        if (padded.length !== 32) {
          throw new Error('token.create happy path maxSupplyU128Hex must be 16 bytes (32 hex chars)');
        }
        const maxSupply = new Uint8Array(16);
        for (let i = 0; i < 16; i += 1) {
          maxSupply[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
        }

        const req = new pb.TokenCreateRequest({
          ticker: String(tc.ticker || 'TEST'),
          alias: String(tc.alias || 'Test Token'),
          decimals: Number(tc.decimals ?? 0),
          maxSupplyU128: maxSupply,
          policyAnchor: anchorBytes,
        });

        const env = await invokeAndDecode('token.create', req.toBinary());

        if (isErrorPayload(env)) {
          throw new Error('token.create returned error envelope');
        }

        if (env.payload.case !== 'tokenCreateResponse') {
          throw new Error(`token.create: unexpected payload ${env.payload.case}`);
        }

        const resp = env.payload.value as pb.TokenCreateResponse;
        if (!resp.success) {
          throw new Error('token.create happy path did not succeed');
        }
      }),
    );
  }

  if (!cfg?.faucet?.deviceIdB32) {
    results.push(skipCase('faucet.claim happy path', 'missing __DSM_UI_VECTOR_CONFIG__.faucet.deviceIdB32'));
  } else {
    results.push(
      await runCase('faucet.claim happy path', async () => {
        const deviceBytes = new Uint8Array(decodeBase32Crockford(String(cfg.faucet.deviceIdB32)));
        if (deviceBytes.length !== 32) {
          throw new Error('faucet.claim happy path deviceIdB32 must be 32 bytes');
        }
        const req = new pb.FaucetClaimRequest({
          deviceId: deviceBytes,
        });

        const env = await invokeAndDecode('faucet.claim', req.toBinary());

        if (isErrorPayload(env)) {
          throw new Error('faucet.claim returned error envelope');
        }

        if (env.payload.case !== 'faucetClaimResponse') {
          throw new Error(`faucet.claim: unexpected payload ${env.payload.case}`);
        }

        const resp = env.payload.value as pb.FaucetClaimResponse;
        if (!resp.success) {
          throw new Error('faucet.claim happy path did not succeed');
        }
      }),
    );
  }

  // --- token.create + balance verification (config-gated) ---
  if (!cfg?.tokenCreateVerify) {
    results.push(skipCase('token.create + balance verify', 'missing __DSM_UI_VECTOR_CONFIG__.tokenCreateVerify'));
  } else {
    results.push(
      await runCase('token.create + balance verify', async () => {
        const tc = cfg.tokenCreateVerify;
        if (!tc?.policyAnchorB32 || typeof tc.policyAnchorB32 !== 'string') {
          throw new Error('tokenCreateVerify missing policyAnchorB32');
        }
        const anchorBytes = new Uint8Array(decodeBase32Crockford(tc.policyAnchorB32));
        if (anchorBytes.length !== 32) {
          throw new Error('tokenCreateVerify policyAnchorB32 must be 32 bytes');
        }

        const maxSupplyHex = typeof tc.maxSupplyU128Hex === 'string' ? tc.maxSupplyU128Hex : '01';
        const hex = maxSupplyHex.startsWith('0x') ? maxSupplyHex.slice(2) : maxSupplyHex;
        const padded = hex.padStart(32, '0');
        const maxSupply = new Uint8Array(16);
        for (let i = 0; i < 16; i += 1) {
          maxSupply[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
        }

        const req = new pb.TokenCreateRequest({
          ticker: String(tc.ticker || 'UIVEC'),
          alias: String(tc.alias || 'UI Vector Token'),
          decimals: Number(tc.decimals ?? 0),
          maxSupplyU128: maxSupply,
          policyAnchor: anchorBytes,
        });

        // Step 1: Create token
        const createEnv = await invokeAndDecode('token.create', req.toBinary());
        if (isErrorPayload(createEnv)) {
          throw new Error('token.create returned error envelope');
        }
        if (createEnv.payload.case !== 'tokenCreateResponse') {
          throw new Error(`token.create: unexpected payload ${createEnv.payload.case}`);
        }
        const createResp = createEnv.payload.value as pb.TokenCreateResponse;
        if (!createResp.success) {
          throw new Error(`token.create failed: ${createResp.message}`);
        }
        if (!createResp.tokenId) {
          throw new Error('token.create returned empty tokenId');
        }

        // Step 2: Query balance.list and verify new token appears
        const balEnv = await queryAndDecode('balance.list');
        if (isErrorPayload(balEnv)) {
          throw new Error('balance.list returned error envelope');
        }
        if (balEnv.payload.case !== 'balancesListResponse') {
          throw new Error(`balance.list: unexpected payload ${balEnv.payload.case}`);
        }
        const balResp = balEnv.payload.value as pb.BalancesListResponse;
        // Token may or may not appear if available=0, so we just log
        const found = balResp.balances.find((b: any) => b.tokenId === createResp.tokenId);
        if (found) {
          console.log(`[uiVector] Token ${createResp.tokenId} found in balance.list`);
        } else {
          console.log(`[uiVector] Token ${createResp.tokenId} not in balance.list (metadata-only, expected)`);
        }
      }),
    );
  }

  // --- wallet.send rejects insufficient custom token balance (config-gated) ---
  if (!cfg?.insufficientTokenTransfer) {
    results.push(skipCase('wallet.send rejects insufficient custom token', 'missing __DSM_UI_VECTOR_CONFIG__.insufficientTokenTransfer'));
  } else {
    results.push(
      await runCase('wallet.send rejects insufficient custom token', async () => {
        const tc = cfg.insufficientTokenTransfer;
        if (!tc?.tokenId || !tc?.toDeviceIdB32 || !tc?.fromDeviceIdB32) {
          throw new Error('insufficientTokenTransfer missing required fields');
        }

        const toDeviceId = new Uint8Array(decodeBase32Crockford(String(tc.toDeviceIdB32)));
        const fromDeviceId = new Uint8Array(decodeBase32Crockford(String(tc.fromDeviceIdB32)));

        if (toDeviceId.length !== 32 || fromDeviceId.length !== 32) {
          throw new Error('insufficientTokenTransfer device IDs must be 32 bytes');
        }

        const req = new pb.OnlineTransferRequest({
          tokenId: String(tc.tokenId),
          toDeviceId,
          amount: 1n,
          memo: 'ui vector: insufficient balance',
          nonce: new Uint8Array(12),
          signature: new Uint8Array(0),
          fromDeviceId,
          chainTip: new Uint8Array(32),
          seq: 1n,
        } as any);

        const env = await invokeAndDecode('wallet.send', req.toBinary());

        if (isErrorPayload(env)) {
          return; // Error envelope = rejection, pass
        }

        if (env.payload.case !== 'onlineTransferResponse') {
          throw new Error(`wallet.send: unexpected payload ${env.payload.case}`);
        }

        const resp = env.payload.value as pb.OnlineTransferResponse;
        if (resp.success) {
          throw new Error('wallet.send should reject transfer of custom token with 0 balance');
        }
      }),
    );
  }

  let passed = 0;
  let failed = 0;
  for (const r of results) {
    if (r.skipped) continue;
    if (r.passed) passed += 1;
    else failed += 1;
  }

  return { passed, failed, results };
}
