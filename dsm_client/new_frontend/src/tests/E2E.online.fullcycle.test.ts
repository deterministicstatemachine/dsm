/// <reference types="jest" />
/* eslint-disable no-console */
// E2E Test: Online transaction full cycle (submit -> recipient retrieve)
// Run with: DSM_RUN_STORAGE_NODES=1 npm test -- src/tests/E2E.online.fullcycle.test.ts -i

import * as pb from '../proto/dsm_app_pb';

const SHOULD_RUN = process.env.DSM_RUN_STORAGE_NODES === '1';

// Minimal fetch polyfill (same as storage integration test)
if (typeof (global as any).fetch !== 'function') {
  const http = require('http');
  const https = require('https');
  (global as any).fetch = (url: string, opts: any = {}) => new Promise((resolve, reject) => {
    try {
      const lib = url.startsWith('https') ? https : http;
      const u = new URL(url);
      const req = lib.request({ hostname: u.hostname, port: u.port, path: u.pathname + (u.search || ''), method: opts.method || 'GET', headers: opts.headers || {} }, (res: any) => {
        const chunks: any[] = [];
        res.on('data', (c: any) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            headers: { get: (n: string) => res.headers[n.toLowerCase()] },
            arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
            // protobuf-only rule: no JSON
            json: async () => { throw new Error('json() disabled'); },
            text: async () => buf.toString(),
          });
        });
      });
      req.on('error', reject);
      if (opts.body) {
        if (opts.body instanceof Uint8Array || Buffer.isBuffer(opts.body)) req.write(Buffer.from(opts.body));
        else if (typeof opts.body === 'string') req.write(opts.body);
      }
      req.end();
    } catch (e) { reject(e); }
  });
}

function base32RFCEncode(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

describe('E2E: Online transaction full cycle', () => {
  if (!SHOULD_RUN) {
    it('skipped (set DSM_RUN_STORAGE_NODES=1 to enable)', () => {
      expect(true).toBe(true);
    });
    return;
  }

  it('submit envelope and recipient can retrieve it from node', async () => {
    // Register sender and recipient on node 0
    const devA = new Uint8Array(32).fill(0x11);
    const devB = new Uint8Array(32).fill(0x22);
    const pkA = devA;
    const ghB = devB;

    const regA = new pb.RegisterDeviceRequest({ deviceId: base32RFCEncode(devA), pubkey: base32RFCEncode(pkA), genesisHash: base32RFCEncode(ghB) } as any);

    let tokenA: string | null = null;
    try {
      const r = await fetch('http://127.0.0.1:8080/api/v2/device/register', { method: 'POST', headers: { 'Content-Type': 'application/protobuf' }, body: Buffer.from(regA.toBinary()) });
      if (r.ok) tokenA = pb.RegisterDeviceResponse.fromBinary(new Uint8Array(await r.arrayBuffer())).token;
      else if (r.status === 409) {
        const rr = await fetch('http://127.0.0.1:8080/api/v2/device/token', { method: 'POST', headers: { 'Content-Type': 'application/protobuf' }, body: Buffer.from(regA.toBinary()) });
        if (rr.ok) tokenA = pb.RegisterDeviceResponse.fromBinary(new Uint8Array(await rr.arrayBuffer())).token;
      }
    } catch (e) { console.warn('register/send fail', e); }
    expect(tokenA).toBeTruthy();

    const regB = new pb.RegisterDeviceRequest({ deviceId: base32RFCEncode(devB), pubkey: base32RFCEncode(devB), genesisHash: base32RFCEncode(devB) } as any);
    let tokenB: string | null = null;
    try {
      const r = await fetch('http://127.0.0.1:8080/api/v2/device/register', { method: 'POST', headers: { 'Content-Type': 'application/protobuf' }, body: Buffer.from(regB.toBinary()) });
      if (r.ok) tokenB = pb.RegisterDeviceResponse.fromBinary(new Uint8Array(await r.arrayBuffer())).token;
      else if (r.status === 409) {
        const rr = await fetch('http://127.0.0.1:8080/api/v2/device/token', { method: 'POST', headers: { 'Content-Type': 'application/protobuf' }, body: Buffer.from(regB.toBinary()) });
        if (rr.ok) tokenB = pb.RegisterDeviceResponse.fromBinary(new Uint8Array(await rr.arrayBuffer())).token;
      }
    } catch (e) { console.warn('register/recv fail', e); }
    expect(tokenB).toBeTruthy();

    // Build envelope (sender -> payload)
    const msgId = crypto.getRandomValues(new Uint8Array(16));
    const env = new pb.Envelope({ version: 3, messageId: msgId, headers: new pb.Headers({ deviceId: devA, chainTip: new Uint8Array(32) } as any), payload: { case: 'batchEnvelope', value: new pb.BatchEnvelope({ envelopes: [] }) } as any } as any);

    // Submit via v2 endpoint with x-dsm-recipient header set to recipient device id
    const submitUrl = 'http://127.0.0.1:8080/api/v2/b0x/submit';
    const headers: any = { 'Content-Type': 'application/octet-stream', 'x-dsm-recipient': base32RFCEncode(devB), 'X-Dsm-Message-Id': base32RFCEncode(msgId), authorization: `DSM ${base32RFCEncode(devA)}:${tokenA}` };
    const subRes = await fetch(submitUrl, { method: 'POST', headers, body: Buffer.from(env.toBinary()) });
    expect([200,204,409]).toContain(subRes.status);

    // Retrieve as recipient from /api/v2/b0x/retrieve
    const retMsgId = crypto.getRandomValues(new Uint8Array(16));
    const retRes = await fetch('http://127.0.0.1:8080/api/v2/b0x/retrieve', { method: 'GET', headers: { authorization: `DSM ${base32RFCEncode(devB)}:${tokenB}`, 'X-Dsm-Message-Id': base32RFCEncode(retMsgId) } });
    if (retRes.status !== 200 && retRes.status !== 204) {
      console.log('retrieve failed', retRes.status, await retRes.text().catch(() => ''));
    }
    expect([200,204]).toContain(retRes.status);
    if (retRes.status === 200) {
      const buf = new Uint8Array(await retRes.arrayBuffer());
      const batch = pb.BatchEnvelope.fromBinary(buf as any);
      expect(batch.envelopes.length).toBeGreaterThanOrEqual(1);
      const gotEnv = batch.envelopes[0];
      expect(gotEnv.headers?.deviceId).toBeDefined();
      expect(gotEnv.messageId.length).toBe(16);
    }
  }, 60000);
});