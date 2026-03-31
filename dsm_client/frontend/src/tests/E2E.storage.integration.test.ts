/// <reference types="jest" />
/* eslint-disable no-console */
// E2E integration test against local dev storage nodes.
// Run locally with: DSM_RUN_STORAGE_NODES=1 npm test -- src/tests/E2E.storage.integration.test.ts -i

import { storageNodeService } from '../services/storageNodeService';

// Minimal fetch polyfill for Node test environment
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

const SHOULD_RUN = process.env.DSM_RUN_STORAGE_NODES === '1';

describe('E2E: storage node ingestion', () => {
  if (!SHOULD_RUN) {
    it('skipped (set DSM_RUN_STORAGE_NODES=1 to enable)', () => {
      expect(true).toBe(true);
    });
    return;
  }

  it('posts a b0x payload to k selected nodes and health-checks nodes', async () => {
    // Configure local dev nodes (all equal mirrors, no primary)
    const cfg = {
      nodes: [
        { url: 'http://127.0.0.1:8080', isPrimary: false },
        { url: 'http://127.0.0.1:8081', isPrimary: false },
        { url: 'http://127.0.0.1:8082', isPrimary: false },
        { url: 'http://127.0.0.1:8083', isPrimary: false },
        { url: 'http://127.0.0.1:8084', isPrimary: false },
      ],
      retryPolicy: { maxRetries: 2, backoffMs: 10 },
      verificationQuorum: 1,
    } as any;
    storageNodeService.setNodesConfig(cfg);

    // Poll health to ensure nodes are up
    const health = await storageNodeService.checkAllNodesHealth();
    console.log('E2E: node health:', health);
    const healthy = health.filter(h => h.status === 'healthy');
    expect(healthy.length).toBeGreaterThanOrEqual(1);

    // Select nodes deterministically for a sample address
    const addr = 'TESTADDR-INTEGRATION';
    const nodes = storageNodeService.selectNodesForAddr(addr, 3);
    expect(nodes.length).toBe(3);

    // Helper: RFC4648 Base32 encode (UPPERCASE, no padding)
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

    // Register a device on node 0 to obtain a token for Authorization
    const pb = require('../proto/dsm_app_pb');
    const devBytes = new Uint8Array(32).map((_, i) => (i + 1) & 0xff);
    const pubkey = devBytes; // reuse dev bytes as pubkey for test
    const genesis = new Uint8Array(32).map((_, i) => (i + 2) & 0xff);
    const reqMsg = new pb.RegisterDeviceRequest({
      deviceId: base32RFCEncode(devBytes),
      pubkey: base32RFCEncode(pubkey),
      genesisHash: base32RFCEncode(genesis),
    } as any);

    // POST register to node 0
    let token: string | null = null;
    try {
      const regRes = await fetch('http://127.0.0.1:8080/api/v2/device/register', { method: 'POST', headers: { 'Content-Type': 'application/protobuf' }, body: Buffer.from(reqMsg.toBinary()) });
      if (regRes.ok) {
        const respBytes = new Uint8Array(await regRes.arrayBuffer());
        const resp = pb.RegisterDeviceResponse.fromBinary(respBytes as any);
        token = resp.token;
      } else if (regRes.status === 409) {
        // Device already exists — reissue token
        const tokenRes = await fetch('http://127.0.0.1:8080/api/v2/device/token', { method: 'POST', headers: { 'Content-Type': 'application/protobuf' }, body: Buffer.from(reqMsg.toBinary()) });
        if (tokenRes.ok) {
          const respBytes = new Uint8Array(await tokenRes.arrayBuffer());
          const resp = pb.RegisterDeviceResponse.fromBinary(respBytes as any);
          token = resp.token;
        } else {
          console.warn('device token reissue failed', tokenRes.status);
        }
      } else {
        console.warn('device register failed', regRes.status);
      }
    } catch (e) {
      console.warn('device register exception', e);
    }

    // Craft a valid Envelope v3 and POST to each selected node using Authorization
    const messageId = crypto.getRandomValues(new Uint8Array(16));
    const envelope = new pb.Envelope({
      version: 3,
      messageId: messageId,
      headers: new pb.Headers({ deviceId: devBytes, chainTip: new Uint8Array(32) } as any),
      payload: { case: 'batchEnvelope', value: new pb.BatchEnvelope({ envelopes: [] }) } as any,
    } as any);

    const results: Array<{ url: string; ok: boolean; status: number }> = [];
    for (const node of nodes) {
      const base = node.replace(/\/$/, '');
      const tryUrls = [`${base}/api/v2/b0x/submit`];
      let succeeded = false;
      for (const url of tryUrls) {
        const headers: any = { 'Content-Type': 'application/octet-stream', 'X-Dsm-Message-Id': base32RFCEncode(messageId) };
        if (token) headers['authorization'] = `DSM ${base32RFCEncode(devBytes)}:${token}`;
        try {
          const resp = await fetch(url, { method: 'POST', headers, body: Buffer.from(envelope.toBinary()) });
          const txt = resp.ok ? '' : await resp.text().catch(() => '');
          if (!resp.ok) console.log('node response:', url, resp.status, txt);
          results.push({ url, ok: resp.ok || resp.status === 409, status: resp.status });
          if (resp.ok || resp.status === 409) { succeeded = true; break; }
        } catch (e: any) {
          results.push({ url, ok: false, status: 0 });
        }
      }
    }

    console.log('E2E storage post results:', results);
    const success = results.filter(r => r.ok);
    expect(success.length).toBeGreaterThanOrEqual(1);
  }, 60000);
});
