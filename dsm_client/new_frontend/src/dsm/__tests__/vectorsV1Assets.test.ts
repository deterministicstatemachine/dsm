/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-env jest

declare const describe: any;
declare const it: any;
declare const expect: any;
declare const beforeAll: any;
declare const afterAll: any;
declare const require: any;
declare const __dirname: string;
declare const Buffer: any;

const fs = require('fs');
const path = require('path');
const { fileURLToPath, pathToFileURL } = require('url');

import { loadVectorCases } from '../../vectors/loader';
import { runVectorCases } from '../../vectors/runner';
import { RejectCode } from '../../vectors/rejectCodes';

type FetchResponse = {
  ok: boolean;
  status: number;
  statusText: string;
  text: () => Promise<string>;
  arrayBuffer: () => Promise<ArrayBuffer>;
};

function makeResponse(buf: any): FetchResponse {
  const safeBuffer = Uint8Array.from(buf).buffer;
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    text: async () => buf.toString('utf8'),
    arrayBuffer: async () => safeBuffer,
  };
}

describe('Vectors v1 assets (frontend loader)', () => {
  const originalFetch = globalThis.fetch;

  beforeAll(() => {
    globalThis.fetch = (async (input: RequestInfo | URL): Promise<FetchResponse> => {
      const url = typeof input === 'string' ? input : input.toString();
      if (!url.startsWith('file://')) {
        return {
          ok: false,
          status: 404,
          statusText: 'Not Found',
          text: async () => '',
          arrayBuffer: async () => new ArrayBuffer(0),
        };
      }
      const filePath = fileURLToPath(url);
      const data = await fs.promises.readFile(filePath);
      return makeResponse(data);
    }) as typeof fetch;
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  it('loads all v1 vector cases deterministically', async () => {
    const basePath = path.resolve(__dirname, '../../../public/vectors/v1');
    const baseUrl = pathToFileURL(basePath).toString();

    const cases = await loadVectorCases({ baseUrl, sortCases: true });
    expect(cases.length).toBeGreaterThan(0);

    const ids = new Set(cases.map(c => c.id));
    const required = [
      'case_0001_proof_cap_over',
      'case_0002_smt_empty_root_ok',
      'case_0003_smt_empty_root_bad',
      'case_0004_devtree_empty_root_ok',
      'case_0005_devtree_single_leaf_ok',
      'case_0006_modal_conflict_pending_online',
      'case_0007_force_missing_witness',
      'case_0008_force_storage_error',
    ];
    for (const id of required) {
      expect(ids.has(id)).toBe(true);
    }

    for (const c of cases) {
      expect(c.request.length).toBeGreaterThan(0);
    }

    const report = await runVectorCases(cases, async (_wire, caseId) => {
      const found = cases.find(c => c.id === caseId);
      return found?.expected.code ?? RejectCode.UNKNOWN_REJECT;
    });

    expect(report.failed).toBe(0);
    expect(report.passed).toBe(cases.length);
  });
});
