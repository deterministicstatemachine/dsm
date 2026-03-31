import { parseKv } from "./kv";
import { parseRejectCode, RejectCode } from "./rejectCodes";

export type VectorCase = {
  id: string;
  request: Uint8Array;
  expected: { code: RejectCode };
};

export type VectorLoadOptions = {
  /**
   * Base URL where the vectors live.
   * Example (web): "/vectors/v1"
   * Example (RN WebView): "https://localhost/assets/vectors/v1" (served by host app)
   */
  baseUrl: string;

  /**
   * Manifest path relative to baseUrl. Default "manifest.txt".
   */
  manifestName?: string;

  /**
   * Deterministic: if true, enforce stable ordering of case ids.
   */
  sortCases?: boolean;
};

async function fetchText(url: string): Promise<string> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`fetch failed ${r.status} ${r.statusText}: ${url}`);
  return await r.text();
}

async function fetchBytes(url: string): Promise<Uint8Array> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`fetch failed ${r.status} ${r.statusText}: ${url}`);
  const buf = await r.arrayBuffer();
  return new Uint8Array(buf);
}

function parseManifest(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length === 0) continue;
    if (line.startsWith("#")) continue;
    out.push(line);
  }
  return out;
}

export async function loadVectorCases(opts: VectorLoadOptions): Promise<VectorCase[]> {
  const baseUrl = opts.baseUrl.replace(/\/+$/, "");
  const manifestName = opts.manifestName ?? "manifest.txt";

  const manifestText = await fetchText(`${baseUrl}/${manifestName}`);
  let ids = parseManifest(manifestText);

  if (opts.sortCases ?? true) {
    ids = [...ids].sort((a, b) => a.localeCompare(b));
  }

  const cases: VectorCase[] = [];
  for (const id of ids) {
    const req = await fetchBytes(`${baseUrl}/${id}/request.bin`);
    const expText = await fetchText(`${baseUrl}/${id}/expected.kv`);
    const kv = parseKv(expText);

    const codeStr = kv.get("code");
    if (!codeStr) throw new Error(`expected.kv missing code for case ${id}`);

    cases.push({
      id,
      request: req,
      expected: { code: parseRejectCode(codeStr) },
    });
  }

  return cases;
}
