import { RejectCode } from "./rejectCodes";
import { VectorCase } from "./loader";

export type VectorAdapter = (wire: Uint8Array, caseId: string) => Promise<RejectCode>;

export type VectorResult = {
  caseId: string;
  expected: RejectCode;
  got: RejectCode;
  passed: boolean;
};

export type VectorRunReport = {
  passed: number;
  failed: number;
  results: VectorResult[];
};

/**
 * Deterministic: stable ordering, no time, no randomness.
 */
export async function runVectorCases(
  cases: VectorCase[],
  adapter: VectorAdapter,
): Promise<VectorRunReport> {
  const results: VectorResult[] = [];

  for (const c of cases) {
    let got: RejectCode;
    try {
      got = await adapter(c.request, c.id);
    } catch {
      // If your adapter throws, we classify as UNKNOWN_REJECT rather than crashing the harness.
      got = RejectCode.UNKNOWN_REJECT;
    }

    const expected = c.expected.code;
    const passed = got === expected;

    results.push({
      caseId: c.id,
      expected,
      got,
      passed,
    });
  }

  results.sort((a, b) => a.caseId.localeCompare(b.caseId));

  let pass = 0;
  let fail = 0;
  for (const r of results) {
    if (r.passed) pass++;
    else fail++;
  }

  return { passed: pass, failed: fail, results };
}
