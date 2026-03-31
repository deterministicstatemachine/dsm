import { loadVectorCases } from "./loader";
import { runVectorCases } from "./runner";
import { realWebviewInboundAdapter } from "./webviewAdapter";
import { runExternalCommitV2Vectors } from "./externalCommitV2";
import { runUiVectors } from "./uiVectors";

export async function runVectorsV1(baseUrl: string = "/vectors/v1"): Promise<void> {
  // Put your vectors at: public/vectors/v1/...
  const cases = await loadVectorCases({ baseUrl });
  const report = await runVectorCases(cases, realWebviewInboundAdapter);

  for (const r of report.results) {
    if (r.passed) {
      console.log(`PASS ${r.caseId}`);
    } else {
      console.log(`FAIL ${r.caseId} expected=${r.expected} got=${r.got}`);
    }
  }

  if (report.failed !== 0) {
    throw new Error(`vector run failed: ${report.passed} passed, ${report.failed} failed`);
  }

  console.log(`OK ${report.passed} passed, ${report.failed} failed`);
}

export async function runExternalCommitV2VectorsAndLog(): Promise<void> {
  const report = await runExternalCommitV2Vectors();

  for (const r of report.results) {
    if (r.passed) {
      console.log(`PASS external-commit-v2 ${r.name}`);
    } else {
      console.log(`FAIL external-commit-v2 ${r.name} ${r.message ?? ""}`.trim());
    }
  }

  if (report.failed !== 0) {
    throw new Error(
      `external-commit-v2 vectors failed: ${report.passed} passed, ${report.failed} failed`,
    );
  }

  console.log(`OK external-commit-v2 ${report.passed} passed, ${report.failed} failed`);
}

export async function runUiVectorsAndLog(): Promise<void> {
  const report = await runUiVectors();

  for (const r of report.results) {
    if (r.skipped) {
      console.log(`SKIP ui-vector ${r.name} ${r.message ?? ""}`.trim());
    } else if (r.passed) {
      console.log(`PASS ui-vector ${r.name}`);
    } else {
      console.log(`FAIL ui-vector ${r.name} ${r.message ?? ""}`.trim());
    }
  }

  if (report.failed !== 0) {
    throw new Error(`ui vectors failed: ${report.passed} passed, ${report.failed} failed`);
  }

  console.log(`OK ui-vectors ${report.passed} passed, ${report.failed} failed`);
}
